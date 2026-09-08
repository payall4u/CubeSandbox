// Copyright (c) 2024 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

//! Host-side lifecycle and cgroup ownership for Cube sandbox shims.
//!
//! The containerd bundle is intentionally not authoritative here: containerd
//! may remove it after a failed bootstrap response.  Records below live under
//! a node-persistent root and are fsync/rename committed before any cgroup or
//! socket mutation.

use cgroups::systemd::props::PropertiesBuilder;
use cgroups::systemd::utils::expand_slice;
use cgroups::systemd::SystemdClient;
use oci_spec::runtime::Spec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zbus::zvariant::Value as ZbusValue;

use crate::common::utils::Utils;
use crate::service::bootstrap::BootstrapParams;
use crate::service::runtime_resource::{self, HostResourceCeiling};

const SCHEMA_VERSION: u32 = 2;
const DEFAULT_LIFECYCLE_ROOT: &str = "/data/cubelet/shim-lifecycle";
const LIFECYCLE_ROOT_ENV: &str = "CUBE_SHIM_LIFECYCLE_ROOT";
const LIFECYCLE_DIR_ENV: &str = "CUBE_SHIM_LIFECYCLE_DIR";
const GATE_FD_ENV: &str = "CUBE_SHIM_GATE_FD";
const LAUNCH_NONCE_ENV: &str = "CUBE_SHIM_LAUNCH_NONCE";
const WATCHDOG_UNIT: &str = "cubesandbox-shim-watchdog.service";
const WATCHDOG_BINARY: &str = "/usr/local/bin/containerd-shim-cube-rs";
const WATCHDOG_PROBE_STAMP: &str = "/run/cubesandbox/shim-cgroup-probe.json";
pub(crate) const WATCHDOG_ACTION: &str = "shim-watchdog";
pub(crate) const SYSTEMD_PROBE_ACTION: &str = "shim-cgroup-probe";
const DEFAULT_CLEANUP_QUEUE_ROOT: &str = "/data/cubelet/shim-cleanup";
const CLEANUP_QUEUE_ROOT_ENV: &str = "CUBE_SHIM_CLEANUP_QUEUE_ROOT";
const HOST_QUEUE_DIRECTORY: &str = "host-cgroup";
const RUNTIME_QUEUE_DIRECTORY: &str = "runtime-resource";
const SOCKET_LOCK_DIRECTORY: &str = "socket-locks";
const CLEANUP_REASON_FILE: &str = "cleanup-reason";
const PRECOMMIT_GRACE: Duration = Duration::from_secs(30);

const RECORD_FILE: &str = "record.json";
const RECORD_LOCK_FILE: &str = "record.lock";
const OPERATION_LOCK_FILE: &str = "operation.lock";
const HOST_OWNER_FILE: &str = "host-cgroup-owner.json";
const RUNTIME_OWNER_FILE: &str = "runtime-resource-owner.json";

const CONTAINER_TYPE_ANNOTATION: &str = "io.kubernetes.cri.container-type";
const SANDBOX_ID_ANNOTATION: &str = "io.kubernetes.cri.sandbox-id";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Classification {
    Pending,
    ManagedSandbox,
    LegacyTask,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum LifecyclePhase {
    Prepared,
    ServerIdentified,
    SocketReady,
    TakeoverClaimed,
    ContainerdCommitted,
    CleanupRequired,
    CleanupOwnersDurable,
    ServerStopped,
    Done,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CreateState {
    None,
    InProgress,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateAdmission {
    First,
    RetryInProgress,
    RetrySucceeded,
    RetryFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BeginCreateError {
    Conflict(String),
    Invalid(String),
}

impl std::fmt::Display for BeginCreateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict(message) | Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PersistedCreateResult {
    Succeeded,
    Failed { code: String, message: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OwnerKind {
    Helper,
    Server,
    Scanner,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProcessIdentity {
    pid: i32,
    boot_id: String,
    start_time_ticks: u64,
    executable: FileIdentity,
    command_sha256: String,
    cwd: FileIdentity,
    cgroup: String,
    launch_nonce_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct OperationOwner {
    kind: OwnerKind,
    epoch: u64,
    identity: ProcessIdentity,
    revoked_epoch: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "manager", rename_all = "snake_case")]
enum HostTarget {
    Pending {
        original_cgroup: String,
    },
    Systemd {
        oci_path: String,
        slice: String,
        unit: String,
        cgroup: String,
        parent_identity: FileIdentity,
        leaf_identity: Option<FileIdentity>,
    },
    Cgroupfs {
        oci_path: String,
        cgroup: String,
        parent_identity: FileIdentity,
        leaf_identity: Option<FileIdentity>,
    },
    Legacy {
        cgroup: String,
    },
}

impl HostTarget {
    fn cgroup(&self) -> &str {
        match self {
            Self::Pending { original_cgroup } => original_cgroup,
            Self::Systemd { cgroup, .. }
            | Self::Cgroupfs { cgroup, .. }
            | Self::Legacy { cgroup } => cgroup,
        }
    }

    fn managed(&self) -> bool {
        matches!(self, Self::Systemd { .. } | Self::Cgroupfs { .. })
    }

    fn leaf_identity(&self) -> Option<&FileIdentity> {
        match self {
            Self::Systemd { leaf_identity, .. } | Self::Cgroupfs { leaf_identity, .. } => {
                leaf_identity.as_ref()
            }
            Self::Pending { .. } | Self::Legacy { .. } => None,
        }
    }

    fn set_leaf_identity(&mut self, identity: FileIdentity) {
        match self {
            Self::Systemd { leaf_identity, .. } | Self::Cgroupfs { leaf_identity, .. } => {
                *leaf_identity = Some(identity);
            }
            Self::Pending { .. } | Self::Legacy { .. } => {}
        }
    }

    fn parent_identity(&self) -> Option<&FileIdentity> {
        match self {
            Self::Systemd {
                parent_identity, ..
            }
            | Self::Cgroupfs {
                parent_identity, ..
            } => Some(parent_identity),
            Self::Pending { .. } | Self::Legacy { .. } => None,
        }
    }

    fn same_location(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Pending {
                    original_cgroup: left,
                },
                Self::Pending {
                    original_cgroup: right,
                },
            ) => left == right,
            (
                Self::Systemd {
                    oci_path: left_oci,
                    slice: left_slice,
                    unit: left_unit,
                    cgroup: left_cgroup,
                    parent_identity: left_parent,
                    ..
                },
                Self::Systemd {
                    oci_path: right_oci,
                    slice: right_slice,
                    unit: right_unit,
                    cgroup: right_cgroup,
                    parent_identity: right_parent,
                    ..
                },
            ) => {
                left_oci == right_oci
                    && left_slice == right_slice
                    && left_unit == right_unit
                    && left_cgroup == right_cgroup
                    && left_parent == right_parent
            }
            (
                Self::Cgroupfs {
                    oci_path: left_oci,
                    cgroup: left_cgroup,
                    parent_identity: left_parent,
                    ..
                },
                Self::Cgroupfs {
                    oci_path: right_oci,
                    cgroup: right_cgroup,
                    parent_identity: right_parent,
                    ..
                },
            ) => {
                left_oci == right_oci && left_cgroup == right_cgroup && left_parent == right_parent
            }
            (Self::Legacy { cgroup: left }, Self::Legacy { cgroup: right }) => left == right,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SocketIdentity {
    path: String,
    parent: FileIdentity,
    device: Option<u64>,
    inode: Option<u64>,
    absent_at_prepare: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FailureResult {
    code: String,
    message: String,
    published_at_ms: u128,
    waiter_count: u32,
    drained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ContainmentIdentity {
    cgroup: String,
    device: Option<u64>,
    inode: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum VmmWorkerState {
    SpawnIntent,
    Allocated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct VmmWorkerRecord {
    state: VmmWorkerState,
    operation_epoch: u64,
    protocol_version: u16,
    launch_nonce_sha256: String,
    expected_executable: FileIdentity,
    identity: Option<ProcessIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct LifecycleRecord {
    schema_version: u32,
    sequence: u64,
    generation: String,
    phase: LifecyclePhase,
    classification: Classification,
    namespace: String,
    instance_id: String,
    bundle: String,
    bundle_identity: FileIdentity,
    created_at_ms: u128,
    takeover_claimed_at_ms: Option<u128>,
    launch_nonce_sha256: String,
    expected_server_path: String,
    expected_server_executable: FileIdentity,
    expected_server_argv: Vec<String>,
    expected_server_command_sha256: String,
    helper: ProcessIdentity,
    server: Option<ProcessIdentity>,
    target: HostTarget,
    socket: SocketIdentity,
    operation_owner: OperationOwner,
    create_state: CreateState,
    create_fingerprint: Option<String>,
    create_waiters: u32,
    failure: Option<FailureResult>,
    containment_breach: Option<ContainmentIdentity>,
    #[serde(default)]
    vmm_worker: Option<VmmWorkerRecord>,
    #[serde(default)]
    degraded_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct HostCgroupOwner {
    schema_version: u32,
    generation: String,
    namespace: String,
    instance_id: String,
    state: HostOwnerState,
    target: HostTarget,
    original_cgroup: String,
    server: Option<ProcessIdentity>,
    #[serde(default)]
    controllers: Option<ControllerJournal>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum HostOwnerState {
    Empty,
    Intent,
    Allocated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ControllerTransactionState {
    Prepared,
    Applying,
    ControllersCommitted,
    RollingBack,
    Restored,
    Degraded,
    AbandonedForExactDelete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ControllerStepState {
    NotStarted,
    Intent,
    Applied,
    UndoIntent,
    Restored,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ControllerStep {
    file: String,
    old: String,
    target: String,
    state: ControllerStepState,
    observed: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ControllerJournal {
    schema_version: u32,
    transaction_id: String,
    owner_epoch: u64,
    owner_identity: ProcessIdentity,
    create_fingerprint: String,
    state: ControllerTransactionState,
    steps: Vec<ControllerStep>,
    degraded_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct HostCleanupJob {
    owner: HostCgroupOwner,
    socket: SocketIdentity,
    created_at_ms: u128,
    lifecycle_root: String,
    ready_for_cleanup: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RuntimeCleanupJob {
    owner: RuntimeResourceOwner,
    ready_for_cleanup: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct WatchdogProbeStamp {
    schema_version: u32,
    boot_id: String,
    binary_path: String,
    binary_identity: FileIdentity,
    binary_sha256: String,
    iterations: u32,
    completed_at_ms: u128,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum RuntimeOwnerState {
    Empty,
    Intent,
    Allocated,
    Released,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ForwardResourceState {
    #[default]
    None,
    Intent,
    Allocated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RuntimeResourceOwner {
    schema_version: u32,
    generation_id: String,
    state: RuntimeOwnerState,
    endpoint: Option<String>,
    sandbox_id: Option<String>,
    lease_id: Option<String>,
    resource_generation: Option<u64>,
    allocation_key: Option<String>,
    #[serde(default)]
    tap_state: ForwardResourceState,
    #[serde(default)]
    tap_cleanup_identity: Option<String>,
    #[serde(default)]
    vm_state: ForwardResourceState,
    #[serde(default)]
    vm_cleanup_identity: Option<String>,
}

impl RuntimeResourceOwner {
    fn empty(generation_id: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            generation_id,
            state: RuntimeOwnerState::Empty,
            endpoint: None,
            sandbox_id: None,
            lease_id: None,
            resource_generation: None,
            allocation_key: None,
            tap_state: ForwardResourceState::None,
            tap_cleanup_identity: None,
            vm_state: ForwardResourceState::None,
            vm_cleanup_identity: None,
        }
    }

    pub(crate) fn intent(
        endpoint: String,
        sandbox_id: String,
        lease_id: String,
        resource_generation: u64,
        allocation_key: String,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            generation_id: String::new(),
            state: RuntimeOwnerState::Intent,
            endpoint: Some(endpoint),
            sandbox_id: Some(sandbox_id),
            lease_id: Some(lease_id),
            resource_generation: Some(resource_generation),
            allocation_key: Some(allocation_key),
            tap_state: ForwardResourceState::None,
            tap_cleanup_identity: None,
            vm_state: ForwardResourceState::None,
            vm_cleanup_identity: None,
        }
    }

    pub(crate) fn mark_allocated(&mut self) {
        self.state = RuntimeOwnerState::Allocated;
    }

    pub(crate) fn mark_released(&mut self) {
        self.state = RuntimeOwnerState::Released;
    }

    pub(crate) fn state(&self) -> RuntimeOwnerState {
        self.state
    }

    pub(crate) fn release_identity(&self) -> Option<(&str, &str, &str, u64)> {
        Some((
            self.endpoint.as_deref()?,
            self.sandbox_id.as_deref()?,
            self.lease_id.as_deref()?,
            self.resource_generation?,
        ))
    }
}

struct RecordLock {
    file: File,
}

pub(crate) struct SocketPathGuard {
    _lock: RecordLock,
}

fn acquire_socket_path_lock(root: &Path, path: &Path) -> Result<SocketPathGuard, String> {
    let path = canonical_socket_path(path)?;
    let directory = root.join(SOCKET_LOCK_DIRECTORY);
    ensure_directory(&directory)?;
    let digest = socket_ownership_digest(&path)?;
    Ok(SocketPathGuard {
        _lock: RecordLock::acquire(&directory.join(format!("{digest}.lock")))?,
    })
}

fn socket_ownership_digest(path: &Path) -> Result<String, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("shim socket has no parent: {}", path.display()))?;
    let name = path.file_name().ok_or_else(|| {
        format!(
            "shim socket path must contain a basename: {}",
            path.display()
        )
    })?;
    let identity = file_identity(parent)?;
    let mut hasher = Sha256::new();
    for value in [identity.device.to_be_bytes(), identity.inode.to_be_bytes()] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    let name = name.as_encoded_bytes();
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    Ok(format!("{:x}", hasher.finalize()))
}

impl RecordLock {
    fn acquire(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("open lifecycle lock {}: {error}", path.display()))?;
        // SAFETY: flock only borrows this valid descriptor for the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(format!(
                "lock lifecycle record {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { file })
    }
}

impl Drop for RecordLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains valid until after this Drop body.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LifecycleHandle {
    directory: PathBuf,
}

pub(crate) struct CreateWaiterGuard {
    handle: LifecycleHandle,
    armed: bool,
}

impl CreateWaiterGuard {
    pub(crate) fn finish(mut self) -> Result<(), String> {
        let result = self.handle.finish_create_waiter();
        if result.is_ok() {
            self.armed = false;
        }
        result
    }
}

impl Drop for CreateWaiterGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.handle.finish_create_waiter();
        }
    }
}

/// The durable result publisher is owned only by the first admitted Create.
/// RPC waiters never carry this guard, so cancellation of a duplicate request
/// cannot complete or corrupt the original operation.
pub(crate) struct CreatePublisherGuard {
    handle: LifecycleHandle,
    armed: bool,
    intended: Option<PersistedCreateResult>,
}

impl CreatePublisherGuard {
    pub(crate) async fn success_until_durable(mut self) {
        self.intended = Some(PersistedCreateResult::Succeeded);
        self.publish_until_durable().await;
    }

    pub(crate) async fn failure_until_durable(mut self, code: &str, message: &str) {
        self.intended = Some(PersistedCreateResult::Failed {
            code: code.to_string(),
            message: message.to_string(),
        });
        self.publish_until_durable().await;
    }

    async fn publish_until_durable(&mut self) {
        let result = self
            .intended
            .clone()
            .expect("Create result is selected before durable publication");
        let mut delay = Duration::from_millis(10);
        loop {
            match publish_create_result_once(&self.handle, &result) {
                Ok(()) => {
                    self.armed = false;
                    return;
                }
                Err(error) => {
                    eprintln!("retry durable Create result publication: {error}");
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay.saturating_mul(2), Duration::from_secs(1));
                }
            }
        }
    }
}

impl Drop for CreatePublisherGuard {
    fn drop(&mut self) {
        if self.armed {
            // Dropping the RPC future must not strand the durable admission in
            // IN_PROGRESS.  Transfer the exact selected result, or the fixed
            // pre-selection cancellation result, to an actor independent from
            // the request future.  A one-shot synchronous write is insufficient
            // because any atomic commit stage can fail transiently.
            let result = self
                .intended
                .clone()
                .unwrap_or_else(|| PersistedCreateResult::Failed {
                    code: "CANCELLED".to_string(),
                    message: "first Create operation ended before selecting its durable result"
                        .to_string(),
                });
            spawn_create_result_actor(self.handle.clone(), result);
        }
    }
}

fn publish_create_result_once(
    handle: &LifecycleHandle,
    result: &PersistedCreateResult,
) -> Result<(), String> {
    let current = match handle.current_create_result() {
        Ok(current) => current,
        Err(_error) if !handle.directory.join(RECORD_FILE).exists() => return Ok(()),
        Err(error) => return Err(error),
    };
    if let Some(existing) = current {
        if &existing != result {
            eprintln!(
                "Create result publication lost ownership to durable terminal result: intended={result:?} durable={existing:?}"
            );
        }
        // The scanner may take over an abandoned IN_PROGRESS result before
        // cleanup.  Once any terminal result is durable it is authoritative;
        // the superseded publisher must stop rather than retry forever.
        return Ok(());
    }
    match result {
        PersistedCreateResult::Succeeded => handle.finish_create_success(),
        PersistedCreateResult::Failed { code, message } => {
            handle.finish_create_failure(code, message)
        }
    }
}

async fn publish_create_result_until_durable(
    handle: LifecycleHandle,
    result: PersistedCreateResult,
) {
    let mut delay = Duration::from_millis(10);
    loop {
        match publish_create_result_once(&handle, &result) {
            Ok(()) => return,
            Err(error) => {
                eprintln!("retry detached durable Create result publication: {error}");
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(delay.saturating_mul(2), Duration::from_secs(1));
            }
        }
    }
}

fn spawn_create_result_actor(handle: LifecycleHandle, result: PersistedCreateResult) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(publish_create_result_until_durable(handle, result));
        return;
    }
    let _ = std::thread::Builder::new()
        .name("cube-create-result".to_string())
        .spawn(move || {
            let mut delay = Duration::from_millis(10);
            loop {
                match publish_create_result_once(&handle, &result) {
                    Ok(()) => return,
                    Err(error) => {
                        eprintln!("retry detached synchronous Create result publication: {error}");
                        std::thread::sleep(delay);
                        delay = std::cmp::min(delay.saturating_mul(2), Duration::from_secs(1));
                    }
                }
            }
        });
}

struct PartialLifecycleDirectory {
    directory: PathBuf,
    armed: bool,
}

impl Drop for PartialLifecycleDirectory {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for name in [
            RUNTIME_OWNER_FILE,
            HOST_OWNER_FILE,
            RECORD_FILE,
            OPERATION_LOCK_FILE,
            RECORD_LOCK_FILE,
        ] {
            let _ = fs::remove_file(self.directory.join(name));
        }
        if fs::remove_dir(&self.directory).is_ok() {
            if let Some(parent) = self.directory.parent() {
                let _ = sync_directory(parent);
            }
        }
    }
}

pub(crate) struct LifecycleOperation {
    handle: LifecycleHandle,
    epoch: u64,
    owner: OwnerKind,
    identity: ProcessIdentity,
    target: HostTarget,
    _lock: RecordLock,
}

impl LifecycleOperation {
    pub(crate) fn verify(&self) -> Result<(), String> {
        let _record_lock = self.handle.record_lock()?;
        let record = self.handle.read_record()?;
        self.verify_record(&record)
    }

    pub(crate) fn verify_host_controllers(&self) -> Result<(), String> {
        let _record_lock = self.handle.record_lock()?;
        let record = self.handle.read_record()?;
        self.verify_record(&record)?;
        if record.classification != Classification::ManagedSandbox {
            return Ok(());
        }
        let owner = self.handle.read_host_owner()?;
        verify_host_owner_for_record(&owner, &record)?;
        let journal = owner
            .controllers
            .as_ref()
            .ok_or_else(|| "managed Host owner has no controller transaction".to_string())?;
        if journal.state != ControllerTransactionState::ControllersCommitted {
            return Err(format!(
                "Host controller transaction is not committed: {:?}",
                journal.state
            ));
        }
        verify_controller_journal_owner(
            journal,
            self.epoch,
            &self.identity,
            record
                .create_fingerprint
                .as_deref()
                .ok_or_else(|| "managed Create has no fingerprint".to_string())?,
        )?;
        exact_controller_readback(&host_leaf_path(&record.target)?, journal, true)
    }

    fn verify_record(&self, record: &LifecycleRecord) -> Result<(), String> {
        if record.operation_owner.epoch != self.epoch || record.operation_owner.kind != self.owner {
            return Err(format!(
                "runtime operation epoch {} was revoked by {:?}/{}",
                self.epoch, record.operation_owner.kind, record.operation_owner.epoch
            ));
        }
        if !immutable_identity_matches(&self.identity, &record.operation_owner.identity) {
            return Err("runtime operation owner identity changed".to_string());
        }
        if !record.target.same_location(&self.target) {
            return Err("runtime operation Host target identity changed".to_string());
        }
        if self.owner != OwnerKind::Helper && record.target != self.target {
            return Err("runtime operation Host leaf identity changed".to_string());
        }
        let actual = process_identity_for_expected(&self.identity)?;
        if !immutable_identity_matches(&self.identity, &actual) {
            return Err("runtime operation process identity is no longer live".to_string());
        }
        let expected_cgroup = match self.owner {
            OwnerKind::Helper | OwnerKind::Server => record.target.cgroup(),
            OwnerKind::Scanner => self.identity.cgroup.as_str(),
        };
        if actual.cgroup != expected_cgroup {
            return Err(format!(
                "runtime operation owner moved to {}, expected {expected_cgroup}",
                actual.cgroup
            ));
        }
        verify_live_target_identity(&record.target)?;
        if matches!(self.owner, OwnerKind::Helper | OwnerKind::Server) {
            verify_target_membership(&record.target, actual.pid)?;
        }
        match self.owner {
            OwnerKind::Helper if record.phase == LifecyclePhase::Prepared => Ok(()),
            OwnerKind::Server if record.phase == LifecyclePhase::ContainerdCommitted => Ok(()),
            OwnerKind::Scanner
                if matches!(
                    record.phase,
                    LifecyclePhase::CleanupOwnersDurable | LifecyclePhase::ServerStopped
                ) =>
            {
                Ok(())
            }
            _ => Err(format!(
                "runtime operation owner/phase mismatch: {:?}/{:?}",
                self.owner, record.phase
            )),
        }
    }

    pub(crate) fn mark_allocated(&self) -> Result<(), String> {
        self.update_runtime_owner(|owner| {
            owner.mark_allocated();
            Ok(())
        })
    }

    pub(crate) fn mark_released(&self) -> Result<(), String> {
        self.update_runtime_owner(|owner| {
            owner.mark_released();
            Ok(())
        })
    }

    pub(crate) fn mark_tap_intent(&self, cleanup_identity: &str) -> Result<(), String> {
        self.update_runtime_owner(|owner| {
            if owner.state != RuntimeOwnerState::Allocated
                || owner.tap_state != ForwardResourceState::None
            {
                return Err(format!(
                    "TAP INTENT requires allocated lease with no prior TAP state; found {:?}/{:?}",
                    owner.state, owner.tap_state
                ));
            }
            owner.tap_state = ForwardResourceState::Intent;
            owner.tap_cleanup_identity = Some(cleanup_identity.to_string());
            Ok(())
        })
    }

    pub(crate) fn mark_tap_allocated_and_vm_intent(&self) -> Result<(), String> {
        let cleanup_identity = format!(
            "host-cgroup={};server={}:{}",
            self.target.cgroup(),
            self.identity.pid,
            self.identity.start_time_ticks
        );
        self.update_runtime_owner(|owner| {
            if owner.tap_state != ForwardResourceState::Intent
                || owner.vm_state != ForwardResourceState::None
            {
                return Err(format!(
                    "TAP allocation and VM INTENT require durable TAP INTENT with no prior VM state; found {:?}/{:?}",
                    owner.tap_state, owner.vm_state
                ));
            }
            // TAP=INTENT already contains the exact provider cleanup
            // identity, so a crash before this commit remains releasable.
            // After TAP acquisition, publish TAP=ALLOCATED and VM=INTENT in
            // one atomic owner generation before any VMM side effect.
            owner.tap_state = ForwardResourceState::Allocated;
            owner.vm_state = ForwardResourceState::Intent;
            owner.vm_cleanup_identity = Some(cleanup_identity);
            Ok(())
        })
    }

    pub(crate) fn mark_vm_allocated(&self) -> Result<(), String> {
        self.update_runtime_owner(|owner| {
            if owner.vm_state != ForwardResourceState::Intent {
                return Err(format!(
                    "VM allocation requires durable INTENT, found {:?}",
                    owner.vm_state
                ));
            }
            owner.vm_state = ForwardResourceState::Allocated;
            Ok(())
        })
    }

    fn update_runtime_owner(
        &self,
        update: impl FnOnce(&mut RuntimeResourceOwner) -> Result<(), String>,
    ) -> Result<(), String> {
        let _record_lock = self.handle.record_lock()?;
        let record = self.handle.read_record()?;
        self.verify_record(&record)?;
        let mut owner: RuntimeResourceOwner =
            read_json(&self.handle.directory.join(RUNTIME_OWNER_FILE))?;
        if owner.generation_id != record.generation {
            return Err("RuntimeResource owner generation changed".to_string());
        }
        update(&mut owner)?;
        atomic_write_json(&self.handle.directory.join(RUNTIME_OWNER_FILE), &owner)
    }
}

impl crate::hypervisor::worker::WorkerPlacement for LifecycleOperation {
    fn prepare_vmm_worker_spawn(
        &self,
        executable: &Path,
        nonce: &str,
        protocol_version: u16,
    ) -> Result<(), String> {
        self.verify()?;
        let executable = fs::canonicalize(executable).map_err(|error| {
            format!(
                "canonicalize cube-vmm-worker executable {}: {error}",
                executable.display()
            )
        })?;
        let expected_executable = file_identity(&executable)?;
        let _record_lock = self.handle.record_lock()?;
        let mut record = self.handle.read_record()?;
        self.verify_record(&record)?;
        if record.vmm_worker.is_some() {
            return Err("lifecycle already has a cube-vmm-worker record".to_string());
        }
        record.vmm_worker = Some(VmmWorkerRecord {
            state: VmmWorkerState::SpawnIntent,
            operation_epoch: self.epoch,
            protocol_version,
            launch_nonce_sha256: sha256_hex(nonce.as_bytes()),
            expected_executable,
            identity: None,
        });
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| "lifecycle sequence overflow".to_string())?;
        atomic_write_json(&self.handle.directory.join(RECORD_FILE), &record)
    }

    fn place_vmm_worker(&self, pid: u32) -> Result<(), String> {
        let pid = i32::try_from(pid)
            .map_err(|error| format!("cube-vmm-worker pid does not fit i32: {error}"))?;
        self.verify()?;
        let before = process_identity(pid)?;
        let nonce_hash = process_environment_value(pid, "CUBE_VMM_WORKER_NONCE")?
            .map(|value| sha256_hex(value.as_bytes()))
            .ok_or_else(|| format!("cube-vmm-worker {pid} has no launch nonce"))?;
        let expected = {
            let _record_lock = self.handle.record_lock()?;
            let record = self.handle.read_record()?;
            self.verify_record(&record)?;
            let worker = record
                .vmm_worker
                .as_ref()
                .ok_or_else(|| "cube-vmm-worker has no durable spawn INTENT".to_string())?;
            if worker.state != VmmWorkerState::SpawnIntent
                || worker.operation_epoch != self.epoch
                || worker.protocol_version != crate::hypervisor::worker::PROTOCOL_VERSION
                || worker.launch_nonce_sha256 != nonce_hash
                || worker.expected_executable != before.executable
                || worker.identity.is_some()
            {
                return Err("cube-vmm-worker does not match durable spawn INTENT".to_string());
            }
            worker.clone()
        };

        if before.cgroup != self.target.cgroup() {
            move_process_to(self.target.cgroup(), pid)?;
        }
        let actual = process_identity(pid)?;
        if !immutable_identity_matches(&before, &actual)
            || actual.cgroup != self.target.cgroup()
            || actual.executable != expected.expected_executable
        {
            return Err("cube-vmm-worker identity changed during placement".to_string());
        }
        verify_target_membership(&self.target, pid)?;

        let _record_lock = self.handle.record_lock()?;
        let mut record = self.handle.read_record()?;
        self.verify_record(&record)?;
        let worker = record
            .vmm_worker
            .as_mut()
            .ok_or_else(|| "cube-vmm-worker spawn INTENT disappeared".to_string())?;
        if *worker != expected {
            return Err("cube-vmm-worker spawn INTENT changed during placement".to_string());
        }
        worker.state = VmmWorkerState::Allocated;
        worker.identity = Some(actual);
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| "lifecycle sequence overflow".to_string())?;
        atomic_write_json(&self.handle.directory.join(RECORD_FILE), &record)?;
        verify_target_membership(&self.target, pid)
    }
}

impl LifecycleHandle {
    pub(crate) fn classification(&self) -> Result<Classification, String> {
        Ok(self.read_record()?.classification)
    }

    pub(crate) fn acquire_socket_path_guard(
        &self,
        address: &str,
    ) -> Result<SocketPathGuard, String> {
        let path = unix_socket_path(address)?;
        let root = self
            .directory
            .parent()
            .ok_or_else(|| "lifecycle directory has no persistent root".to_string())?;
        acquire_socket_path_lock(root, &path)
    }

    pub(crate) fn create_waiter_guard(&self) -> CreateWaiterGuard {
        CreateWaiterGuard {
            handle: self.clone(),
            armed: true,
        }
    }

    pub(crate) fn create_publisher_guard(&self) -> CreatePublisherGuard {
        CreatePublisherGuard {
            handle: self.clone(),
            armed: true,
            intended: None,
        }
    }

    /// Deterministic PoC failpoint used to hold the first Create after Host
    /// placement and the CONTAINERD_COMMITTED transition, but before any
    /// sandbox-local or RuntimeResource allocation. It is completely inactive
    /// unless the shim inherited an explicit test directory from containerd.
    pub(crate) async fn wait_test_failpoint(&self, name: &str) {
        let Ok(root) = std::env::var("CUBE_SHIM_TEST_FAILPOINT_DIR") else {
            return;
        };
        let root = PathBuf::from(root);
        let reached = root.join(format!(
            "{name}-{}.reached",
            self.instance_id_for_test_hook()
        ));
        let release = root.join(format!(
            "{name}-{}.release",
            self.instance_id_for_test_hook()
        ));
        if fs::create_dir_all(&root).is_err() || atomic_write_bytes(&reached, b"reached\n").is_err()
        {
            return;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while !release.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn instance_id_for_test_hook(&self) -> String {
        self.directory
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unknown")
            .to_string()
    }

    fn create(
        root: &Path,
        params: &BootstrapParams,
        bundle: &Path,
        classification: Classification,
        target: HostTarget,
        address: &str,
        nonce: &[u8],
        executable: &Path,
        debug: bool,
    ) -> Result<Self, String> {
        ensure_directory(root)?;
        let socket_path = unix_socket_path(address)?;
        let _socket_guard = acquire_socket_path_lock(root, &socket_path)?;
        if another_record_owns_socket(root, None, &socket_path)? {
            return Err(format!(
                "shim socket path is already reserved by another live lifecycle: {}",
                socket_path.display()
            ));
        }
        let bundle = fs::canonicalize(bundle)
            .map_err(|error| format!("canonicalize shim bundle {}: {error}", bundle.display()))?;
        let bundle_identity = file_identity(&bundle)?;
        let key = lifecycle_key(
            &params.namespace,
            &params.instance_id,
            &bundle,
            &bundle_identity,
        );
        let directory = root.join(key);
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(format!(
                    "lifecycle directory already exists for {}/{}: {}",
                    params.namespace,
                    params.instance_id,
                    directory.display()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "create lifecycle directory {}: {error}",
                    directory.display()
                ));
            }
        }
        let mut partial = PartialLifecycleDirectory {
            directory: directory.clone(),
            armed: true,
        };
        sync_directory(root)?;
        sync_directory(&directory)?;
        for name in [RECORD_LOCK_FILE, OPERATION_LOCK_FILE] {
            let path = directory.join(name);
            let file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .map_err(|error| format!("create lifecycle lock {}: {error}", path.display()))?;
            file.sync_all()
                .map_err(|error| format!("sync lifecycle lock {}: {error}", path.display()))?;
        }
        sync_directory(&directory)?;

        let helper = process_identity(std::process::id() as i32)?;
        let socket_parent = socket_path
            .parent()
            .ok_or_else(|| format!("shim socket has no parent: {}", socket_path.display()))?;
        let socket = SocketIdentity {
            path: socket_path.display().to_string(),
            parent: file_identity(socket_parent)?,
            device: None,
            inode: None,
            absent_at_prepare: !socket_path.exists(),
        };
        if !socket.absent_at_prepare {
            return Err(format!(
                "refuse lifecycle prepare because socket already exists: {}",
                socket.path
            ));
        }
        let generation = uuid::Uuid::new_v4().to_string();
        let executable = fs::canonicalize(executable).map_err(|error| {
            format!(
                "canonicalize expected CubeShim executable {}: {error}",
                executable.display()
            )
        })?;
        let expected_server_argv = expected_server_argv(params, address, &executable, debug)?;
        let expected_server_command_sha256 = command_sha256(&expected_server_argv);
        let record = LifecycleRecord {
            schema_version: SCHEMA_VERSION,
            sequence: 1,
            generation: generation.clone(),
            phase: LifecyclePhase::Prepared,
            classification,
            namespace: params.namespace.clone(),
            instance_id: params.instance_id.clone(),
            bundle: bundle.display().to_string(),
            bundle_identity,
            created_at_ms: unix_time_ms()?,
            takeover_claimed_at_ms: None,
            launch_nonce_sha256: sha256_hex(nonce),
            expected_server_path: executable.display().to_string(),
            expected_server_executable: file_identity(&executable)?,
            expected_server_argv,
            expected_server_command_sha256,
            helper: helper.clone(),
            server: None,
            target: target.clone(),
            socket,
            operation_owner: OperationOwner {
                kind: OwnerKind::Helper,
                epoch: 1,
                identity: helper,
                revoked_epoch: None,
            },
            create_state: CreateState::None,
            create_fingerprint: None,
            create_waiters: 0,
            failure: None,
            containment_breach: None,
            vmm_worker: None,
            degraded_reason: None,
        };
        let host_owner = HostCgroupOwner {
            schema_version: SCHEMA_VERSION,
            generation: generation.clone(),
            namespace: params.namespace.clone(),
            instance_id: params.instance_id.clone(),
            state: HostOwnerState::Empty,
            target,
            original_cgroup: record.helper.cgroup.clone(),
            server: None,
            controllers: None,
        };
        atomic_write_json(&directory.join(HOST_OWNER_FILE), &host_owner)?;
        atomic_write_json(
            &directory.join(RUNTIME_OWNER_FILE),
            &RuntimeResourceOwner::empty(generation),
        )?;
        // record.json is the commit marker.  Without it no Host mutation is
        // allowed, so a watchdog may safely reap an interrupted constructor.
        atomic_write_json(&directory.join(RECORD_FILE), &record)?;
        partial.armed = false;
        Ok(Self { directory })
    }

    pub(crate) fn from_env() -> Result<Option<Self>, String> {
        let Some(directory) = std::env::var_os(LIFECYCLE_DIR_ENV) else {
            return Ok(None);
        };
        let directory = PathBuf::from(directory);
        if !directory.is_absolute() {
            return Err(format!(
                "{LIFECYCLE_DIR_ENV} must be absolute: {}",
                directory.display()
            ));
        }
        let handle = Self { directory };
        handle.read_record()?;
        Ok(Some(handle))
    }

    fn record_lock(&self) -> Result<RecordLock, String> {
        RecordLock::acquire(&self.directory.join(RECORD_LOCK_FILE))
    }

    fn operation_lock(&self) -> Result<RecordLock, String> {
        RecordLock::acquire(&self.directory.join(OPERATION_LOCK_FILE))
    }

    fn read_record(&self) -> Result<LifecycleRecord, String> {
        let record: LifecycleRecord = read_json(&self.directory.join(RECORD_FILE))?;
        if record.schema_version != SCHEMA_VERSION || record.generation.is_empty() {
            return Err(format!(
                "lifecycle record has unsupported schema or empty generation: {}/{}",
                record.schema_version, record.generation
            ));
        }
        Ok(record)
    }

    fn read_host_owner(&self) -> Result<HostCgroupOwner, String> {
        let owner: HostCgroupOwner = read_json(&self.directory.join(HOST_OWNER_FILE))?;
        if owner.schema_version != SCHEMA_VERSION || owner.generation.is_empty() {
            return Err(format!(
                "Host owner has unsupported schema or empty generation: {}/{}",
                owner.schema_version, owner.generation
            ));
        }
        Ok(owner)
    }

    fn update_record(
        &self,
        update: impl FnOnce(&mut LifecycleRecord) -> Result<(), String>,
    ) -> Result<LifecycleRecord, String> {
        let _lock = self.record_lock()?;
        let mut record = self.read_record()?;
        update(&mut record)?;
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| "lifecycle sequence overflow".to_string())?;
        atomic_write_json(&self.directory.join(RECORD_FILE), &record)?;
        Ok(record)
    }

    fn register_server(&self, nonce: &[u8]) -> Result<(), String> {
        let expected = sha256_hex(nonce);
        let identity = server_process_identity(std::process::id() as i32)?;
        self.register_server_identity(identity, &expected)
    }

    fn register_server_identity(
        &self,
        identity: ProcessIdentity,
        expected_nonce_hash: &str,
    ) -> Result<(), String> {
        let _lock = self.record_lock()?;
        let mut record = self.read_record()?;
        if record.launch_nonce_sha256 != expected_nonce_hash {
            return Err("server launch nonce does not match lifecycle record".to_string());
        }
        if identity.launch_nonce_sha256.as_deref() != Some(expected_nonce_hash) {
            return Err("server process environment nonce does not match PREPARED".to_string());
        }
        if identity.executable != record.expected_server_executable
            || identity.command_sha256 != record.expected_server_command_sha256
            || identity.cwd != record.bundle_identity
        {
            return Err(
                "server executable, argv, or bundle identity changed after PREPARED".to_string(),
            );
        }
        let actual_executable = fs::read_link(format!("/proc/{}/exe", identity.pid))
            .map_err(|error| format!("read server executable link: {error}"))?;
        if actual_executable != Path::new(&record.expected_server_path) {
            return Err(format!(
                "server executable path {} does not match PREPARED {}",
                actual_executable.display(),
                record.expected_server_path
            ));
        }
        if let Some(registered) = &record.server {
            if immutable_identity_matches(registered, &identity) {
                // Parent and child deliberately race to publish the same
                // immutable identity. The loser only verifies it; rewriting
                // the identical durable record adds an fsync to every Pod.
                return Ok(());
            }
            return Err("a different server identity is already registered".to_string());
        }
        if record.phase != LifecyclePhase::Prepared {
            return Err(format!(
                "server registration requires PREPARED, found {:?}",
                record.phase
            ));
        }
        if record.target.cgroup() != identity.cgroup {
            return Err(format!(
                "server registered in {}, expected {}",
                identity.cgroup,
                record.target.cgroup()
            ));
        }
        record.server = Some(identity);
        record.phase = LifecyclePhase::ServerIdentified;
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| "lifecycle sequence overflow".to_string())?;
        atomic_write_json(&self.directory.join(RECORD_FILE), &record)?;
        Ok(())
    }

    fn register_spawned_server(&self, pid: i32, nonce: &[u8]) -> Result<(), String> {
        let expected = sha256_hex(nonce);
        let mut last_error = None;
        let mut identity = None;
        for _ in 0..200 {
            match server_process_identity(pid) {
                Ok(value) => {
                    identity = Some(value);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
            if !Path::new(&format!("/proc/{pid}")).exists() {
                return Err(last_error.unwrap_or_else(|| {
                    format!("spawned server {pid} exited before identity capture")
                }));
            }
            if last_error
                .as_ref()
                .is_some_and(|error| !error.contains("has no CUBE_SHIM_LAUNCH_NONCE"))
            {
                return Err(last_error.unwrap());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let identity = identity.ok_or_else(|| {
            last_error.unwrap_or_else(|| format!("timed out capturing server {pid} identity"))
        })?;
        self.register_server_identity(identity, &expected)
    }

    pub(crate) fn mark_socket_ready(&self, address: &str) -> Result<(), String> {
        let path = unix_socket_path(address)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("stat bound shim socket {}: {error}", path.display()))?;
        if !metadata.file_type().is_socket() {
            return Err(format!(
                "bound shim path is not a socket: {}",
                path.display()
            ));
        }
        self.update_record(|record| {
            if !matches!(
                record.phase,
                LifecyclePhase::ServerIdentified | LifecyclePhase::SocketReady
            ) {
                return Err(format!(
                    "socket readiness requires SERVER_IDENTIFIED, found {:?}",
                    record.phase
                ));
            }
            if record.socket.path != path.display().to_string() {
                return Err("shim socket path changed after PREPARED".to_string());
            }
            if file_identity(path.parent().unwrap())? != record.socket.parent {
                return Err("shim socket parent identity changed".to_string());
            }
            record.socket.device = Some(metadata.dev());
            record.socket.inode = Some(metadata.ino());
            record.phase = LifecyclePhase::SocketReady;
            Ok(())
        })?;
        Ok(())
    }

    pub(crate) fn begin_managed_create(
        &self,
        bundle: &Path,
        cgroup_parent: &str,
        fingerprint: &[u8],
    ) -> Result<CreateAdmission, BeginCreateError> {
        let record = self.read_record().map_err(BeginCreateError::Invalid)?;
        validate_takeover_bundle_identity(&record, bundle).map_err(BeginCreateError::Invalid)?;
        if record.namespace != "k8s.io" {
            return Err(BeginCreateError::Invalid(
                "managed sandbox requires bootstrap namespace k8s.io".to_string(),
            ));
        }
        validate_containerd_id(&record.instance_id).map_err(BeginCreateError::Invalid)?;
        // A durable Create already owns its canonical target. Do not parse or
        // stat a new caller-provided parent before the fingerprint conflict
        // decision (V12); an identical retry will use the durable target and
        // perform exact readback later.
        let target = if matches!(
            record.phase,
            LifecyclePhase::TakeoverClaimed | LifecyclePhase::ContainerdCommitted
        ) {
            record.target.clone()
        } else {
            target_from_cri_parent(cgroup_parent, &record.instance_id)
                .map_err(BeginCreateError::Invalid)?
        };
        self.claim_create(Classification::ManagedSandbox, target, fingerprint)
    }

    pub(crate) fn begin_legacy_create(
        &self,
        bundle: &Path,
        instance_id: &str,
        fingerprint: &[u8],
    ) -> Result<CreateAdmission, BeginCreateError> {
        let record = self.read_record().map_err(BeginCreateError::Invalid)?;
        validate_containerd_id(instance_id).map_err(BeginCreateError::Invalid)?;
        if instance_id != record.instance_id {
            return Err(BeginCreateError::Invalid(format!(
                "legacy CreateTask id {instance_id} does not match bootstrap {}",
                record.instance_id
            )));
        }
        let bundle = validate_takeover_bundle_identity(&record, bundle)
            .map_err(BeginCreateError::Invalid)?;
        let spec = load_spec(&bundle).map_err(BeginCreateError::Invalid)?;
        let params = BootstrapParams {
            namespace: record.namespace.clone(),
            instance_id: record.instance_id.clone(),
            ..Default::default()
        };
        let (classification, target) = classify_and_target(&spec, &params, &record.helper.cgroup)
            .map_err(BeginCreateError::Invalid)?;
        if classification != Classification::LegacyTask {
            return Err(BeginCreateError::Invalid(
                "CreateTask cannot claim a managed Sandbox lifecycle".to_string(),
            ));
        }
        self.claim_create(classification, target, fingerprint)
    }

    fn claim_create(
        &self,
        expected: Classification,
        target: HostTarget,
        fingerprint: &[u8],
    ) -> Result<CreateAdmission, BeginCreateError> {
        let _operation_lock = self.operation_lock().map_err(BeginCreateError::Invalid)?;
        let fingerprint = sha256_hex(fingerprint);
        let server = current_claim_server_identity().map_err(BeginCreateError::Invalid)?;
        let mut admission = CreateAdmission::First;
        let mut commit_attempted = false;
        let mut intended_sequence = None;
        let mut intended_waiters = None;
        let update = self.update_record(|record| {
            if matches!(
                record.phase,
                LifecyclePhase::TakeoverClaimed | LifecyclePhase::ContainerdCommitted
            ) {
                if record.classification != expected || !record.target.same_location(&target) {
                    return Err(format!(
                        "CONFLICT: takeover RPC {:?} does not match durable {:?}",
                        expected, record.classification
                    ));
                }
                if record.create_fingerprint.as_deref() == Some(fingerprint.as_str()) {
                    let owner = &record.operation_owner.identity;
                    if record.operation_owner.kind != OwnerKind::Server
                        || !immutable_identity_matches(owner, &server)
                    {
                        return Err("retry caller or claimed server identity changed".to_string());
                    }
                    if record.phase == LifecyclePhase::ContainerdCommitted {
                        if owner.cgroup != record.target.cgroup()
                            || server.cgroup != record.target.cgroup()
                        {
                            return Err(
                                "retry caller or committed owner containment identity changed"
                                    .to_string(),
                            );
                        }
                        verify_target_membership(&record.target, server.pid)?;
                    } else if !takeover_cgroup_allowed(record, &server.cgroup) {
                        return Err(
                            "retry caller is outside both claimed Host locations".to_string()
                        );
                    }
                    record.create_waiters = record
                        .create_waiters
                        .checked_add(1)
                        .ok_or_else(|| "Create waiter count overflow".to_string())?;
                    admission = match record.create_state {
                        CreateState::InProgress => CreateAdmission::RetryInProgress,
                        CreateState::Succeeded => CreateAdmission::RetrySucceeded,
                        CreateState::Failed => CreateAdmission::RetryFailed,
                        CreateState::None => {
                            return Err("committed Create has no durable state".to_string())
                        }
                    };
                    intended_sequence = Some(
                        record
                            .sequence
                            .checked_add(1)
                            .ok_or_else(|| "lifecycle sequence overflow".to_string())?,
                    );
                    intended_waiters = Some(record.create_waiters);
                    commit_attempted = true;
                    return Ok(());
                }
                return Err(
                    "CONFLICT: sandbox already has a different takeover fingerprint".to_string(),
                );
            }
            if record.phase != LifecyclePhase::SocketReady {
                return Err(format!(
                    "takeover requires SOCKET_READY, found {:?}",
                    record.phase
                ));
            }
            if record.classification != Classification::Pending
                || !matches!(record.target, HostTarget::Pending { .. })
            {
                return Err(
                    "unclaimed lifecycle has a concrete classification or target".to_string(),
                );
            }
            let registered = record
                .server
                .as_ref()
                .ok_or_else(|| "takeover record has no server identity".to_string())?;
            if !immutable_identity_matches(registered, &server) {
                return Err("takeover caller does not match registered server".to_string());
            }
            if registered.cgroup != record.target.cgroup()
                || server.cgroup != record.target.cgroup()
            {
                return Err("first takeover caller left the bootstrap cgroup".to_string());
            }
            verify_target_membership(&record.target, server.pid)?;
            if expected == Classification::ManagedSandbox && target.leaf_identity().is_some() {
                return Err(format!(
                    "refuse to reuse an existing managed Host leaf {}",
                    target.cgroup()
                ));
            }
            let old_epoch = record.operation_owner.epoch;
            record.operation_owner = OperationOwner {
                kind: OwnerKind::Server,
                epoch: old_epoch
                    .checked_add(1)
                    .ok_or_else(|| "operation owner epoch overflow".to_string())?,
                identity: server.clone(),
                revoked_epoch: None,
            };
            record.classification = expected;
            record.target = target.clone();
            record.phase = LifecyclePhase::TakeoverClaimed;
            record.takeover_claimed_at_ms = Some(unix_time_ms()?);
            record.create_state = CreateState::InProgress;
            record.create_fingerprint = Some(fingerprint.clone());
            record.create_waiters = 1;
            intended_sequence = Some(
                record
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| "lifecycle sequence overflow".to_string())?,
            );
            intended_waiters = Some(record.create_waiters);
            commit_attempted = true;
            Ok(())
        });
        if let Err(error) = update {
            // rename(2) may have committed the exact claim even when the
            // following directory fsync reports an error.  While the unique
            // operation lock is still held, read back the record and complete
            // the parent fsync.  The current caller retains First/retry
            // ownership; it must never strand an ownerless IN_PROGRESS claim.
            if commit_attempted {
                let _record_lock = self.record_lock().map_err(BeginCreateError::Invalid)?;
                let durable = self.read_record().map_err(BeginCreateError::Invalid)?;
                let exact = matches!(
                    durable.phase,
                    LifecyclePhase::TakeoverClaimed | LifecyclePhase::ContainerdCommitted
                ) && durable.classification == expected
                    && durable.target.same_location(&target)
                    && durable.create_fingerprint.as_deref() == Some(fingerprint.as_str())
                    && durable.operation_owner.kind == OwnerKind::Server
                    && immutable_identity_matches(&durable.operation_owner.identity, &server)
                    && durable.create_state != CreateState::None
                    && Some(durable.sequence) == intended_sequence
                    && Some(durable.create_waiters) == intended_waiters;
                if exact {
                    sync_directory(&self.directory).map_err(BeginCreateError::Invalid)?;
                    return Ok(admission);
                }
            }
            return Err(if let Some(message) = error.strip_prefix("CONFLICT: ") {
                BeginCreateError::Conflict(message.to_string())
            } else {
                BeginCreateError::Invalid(error)
            });
        }
        Ok(admission)
    }

    pub(crate) fn commit_legacy_takeover(&self) -> Result<(), String> {
        self.commit_host_placement(false)
    }

    pub(crate) fn place_managed_server(&self) -> Result<(), String> {
        self.commit_host_placement(true)
    }

    fn commit_host_placement(&self, managed: bool) -> Result<(), String> {
        let _operation_lock = self.operation_lock()?;
        let expected = if managed {
            Classification::ManagedSandbox
        } else {
            Classification::LegacyTask
        };
        let owner_path = self.directory.join(HOST_OWNER_FILE);
        let (registered, claim_epoch, target, trace_sandbox_id) = {
            // Keep record.lock only around validation and the durable Host
            // INTENT. The scanner must be able to revoke this epoch while a
            // systemd/cgroupfs placement call is stuck.
            let _record_lock = self.record_lock()?;
            let mut record = self.read_record()?;
            if record.phase == LifecyclePhase::ContainerdCommitted {
                if record.classification != expected {
                    return Err("committed takeover classification changed".to_string());
                }
                return Ok(());
            }
            if record.phase != LifecyclePhase::TakeoverClaimed
                || record.classification != expected
                || record.operation_owner.kind != OwnerKind::Server
                || record.operation_owner.revoked_epoch.is_some()
                || record.create_state != CreateState::InProgress
            {
                return Err(format!(
                    "Host placement requires an unfenced claimed {:?} server with an IN_PROGRESS Create, found {:?}/{:?}/{:?}/{:?}/revoked={:?}",
                    expected,
                    record.phase,
                    record.classification,
                    record.operation_owner.kind,
                    record.create_state,
                    record.operation_owner.revoked_epoch
                ));
            }
            let registered = record
                .server
                .as_ref()
                .ok_or_else(|| "claimed takeover has no registered server".to_string())?
                .clone();
            let server = current_claim_server_identity()?;
            if !immutable_identity_matches(&registered, &server)
                || !immutable_identity_matches(&record.operation_owner.identity, &server)
            {
                return Err("Host placement caller does not match claimed server".to_string());
            }
            if !takeover_cgroup_allowed(&record, &server.cgroup) {
                return Err(format!(
                    "claimed server is outside both Host placement locations: {}",
                    server.cgroup
                ));
            }

            let mut host_owner = self.read_host_owner()?;
            if host_owner.generation != record.generation
                || host_owner.namespace != record.namespace
                || host_owner.instance_id != record.instance_id
                || host_owner.original_cgroup != record.helper.cgroup
            {
                return Err("Host owner identity differs from claimed lifecycle".to_string());
            }

            if managed {
                if !record.target.managed() {
                    return Err("managed claim has no managed Host target".to_string());
                }
                match host_owner.state {
                    HostOwnerState::Empty => {
                        if !matches!(host_owner.target, HostTarget::Pending { .. }) {
                            return Err(
                                "EMPTY Host owner unexpectedly has a concrete target".to_string()
                            );
                        }
                        host_owner.state = HostOwnerState::Intent;
                        host_owner.target = record.target.clone();
                        host_owner.server = Some(server);
                        // This INTENT precedes every external Host mutation.
                        atomic_write_json(&owner_path, &host_owner)?;
                    }
                    HostOwnerState::Intent => {
                        if !host_owner.target.same_location(&record.target)
                            || host_owner
                                .server
                                .as_ref()
                                .is_none_or(|owner| !immutable_identity_matches(owner, &registered))
                        {
                            return Err(
                                "Host INTENT differs from the durable takeover claim".to_string()
                            );
                        }
                    }
                    HostOwnerState::Allocated => {
                        if !host_owner.target.same_location(&record.target) {
                            return Err("allocated Host owner target changed".to_string());
                        }
                    }
                }
            } else {
                if host_owner.state != HostOwnerState::Empty
                    || !matches!(host_owner.target, HostTarget::Pending { .. })
                    || !matches!(record.target, HostTarget::Legacy { .. })
                {
                    return Err("legacy takeover must retain an EMPTY Host owner".to_string());
                }
                verify_target_membership(&record.target, server.pid)?;
                record.server = Some(server.clone());
                record.operation_owner.identity = server;
                record.phase = LifecyclePhase::ContainerdCommitted;
                record.sequence = record
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| "lifecycle sequence overflow".to_string())?;
                atomic_write_json(&self.directory.join(RECORD_FILE), &record)?;
                return Ok(());
            }
            (
                registered,
                record.operation_owner.epoch,
                record.target.clone(),
                record.instance_id.clone(),
            )
        };

        let mut server = current_claim_server_identity()?;
        if server.cgroup != target.cgroup() {
            create_and_join_target(&target, server.pid, Some(&trace_sandbox_id))?;
        }
        server = current_claim_server_identity()?;
        if !immutable_identity_matches(&registered, &server) {
            return Err("server identity changed during Host placement".to_string());
        }
        verify_target_membership(&target, server.pid)?;
        let leaf_path = Path::new("/sys/fs/cgroup").join(target.cgroup().trim_start_matches('/'));
        let leaf_identity = file_identity(&leaf_path)?;

        // Re-enter record.lock only after the external placement completed.
        // A scanner may have revoked the claim in the meantime; in that case
        // leave the durable INTENT for cleanup and publish no ALLOCATED/commit.
        let _record_lock = self.record_lock()?;
        let mut record = self.read_record()?;
        if record.phase != LifecyclePhase::TakeoverClaimed
            || record.classification != expected
            || record.create_state != CreateState::InProgress
            || record.operation_owner.kind != OwnerKind::Server
            || record.operation_owner.epoch != claim_epoch
            || record.operation_owner.revoked_epoch.is_some()
            || !immutable_identity_matches(&record.operation_owner.identity, &registered)
            || !record.target.same_location(&target)
        {
            return Err("Host placement claim was revoked or changed during mutation".to_string());
        }
        if !immutable_identity_matches(record.server.as_ref().unwrap_or(&registered), &server) {
            return Err("registered server identity changed during Host placement".to_string());
        }
        verify_target_membership(&record.target, server.pid)?;
        let mut host_owner = self.read_host_owner()?;
        if host_owner.generation != record.generation
            || host_owner.state == HostOwnerState::Empty
            || !host_owner.target.same_location(&record.target)
            || host_owner
                .server
                .as_ref()
                .is_none_or(|owner| !immutable_identity_matches(owner, &server))
        {
            return Err("Host owner changed during placement".to_string());
        }
        record.target.set_leaf_identity(leaf_identity.clone());
        host_owner.target.set_leaf_identity(leaf_identity);
        host_owner.server = Some(server.clone());
        host_owner.state = HostOwnerState::Allocated;
        atomic_write_json(&owner_path, &host_owner)?;
        record.server = Some(server.clone());
        record.operation_owner.identity = server;
        record.phase = LifecyclePhase::ContainerdCommitted;
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| "lifecycle sequence overflow".to_string())?;
        atomic_write_json(&self.directory.join(RECORD_FILE), &record)?;
        verify_target_membership(&record.target, std::process::id() as i32)
    }

    /// Apply or recover the static Host leaf transaction. The operation lock
    /// serializes all external mutations, while every individual write is
    /// preceded by a durable INTENT and a fresh epoch/identity check under the
    /// record lock.
    pub(crate) fn apply_host_resource_ceiling(
        &self,
        ceiling: &HostResourceCeiling,
    ) -> Result<(), String> {
        let _operation_lock = self.operation_lock()?;
        let (epoch, identity, target, fingerprint) = {
            let _record_lock = self.record_lock()?;
            let record = self.read_record()?;
            verify_controller_record(&record)?;
            let owner = self.read_host_owner()?;
            verify_host_owner_for_record(&owner, &record)?;
            (
                record.operation_owner.epoch,
                record.operation_owner.identity.clone(),
                record.target.clone(),
                record
                    .create_fingerprint
                    .clone()
                    .ok_or_else(|| "managed Create has no fingerprint".to_string())?,
            )
        };
        let leaf = host_leaf_path(&target)?;
        let targets = controller_targets(ceiling);

        {
            let _record_lock = self.record_lock()?;
            let record = self.read_record()?;
            verify_controller_claim(&record, epoch, &identity, &target)?;
            let mut owner = self.read_host_owner()?;
            verify_host_owner_for_record(&owner, &record)?;
            match owner.controllers.as_ref() {
                Some(journal) => {
                    verify_controller_journal_identity(
                        journal,
                        epoch,
                        &identity,
                        &fingerprint,
                        &targets,
                    )?;
                }
                None => {
                    let mut steps = Vec::with_capacity(targets.len());
                    for (file, target_value) in &targets {
                        steps.push(ControllerStep {
                            file: (*file).to_string(),
                            old: read_controller_value(&leaf, file)?,
                            target: target_value.clone(),
                            state: ControllerStepState::NotStarted,
                            observed: None,
                        });
                    }
                    preflight_controller_targets(&leaf, &steps)?;
                    owner.controllers = Some(ControllerJournal {
                        schema_version: 1,
                        transaction_id: uuid::Uuid::new_v4().to_string(),
                        owner_epoch: epoch,
                        owner_identity: identity.clone(),
                        create_fingerprint: fingerprint.clone(),
                        state: ControllerTransactionState::Prepared,
                        steps,
                        degraded_reason: None,
                    });
                    persist_host_owner_exact(&self.directory, &owner)?;
                }
            }
        }
        controller_test_failpoint(&self.directory, "after-prepared")?;

        match self.replay_controller_forward(epoch, &identity, &target, &fingerprint) {
            Ok(()) => Ok(()),
            Err(forward_error) => {
                let rollback =
                    self.rollback_controller_as_server(epoch, &identity, &target, &fingerprint);
                match rollback {
                    Ok(()) => Err(forward_error),
                    Err(rollback_error) => Err(format!(
                        "{forward_error}; Host controller rollback: {rollback_error}"
                    )),
                }
            }
        }
    }

    fn replay_controller_forward(
        &self,
        epoch: u64,
        identity: &ProcessIdentity,
        target: &HostTarget,
        fingerprint: &str,
    ) -> Result<(), String> {
        let leaf = host_leaf_path(target)?;
        replay_controller_forward_state(
            &leaf,
            || {
                let _record_lock = self.record_lock()?;
                let record = self.read_record()?;
                verify_controller_claim(&record, epoch, identity, target)?;
                let owner = self.read_host_owner()?;
                verify_host_owner_for_record(&owner, &record)?;
                let journal = owner
                    .controllers
                    .as_ref()
                    .ok_or_else(|| "Host controller journal disappeared".to_string())?;
                verify_controller_journal_owner(journal, epoch, identity, fingerprint)?;
                Ok(journal.clone())
            },
            |updated| {
                let _record_lock = self.record_lock()?;
                let record = self.read_record()?;
                verify_controller_claim(&record, epoch, identity, target)?;
                let mut owner = self.read_host_owner()?;
                verify_host_owner_for_record(&owner, &record)?;
                if owner.controllers.as_ref().is_none_or(|current| {
                    current.transaction_id != updated.transaction_id
                        || current.owner_epoch != updated.owner_epoch
                }) {
                    return Err("Host controller transaction changed during forward".to_string());
                }
                owner.controllers = Some(updated.clone());
                persist_host_owner_exact(&self.directory, &owner)
            },
            || {
                let _record_lock = self.record_lock()?;
                let record = self.read_record()?;
                verify_controller_claim(&record, epoch, identity, target)
            },
            |name| controller_test_failpoint(&self.directory, name),
        )
    }

    fn rollback_controller_as_server(
        &self,
        epoch: u64,
        identity: &ProcessIdentity,
        target: &HostTarget,
        fingerprint: &str,
    ) -> Result<(), String> {
        let leaf = host_leaf_path(target)?;
        {
            let _record_lock = self.record_lock()?;
            let record = self.read_record()?;
            verify_controller_claim(&record, epoch, identity, target)?;
            let mut owner = self.read_host_owner()?;
            let journal = owner
                .controllers
                .as_mut()
                .ok_or_else(|| "Host controller journal disappeared before rollback".to_string())?;
            verify_controller_journal_owner(journal, epoch, identity, fingerprint)?;
            if journal.state != ControllerTransactionState::Restored {
                journal.state = ControllerTransactionState::RollingBack;
                persist_host_owner_exact(&self.directory, &owner)?;
            }
        }
        replay_controller_rollback_with_failpoint(
            &leaf,
            || {
                let _record_lock = self.record_lock()?;
                let record = self.read_record()?;
                verify_controller_claim(&record, epoch, identity, target)?;
                let owner = self.read_host_owner()?;
                let journal = owner.controllers.ok_or_else(|| {
                    "Host controller journal disappeared during rollback".to_string()
                })?;
                verify_controller_journal_owner(&journal, epoch, identity, fingerprint)?;
                Ok(journal)
            },
            |updated| {
                let _record_lock = self.record_lock()?;
                let record = self.read_record()?;
                verify_controller_claim(&record, epoch, identity, target)?;
                let mut owner = self.read_host_owner()?;
                let current = owner.controllers.as_ref().ok_or_else(|| {
                    "Host controller journal disappeared during rollback".to_string()
                })?;
                if current.transaction_id != updated.transaction_id {
                    return Err("Host controller transaction changed during rollback".to_string());
                }
                owner.controllers = Some(updated.clone());
                persist_host_owner_exact(&self.directory, &owner)
            },
            || {
                let _record_lock = self.record_lock()?;
                let record = self.read_record()?;
                verify_controller_claim(&record, epoch, identity, target)
            },
            |name| controller_test_failpoint(&self.directory, name),
        )?;
        let _record_lock = self.record_lock()?;
        let record = self.read_record()?;
        verify_controller_claim(&record, epoch, identity, target)?;
        let mut owner = self.read_host_owner()?;
        verify_host_owner_for_record(&owner, &record)?;
        let journal = owner
            .controllers
            .as_ref()
            .ok_or_else(|| "Host controller journal disappeared after rollback".to_string())?;
        verify_controller_journal_owner(journal, epoch, identity, fingerprint)?;
        if journal.state != ControllerTransactionState::Restored {
            return Err("Host controller rollback did not reach RESTORED".to_string());
        }
        clear_restored_controller_journal(&leaf, &mut owner.controllers)?;
        persist_host_owner_exact(&self.directory, &owner)
    }

    pub(crate) fn finish_create_success(&self) -> Result<(), String> {
        let _operation_lock = self.operation_lock()?;
        let _record_lock = self.record_lock()?;
        let mut record = self.read_record()?;
        if record.phase != LifecyclePhase::ContainerdCommitted {
            return Err(format!(
                "successful Create requires CONTAINERD_COMMITTED, found {:?}",
                record.phase
            ));
        }
        if record.create_state == CreateState::Succeeded {
            return Ok(());
        }
        if record.create_state != CreateState::InProgress {
            return Err(format!(
                "successful Create cannot replace {:?}",
                record.create_state
            ));
        }
        if record.classification == Classification::ManagedSandbox {
            let owner = self.read_host_owner()?;
            verify_host_owner_for_record(&owner, &record)?;
            let journal = owner.controllers.as_ref().ok_or_else(|| {
                "successful managed Create has no Host controller journal".to_string()
            })?;
            if journal.state != ControllerTransactionState::ControllersCommitted {
                return Err(format!(
                    "successful managed Create requires CONTROLLERS_COMMITTED, found {:?}",
                    journal.state
                ));
            }
            exact_controller_readback(&host_leaf_path(&record.target)?, journal, true)?;
        }
        record.create_state = CreateState::Succeeded;
        record.failure = None;
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| "lifecycle sequence overflow".to_string())?;
        atomic_write_json(&self.directory.join(RECORD_FILE), &record)
    }

    pub(crate) fn finish_create_failure(&self, code: &str, message: &str) -> Result<(), String> {
        self.update_record(|record| {
            if !matches!(
                record.phase,
                LifecyclePhase::TakeoverClaimed | LifecyclePhase::ContainerdCommitted
            ) {
                return Err(format!(
                    "failed Create requires TAKEOVER_CLAIMED or CONTAINERD_COMMITTED, found {:?}",
                    record.phase
                ));
            }
            if record.create_state == CreateState::Failed {
                return match record.failure.as_ref() {
                    Some(existing) if existing.code == code && existing.message == message => {
                        Ok(())
                    }
                    Some(existing) => Err(format!(
                        "refuse to replace durable Create failure {}/{} with {code}/{message}",
                        existing.code, existing.message
                    )),
                    None => Err("durable FAILED Create has no result identity".to_string()),
                };
            }
            if record.create_state != CreateState::InProgress {
                return Err(format!(
                    "failed Create cannot replace {:?}",
                    record.create_state
                ));
            }
            record.create_state = CreateState::Failed;
            record.failure = Some(FailureResult {
                code: code.to_string(),
                message: message.to_string(),
                published_at_ms: unix_time_ms()?,
                waiter_count: record.create_waiters,
                drained: false,
            });
            Ok(())
        })?;
        Ok(())
    }

    pub(crate) fn finish_create_waiter(&self) -> Result<(), String> {
        self.update_record(|record| {
            record.create_waiters = record
                .create_waiters
                .checked_sub(1)
                .ok_or_else(|| "Create waiter count underflow".to_string())?;
            if record.create_waiters == 0 {
                if let Some(failure) = record.failure.as_mut() {
                    failure.drained = true;
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    pub(crate) async fn wait_create_result(
        &self,
        timeout: Duration,
    ) -> Result<PersistedCreateResult, String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(result) = self.current_create_result()? {
                return Ok(result);
            }
            if std::time::Instant::now() >= deadline {
                return Err("timed out waiting for durable Create result".to_string());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub(crate) fn current_create_result(&self) -> Result<Option<PersistedCreateResult>, String> {
        let record = self.read_record()?;
        match record.create_state {
            CreateState::Succeeded => Ok(Some(PersistedCreateResult::Succeeded)),
            CreateState::Failed => {
                let failure = record
                    .failure
                    .ok_or_else(|| "FAILED Create has no published result".to_string())?;
                Ok(Some(PersistedCreateResult::Failed {
                    code: failure.code,
                    message: failure.message,
                }))
            }
            CreateState::InProgress => Ok(None),
            CreateState::None => Err("Create takeover is not committed".to_string()),
        }
    }

    pub(crate) fn runtime_owner(&self) -> Result<RuntimeResourceOwner, String> {
        let _lock = self.record_lock()?;
        read_json(&self.directory.join(RUNTIME_OWNER_FILE))
    }

    pub(crate) fn begin_runtime_intent(
        &self,
        owner: &RuntimeResourceOwner,
    ) -> Result<LifecycleOperation, String> {
        let operation_lock = self.operation_lock()?;
        let _record_lock = self.record_lock()?;
        let record = self.read_record()?;
        if record.operation_owner.kind != OwnerKind::Server
            || record.phase != LifecyclePhase::ContainerdCommitted
            || record.create_state != CreateState::InProgress
        {
            return Err(format!(
                "RuntimeResource allocation requires an IN_PROGRESS Create with committed server owner; found {:?}/{:?}/{:?}",
                record.operation_owner.kind, record.phase, record.create_state
            ));
        }
        let operation = LifecycleOperation {
            handle: self.clone(),
            epoch: record.operation_owner.epoch,
            owner: OwnerKind::Server,
            identity: record.operation_owner.identity.clone(),
            target: record.target.clone(),
            _lock: operation_lock,
        };
        operation.verify_record(&record)?;
        if record.classification == Classification::ManagedSandbox {
            let host_owner = self.read_host_owner()?;
            verify_host_owner_for_record(&host_owner, &record)?;
            let journal = host_owner.controllers.as_ref().ok_or_else(|| {
                "RuntimeResource allocation requires a Host controller journal".to_string()
            })?;
            if journal.state != ControllerTransactionState::ControllersCommitted {
                return Err(format!(
                    "RuntimeResource allocation requires CONTROLLERS_COMMITTED, found {:?}",
                    journal.state
                ));
            }
            verify_controller_journal_owner(
                journal,
                record.operation_owner.epoch,
                &record.operation_owner.identity,
                record
                    .create_fingerprint
                    .as_deref()
                    .ok_or_else(|| "managed Create has no fingerprint".to_string())?,
            )?;
            exact_controller_readback(&host_leaf_path(&record.target)?, journal, true)?;
        }
        let mut owner = owner.clone();
        owner.generation_id = record.generation.clone();
        atomic_write_json(&self.directory.join(RUNTIME_OWNER_FILE), &owner)?;
        Ok(operation)
    }

    pub(crate) fn validate_cri_parent(&self, cgroup_parent: &str) -> Result<(), String> {
        let record = self.read_record()?;
        if record.classification != Classification::ManagedSandbox {
            return Ok(());
        }
        validate_unified_cgroup_mount()?;
        let actual = canonical_cri_cgroup_parent(cgroup_parent)?;
        let expected = match &record.target {
            HostTarget::Systemd { cgroup, .. } | HostTarget::Cgroupfs { cgroup, .. } => {
                Path::new(cgroup)
                    .parent()
                    .ok_or_else(|| format!("Host target has no parent: {cgroup}"))?
                    .display()
                    .to_string()
            }
            HostTarget::Pending { .. } | HostTarget::Legacy { .. } => {
                return Err("managed lifecycle unexpectedly uses a legacy Host target".to_string())
            }
        };
        if actual != expected {
            return Err(format!(
                "CRI cgroup_parent {actual} does not match OCI Host parent {expected}"
            ));
        }
        let path = Path::new("/sys/fs/cgroup").join(actual.trim_start_matches('/'));
        let expected_identity = record
            .target
            .parent_identity()
            .ok_or_else(|| "managed Host target has no parent identity".to_string())?;
        if file_identity(&path)? != *expected_identity {
            return Err(format!(
                "CRI cgroup_parent identity changed: {}",
                path.display()
            ));
        }
        Ok(())
    }

    pub(crate) fn begin_runtime_release(&self) -> Result<LifecycleOperation, String> {
        self.begin_server_operation(
            "RuntimeResource release",
            &[
                CreateState::InProgress,
                CreateState::Succeeded,
                CreateState::Failed,
            ],
        )
    }

    fn begin_server_operation(
        &self,
        action: &str,
        allowed_create_states: &[CreateState],
    ) -> Result<LifecycleOperation, String> {
        let operation_lock = self.operation_lock()?;
        let _record_lock = self.record_lock()?;
        let record = self.read_record()?;
        if record.operation_owner.kind != OwnerKind::Server
            || record.phase != LifecyclePhase::ContainerdCommitted
            || record.operation_owner.revoked_epoch.is_some()
            || !allowed_create_states.contains(&record.create_state)
        {
            return Err(format!(
                "{action} requires an unfenced committed server in an allowed Create state; found {:?}/{:?}/{:?}/revoked={:?}",
                record.operation_owner.kind,
                record.phase,
                record.create_state,
                record.operation_owner.revoked_epoch
            ));
        }
        let operation = LifecycleOperation {
            handle: self.clone(),
            epoch: record.operation_owner.epoch,
            owner: OwnerKind::Server,
            identity: record.operation_owner.identity.clone(),
            target: record.target.clone(),
            _lock: operation_lock,
        };
        operation.verify_record(&record)?;
        Ok(operation)
    }

    pub(crate) fn begin_start_operation(&self) -> Result<LifecycleOperation, String> {
        self.begin_server_operation("StartSandbox", &[CreateState::Succeeded])
    }

    /// Holds the same operation barrier used by cleanup while a durable
    /// SUCCEEDED Create is read back from the RuntimeResource provider. The
    /// caller must verify again after Inspect before returning success.
    pub(crate) fn begin_create_readback_operation(&self) -> Result<LifecycleOperation, String> {
        self.begin_server_operation("CreateSandbox readback", &[CreateState::Succeeded])
    }

    fn begin_helper_host_operation(&self) -> Result<LifecycleOperation, String> {
        let operation_lock = self.operation_lock()?;
        let record = self.read_record()?;
        let helper = process_identity(std::process::id() as i32)?;
        if record.operation_owner.kind != OwnerKind::Helper
            || record.phase != LifecyclePhase::Prepared
            || !immutable_identity_matches(&record.helper, &helper)
            || record.helper.cgroup != helper.cgroup
        {
            return Err(format!(
                "Host leaf mutation requires PREPARED helper owner; found {:?}/{:?}",
                record.operation_owner.kind, record.phase
            ));
        }
        verify_live_target_identity(&record.target)?;
        Ok(LifecycleOperation {
            handle: self.clone(),
            epoch: record.operation_owner.epoch,
            owner: OwnerKind::Helper,
            identity: record.operation_owner.identity.clone(),
            target: record.target.clone(),
            _lock: operation_lock,
        })
    }

    fn persist_leaf_identity(&self, identity: FileIdentity) -> Result<(), String> {
        let _record_lock = self.record_lock()?;
        let mut record = self.read_record()?;
        let mut owner = self.read_host_owner()?;
        if record.generation != owner.generation || !record.target.same_location(&owner.target) {
            return Err("Host owner identity changed while recording leaf".to_string());
        }
        owner.target.set_leaf_identity(identity.clone());
        atomic_write_json(&self.directory.join(HOST_OWNER_FILE), &owner)?;
        record.target.set_leaf_identity(identity);
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| "lifecycle sequence overflow".to_string())?;
        atomic_write_json(&self.directory.join(RECORD_FILE), &record)
    }

    pub(crate) fn request_cleanup(&self, reason: &str) -> Result<(), String> {
        let record = self.update_record(|record| {
            if record.phase == LifecyclePhase::Done {
                return Ok(());
            }
            if matches!(
                record.phase,
                LifecyclePhase::TakeoverClaimed | LifecyclePhase::ContainerdCommitted
            ) {
                if record.create_state == CreateState::InProgress {
                    // containerd may invoke the delete action immediately
                    // after losing the Create RPC connection.  Publish the
                    // terminal result before cleanup so duplicate waiters and
                    // the external scanner observe one deterministic outcome.
                    record.create_state = CreateState::Failed;
                    record.failure = Some(FailureResult {
                        code: "CANCELLED".to_string(),
                        message: reason.to_string(),
                        published_at_ms: unix_time_ms()?,
                        waiter_count: record.create_waiters,
                        drained: record.create_waiters == 0,
                    });
                    // Fence a still-live Create actor immediately. It may
                    // already hold the operation lock, so cleanup cannot wait
                    // for that lock before publishing the terminal result.
                    // The next epoch check prevents later provider mutations;
                    // if an allocating RPC is already in flight, its durable
                    // INTENT remains replayable by cleanup.
                    let old_epoch = record.operation_owner.epoch;
                    record.operation_owner.epoch = old_epoch
                        .checked_add(1)
                        .ok_or_else(|| "operation owner epoch overflow".to_string())?;
                    record.operation_owner.revoked_epoch = Some(old_epoch);
                    return Ok(());
                }
                if record.create_state == CreateState::Failed
                    && !create_failure_cleanup_ready(record)?
                {
                    return Ok(());
                }
            }
            if !matches!(
                record.phase,
                LifecyclePhase::CleanupRequired
                    | LifecyclePhase::CleanupOwnersDurable
                    | LifecyclePhase::ServerStopped
            ) {
                let old_epoch = record.operation_owner.epoch;
                record.operation_owner.epoch = old_epoch
                    .checked_add(1)
                    .ok_or_else(|| "operation owner epoch overflow".to_string())?;
                record.operation_owner.revoked_epoch = Some(old_epoch);
                record.phase = LifecyclePhase::CleanupRequired;
            }
            Ok(())
        })?;
        if record.phase == LifecyclePhase::Done {
            return Ok(());
        }
        atomic_write_bytes(&self.directory.join(CLEANUP_REASON_FILE), reason.as_bytes())
    }

    fn scanner_publish_failure_if_current(
        &self,
        snapshot: &LifecycleRecord,
        code: &str,
        message: &str,
        observed_cgroup: Option<&str>,
    ) -> Result<bool, String> {
        let observed = observed_cgroup.map(containment_identity).transpose()?;
        // Fault publication is the fencing edge. It must not wait for an
        // in-flight provider operation that already holds operation.lock:
        // persist FAILED and revoke that operation's epoch under record.lock
        // first. Cleanup later waits on operation.lock after both owner
        // handoffs are durable.
        let _record_lock = self.record_lock()?;
        let mut record = self.read_record()?;
        if !same_scanner_snapshot(snapshot, &record) {
            return Ok(false);
        }
        if record.create_state != CreateState::InProgress
            || !matches!(
                record.phase,
                LifecyclePhase::TakeoverClaimed | LifecyclePhase::ContainerdCommitted
            )
        {
            return Err(format!(
                "scanner failure takeover requires active Create, found {:?}/{:?}",
                record.phase, record.create_state
            ));
        }
        if record.containment_breach.is_none() {
            record.containment_breach = observed;
        }
        let old_epoch = record.operation_owner.epoch;
        record.operation_owner.epoch = old_epoch
            .checked_add(1)
            .ok_or_else(|| "operation owner epoch overflow".to_string())?;
        record.operation_owner.revoked_epoch = Some(old_epoch);
        record.create_state = CreateState::Failed;
        record.failure = Some(FailureResult {
            code: code.to_string(),
            message: message.to_string(),
            published_at_ms: unix_time_ms()?,
            waiter_count: record.create_waiters,
            drained: record.create_waiters == 0,
        });
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| "lifecycle sequence overflow".to_string())?;
        atomic_write_json(&self.directory.join(RECORD_FILE), &record)?;
        Ok(true)
    }

    fn scanner_request_cleanup_if_current(
        &self,
        snapshot: &LifecycleRecord,
        reason: &str,
        observed_cgroup: Option<&str>,
    ) -> Result<bool, String> {
        let observed = observed_cgroup.map(containment_identity).transpose()?;
        // Revoke and transition to cleanup under record.lock before waiting
        // for any operation barrier. This keeps a stuck provider RPC from
        // blocking durable fencing and owner handoff.
        let _record_lock = self.record_lock()?;
        let mut record = self.read_record()?;
        if !same_scanner_snapshot(snapshot, &record) {
            return Ok(false);
        }
        if matches!(
            record.phase,
            LifecyclePhase::TakeoverClaimed | LifecyclePhase::ContainerdCommitted
        ) {
            if record.create_state == CreateState::None {
                return Err("scanner found claimed lifecycle without Create state".to_string());
            }
            if record.create_state == CreateState::InProgress {
                return Err("scanner cannot revoke an IN_PROGRESS Create before publishing its durable failure".to_string());
            }
            if record.create_state == CreateState::Failed && !create_failure_cleanup_ready(&record)?
            {
                return Ok(false);
            }
        }
        if record.phase == LifecyclePhase::Done {
            return Ok(false);
        }
        if record.containment_breach.is_none() {
            record.containment_breach = observed;
        }
        if !matches!(
            record.phase,
            LifecyclePhase::CleanupRequired
                | LifecyclePhase::CleanupOwnersDurable
                | LifecyclePhase::ServerStopped
        ) {
            let old_epoch = record.operation_owner.epoch;
            record.operation_owner.epoch = old_epoch
                .checked_add(1)
                .ok_or_else(|| "operation owner epoch overflow".to_string())?;
            record.operation_owner.revoked_epoch = Some(old_epoch);
            record.phase = LifecyclePhase::CleanupRequired;
        }
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| "lifecycle sequence overflow".to_string())?;
        atomic_write_json(&self.directory.join(RECORD_FILE), &record)?;
        atomic_write_bytes(&self.directory.join(CLEANUP_REASON_FILE), reason.as_bytes())?;
        Ok(true)
    }

    pub(crate) fn request_degraded_cleanup(&self, reason: &str) -> Result<(), String> {
        let record = self.update_record(|record| {
            if record.phase == LifecyclePhase::Done {
                return Ok(());
            }
            if record.degraded_reason.is_none() {
                record.degraded_reason = Some(reason.to_string());
            }
            if !matches!(
                record.phase,
                LifecyclePhase::CleanupRequired
                    | LifecyclePhase::CleanupOwnersDurable
                    | LifecyclePhase::ServerStopped
            ) {
                let old_epoch = record.operation_owner.epoch;
                record.operation_owner.epoch = old_epoch
                    .checked_add(1)
                    .ok_or_else(|| "operation owner epoch overflow".to_string())?;
                record.operation_owner.revoked_epoch = Some(old_epoch);
                record.phase = LifecyclePhase::CleanupRequired;
            }
            Ok(())
        })?;
        if record.phase != LifecyclePhase::Done {
            atomic_write_bytes(&self.directory.join(CLEANUP_REASON_FILE), reason.as_bytes())?;
        }
        Ok(())
    }

    fn request_containment_cleanup(
        &self,
        observed_cgroup: &str,
        reason: &str,
    ) -> Result<(), String> {
        let observed = containment_identity(observed_cgroup)?;
        let record = self.update_record(|record| {
            if record.phase == LifecyclePhase::Done {
                return Ok(());
            }
            if record.containment_breach.is_none() {
                record.containment_breach = Some(observed);
            }
            if !matches!(
                record.phase,
                LifecyclePhase::CleanupRequired
                    | LifecyclePhase::CleanupOwnersDurable
                    | LifecyclePhase::ServerStopped
            ) {
                let old_epoch = record.operation_owner.epoch;
                record.operation_owner.epoch = old_epoch
                    .checked_add(1)
                    .ok_or_else(|| "operation owner epoch overflow".to_string())?;
                record.operation_owner.revoked_epoch = Some(old_epoch);
                record.phase = LifecyclePhase::CleanupRequired;
            }
            Ok(())
        })?;
        if record.phase != LifecyclePhase::Done {
            atomic_write_bytes(&self.directory.join(CLEANUP_REASON_FILE), reason.as_bytes())?;
        }
        Ok(())
    }

    pub(crate) async fn request_cleanup_and_wait(&self, reason: &str) -> Result<(), String> {
        self.request_cleanup(reason)?;
        self.wait_for_phase_at_least(LifecyclePhase::Done, Duration::from_secs(45))
            .await
    }

    async fn wait_for_phase_at_least(
        &self,
        target: LifecyclePhase,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let phase = match self.read_record() {
                Ok(record) => record.phase,
                Err(_error)
                    if target == LifecyclePhase::Done
                        && !self.directory.join(RECORD_FILE).exists() =>
                {
                    return Ok(())
                }
                Err(error) => return Err(error),
            };
            if phase_rank(phase) >= phase_rank(target) {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for lifecycle phase {target:?}; current={phase:?}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn controller_targets(ceiling: &HostResourceCeiling) -> [(&'static str, String); 4] {
    [
        ("memory.oom.group", ceiling.memory_oom_group.clone()),
        ("pids.max", ceiling.pids_max.clone()),
        ("memory.max", ceiling.memory_max.clone()),
        ("cpu.max", ceiling.cpu_max.clone()),
    ]
}

fn host_leaf_path(target: &HostTarget) -> Result<PathBuf, String> {
    if !target.managed() || target.leaf_identity().is_none() {
        return Err("managed Host target has no committed leaf identity".to_string());
    }
    verify_live_target_identity(target)?;
    Ok(Path::new("/sys/fs/cgroup").join(target.cgroup().trim_start_matches('/')))
}

fn verify_controller_record(record: &LifecycleRecord) -> Result<(), String> {
    if record.classification != Classification::ManagedSandbox
        || record.phase != LifecyclePhase::ContainerdCommitted
        || record.create_state != CreateState::InProgress
        || record.operation_owner.kind != OwnerKind::Server
        || record.operation_owner.revoked_epoch.is_some()
    {
        return Err(format!(
            "Host controller mutation requires an unfenced committed managed Create; found {:?}/{:?}/{:?}/{:?}/revoked={:?}",
            record.classification,
            record.phase,
            record.create_state,
            record.operation_owner.kind,
            record.operation_owner.revoked_epoch
        ));
    }
    Ok(())
}

fn verify_controller_claim(
    record: &LifecycleRecord,
    epoch: u64,
    identity: &ProcessIdentity,
    target: &HostTarget,
) -> Result<(), String> {
    verify_controller_record(record)?;
    if record.operation_owner.epoch != epoch
        || !immutable_identity_matches(&record.operation_owner.identity, identity)
        || record.target != *target
    {
        return Err("Host controller operation owner was revoked or changed".to_string());
    }
    let actual = process_identity_for_expected(identity)?;
    if !immutable_identity_matches(identity, &actual) || actual.cgroup != target.cgroup() {
        return Err(
            "Host controller operation process identity or containment changed".to_string(),
        );
    }
    verify_target_membership(target, actual.pid)
}

fn verify_host_owner_for_record(
    owner: &HostCgroupOwner,
    record: &LifecycleRecord,
) -> Result<(), String> {
    if owner.schema_version != SCHEMA_VERSION
        || owner.generation != record.generation
        || owner.namespace != record.namespace
        || owner.instance_id != record.instance_id
        || owner.state != HostOwnerState::Allocated
        || owner.target != record.target
        || owner.original_cgroup != record.helper.cgroup
        || owner.server.as_ref().is_none_or(|server| {
            record
                .server
                .as_ref()
                .is_none_or(|registered| !immutable_identity_matches(server, registered))
        })
    {
        return Err("Host owner does not match committed lifecycle identity".to_string());
    }
    Ok(())
}

fn verify_controller_journal_owner(
    journal: &ControllerJournal,
    epoch: u64,
    identity: &ProcessIdentity,
    fingerprint: &str,
) -> Result<(), String> {
    if journal.schema_version != 1
        || journal.transaction_id.is_empty()
        || journal.owner_epoch != epoch
        || !immutable_identity_matches(&journal.owner_identity, identity)
        || journal.create_fingerprint != fingerprint
        || journal.steps.len() != 4
        || journal.steps.iter().map(|step| step.file.as_str()).ne([
            "memory.oom.group",
            "pids.max",
            "memory.max",
            "cpu.max",
        ])
    {
        return Err("Host controller journal identity or fixed step order changed".to_string());
    }
    Ok(())
}

fn verify_controller_journal_identity(
    journal: &ControllerJournal,
    epoch: u64,
    identity: &ProcessIdentity,
    fingerprint: &str,
    targets: &[(&str, String); 4],
) -> Result<(), String> {
    verify_controller_journal_owner(journal, epoch, identity, fingerprint)?;
    if journal
        .steps
        .iter()
        .zip(targets)
        .any(|(step, (file, target))| step.file != *file || step.target != *target)
    {
        return Err("Host controller retry target differs from durable journal".to_string());
    }
    Ok(())
}

fn persist_host_owner_exact(directory: &Path, owner: &HostCgroupOwner) -> Result<(), String> {
    let path = directory.join(HOST_OWNER_FILE);
    match atomic_write_json(&path, owner) {
        Ok(()) => Ok(()),
        Err(error) => {
            let durable: HostCgroupOwner = read_json(&path)?;
            if durable == *owner {
                sync_directory(directory)
            } else {
                Err(error)
            }
        }
    }
}

fn canonical_controller_value(file: &str, raw: &str) -> Result<String, String> {
    let fields: Vec<_> = raw.split_whitespace().collect();
    match file {
        "cpu.max" => {
            if fields.len() != 2 {
                return Err(format!("cpu.max must contain quota and period: {raw:?}"));
            }
            if fields[0] != "max" {
                fields[0]
                    .parse::<u64>()
                    .map_err(|error| format!("parse cpu.max quota {}: {error}", fields[0]))?;
            }
            let period = fields[1]
                .parse::<u64>()
                .map_err(|error| format!("parse cpu.max period {}: {error}", fields[1]))?;
            if period == 0 {
                return Err("cpu.max period must be non-zero".to_string());
            }
            Ok(format!("{} {}", fields[0], fields[1]))
        }
        "memory.max" => {
            if fields.len() != 1 {
                return Err(format!("{file} must contain one value: {raw:?}"));
            }
            if fields[0] != "max" {
                fields[0]
                    .parse::<u64>()
                    .map_err(|error| format!("parse {file} value {}: {error}", fields[0]))?;
            }
            Ok(fields[0].to_string())
        }
        "pids.max" => {
            if fields.len() != 1 {
                return Err(format!("{file} must contain one value: {raw:?}"));
            }
            if fields[0] == "max" {
                return Ok(fields[0].to_string());
            }
            let value = fields[0]
                .parse::<u64>()
                .map_err(|error| format!("parse {file} value {}: {error}", fields[0]))?;
            if value > runtime_resource::LINUX_PIDS_MAX_LIMIT {
                return Err(format!(
                    "pids.max {value} exceeds Linux numeric limit {}",
                    runtime_resource::LINUX_PIDS_MAX_LIMIT
                ));
            }
            Ok(fields[0].to_string())
        }
        "memory.oom.group" => {
            if fields.len() != 1 || !matches!(fields[0], "0" | "1") {
                return Err(format!("memory.oom.group must be 0 or 1: {raw:?}"));
            }
            Ok(fields[0].to_string())
        }
        _ => Err(format!("unsupported Host controller file {file}")),
    }
}

fn read_controller_value(leaf: &Path, file: &str) -> Result<String, String> {
    let path = leaf.join(file);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("stat Host controller {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "Host controller is not a regular cgroup file: {}",
            path.display()
        ));
    }
    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("read Host controller {}: {error}", path.display()))?;
    canonical_controller_value(file, &raw)
}

fn write_controller_value(leaf: &Path, file: &str, value: &str) -> Result<(), String> {
    let canonical = canonical_controller_value(file, value)?;
    let path = leaf.join(file);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("stat Host controller {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "Host controller is not a regular cgroup file: {}",
            path.display()
        ));
    }
    fs::write(&path, canonical.as_bytes())
        .map_err(|error| format!("write Host controller {}: {error}", path.display()))
}

fn preflight_controller_targets(leaf: &Path, steps: &[ControllerStep]) -> Result<(), String> {
    if steps.len() != 4 {
        return Err("Host controller transaction requires four fixed steps".to_string());
    }
    for step in steps {
        canonical_controller_value(&step.file, &step.old)?;
        canonical_controller_value(&step.file, &step.target)?;
    }
    let pids_target = steps[1]
        .target
        .parse::<u64>()
        .map_err(|error| format!("parse Host pids target: {error}"))?;
    let pids_current = fs::read_to_string(leaf.join("pids.current"))
        .map_err(|error| format!("read Host pids.current: {error}"))?
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("parse Host pids.current: {error}"))?;
    if pids_current > pids_target {
        return Err(format!(
            "Host pids.current {pids_current} exceeds target {pids_target}"
        ));
    }
    let memory_target = steps[2]
        .target
        .parse::<u64>()
        .map_err(|error| format!("parse Host memory target: {error}"))?;
    let memory_current = fs::read_to_string(leaf.join("memory.current"))
        .map_err(|error| format!("read Host memory.current: {error}"))?
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("parse Host memory.current: {error}"))?;
    if memory_current > memory_target {
        return Err(format!(
            "Host memory.current {memory_current} exceeds target {memory_target}"
        ));
    }
    Ok(())
}

fn exact_controller_readback(
    leaf: &Path,
    journal: &ControllerJournal,
    target: bool,
) -> Result<(), String> {
    for step in &journal.steps {
        let expected = if target { &step.target } else { &step.old };
        let actual = read_controller_value(leaf, &step.file)?;
        if &actual != expected {
            return Err(format!(
                "Host controller {} readback mismatch: expected {expected}, found {actual}",
                step.file
            ));
        }
    }
    Ok(())
}

fn mark_controller_degraded(journal: &mut ControllerJournal, reason: &str) {
    journal.state = ControllerTransactionState::Degraded;
    journal.degraded_reason = Some(reason.to_string());
}

fn clear_restored_controller_journal(
    leaf: &Path,
    journal: &mut Option<ControllerJournal>,
) -> Result<(), String> {
    let Some(restored) = journal.as_ref() else {
        return Ok(());
    };
    if restored.state != ControllerTransactionState::Restored {
        return Err(format!(
            "Host controller journal removal requires RESTORED, found {:?}",
            restored.state
        ));
    }
    exact_controller_readback(leaf, restored, false)?;
    *journal = None;
    Ok(())
}

fn replay_controller_forward_state<Load, Persist, Verify, Failpoint>(
    leaf: &Path,
    mut load: Load,
    mut persist: Persist,
    mut verify_claim: Verify,
    mut failpoint: Failpoint,
) -> Result<(), String>
where
    Load: FnMut() -> Result<ControllerJournal, String>,
    Persist: FnMut(&ControllerJournal) -> Result<(), String>,
    Verify: FnMut() -> Result<(), String>,
    Failpoint: FnMut(&str) -> Result<(), String>,
{
    loop {
        let mut journal = load()?;
        if journal.state == ControllerTransactionState::ControllersCommitted {
            exact_controller_readback(leaf, &journal, true)?;
            return Ok(());
        }
        if matches!(
            journal.state,
            ControllerTransactionState::RollingBack
                | ControllerTransactionState::Restored
                | ControllerTransactionState::Degraded
                | ControllerTransactionState::AbandonedForExactDelete
        ) {
            return Err(format!(
                "Host controller transaction cannot move forward from {:?}",
                journal.state
            ));
        }
        let Some(index) = journal
            .steps
            .iter()
            .position(|step| step.state != ControllerStepState::Applied)
        else {
            journal.state = ControllerTransactionState::ControllersCommitted;
            persist(&journal)?;
            continue;
        };
        let actual = read_controller_value(leaf, &journal.steps[index].file)?;
        let step = &mut journal.steps[index];
        let next = match step.state {
            ControllerStepState::NotStarted => {
                if actual != step.old && actual != step.target {
                    let reason = format!(
                        "controller {} is neither old {} nor target {}: {actual}",
                        step.file, step.old, step.target
                    );
                    mark_controller_degraded(&mut journal, &reason);
                    persist(&journal)?;
                    return Err(reason);
                }
                step.state = ControllerStepState::Intent;
                step.observed = Some(actual);
                journal.state = ControllerTransactionState::Applying;
                let result = (index, step.file.clone(), step.target.clone());
                persist(&journal)?;
                result
            }
            ControllerStepState::Intent => {
                if actual == step.target {
                    step.state = ControllerStepState::Applied;
                    step.observed = Some(actual);
                    persist(&journal)?;
                    continue;
                }
                if actual != step.old {
                    let reason = format!(
                        "controller {} INTENT readback is neither old {} nor target {}: {actual}",
                        step.file, step.old, step.target
                    );
                    mark_controller_degraded(&mut journal, &reason);
                    persist(&journal)?;
                    return Err(reason);
                }
                (index, step.file.clone(), step.target.clone())
            }
            state => {
                return Err(format!(
                    "controller {} has invalid forward state {state:?}",
                    step.file
                ));
            }
        };

        failpoint(&format!("before-write-{}", next.1))?;
        verify_claim()?;
        write_controller_value(leaf, &next.1, &next.2)?;
        failpoint(&format!("after-write-{}", next.1))?;
        failpoint(&format!("before-readback-{}", next.1))?;
        let observed = read_controller_value(leaf, &next.1)?;
        if observed != next.2 {
            return Err(format!(
                "controller {} target readback mismatch: expected {}, found {observed}",
                next.1, next.2
            ));
        }
        failpoint(&format!("after-readback-{}", next.1))?;
        let mut journal = load()?;
        let step = journal
            .steps
            .get_mut(next.0)
            .ok_or_else(|| "Host controller step index changed".to_string())?;
        if step.file != next.1 || step.target != next.2 || step.state != ControllerStepState::Intent
        {
            return Err("Host controller INTENT changed during write".to_string());
        }
        step.state = ControllerStepState::Applied;
        step.observed = Some(observed);
        persist(&journal)?;
        failpoint(&format!("after-applied-{}", next.1))?;
    }
}

fn replay_controller_rollback<Load, Persist>(
    leaf: &Path,
    load: Load,
    persist: Persist,
) -> Result<(), String>
where
    Load: FnMut() -> Result<ControllerJournal, String>,
    Persist: FnMut(&ControllerJournal) -> Result<(), String>,
{
    replay_controller_rollback_with_failpoint(leaf, load, persist, || Ok(()), |_| Ok(()))
}

fn replay_controller_rollback_with_failpoint<Load, Persist, Verify, Failpoint>(
    leaf: &Path,
    mut load: Load,
    mut persist: Persist,
    mut verify_claim: Verify,
    mut failpoint: Failpoint,
) -> Result<(), String>
where
    Load: FnMut() -> Result<ControllerJournal, String>,
    Persist: FnMut(&ControllerJournal) -> Result<(), String>,
    Verify: FnMut() -> Result<(), String>,
    Failpoint: FnMut(&str) -> Result<(), String>,
{
    loop {
        let mut journal = load()?;
        if journal.state == ControllerTransactionState::Restored {
            exact_controller_readback(leaf, &journal, false)?;
            return Ok(());
        }
        if matches!(
            journal.state,
            ControllerTransactionState::Degraded
                | ControllerTransactionState::AbandonedForExactDelete
        ) {
            return Err(format!(
                "Host controller rollback cannot continue from {:?}: {}",
                journal.state,
                journal.degraded_reason.as_deref().unwrap_or("no reason")
            ));
        }
        if journal.state != ControllerTransactionState::RollingBack {
            journal.state = ControllerTransactionState::RollingBack;
            persist(&journal)?;
            continue;
        }
        let Some(index) = journal
            .steps
            .iter()
            .rposition(|step| step.state != ControllerStepState::Restored)
        else {
            journal.state = ControllerTransactionState::Restored;
            persist(&journal)?;
            continue;
        };
        let actual = read_controller_value(leaf, &journal.steps[index].file)?;
        let step = &mut journal.steps[index];
        match step.state {
            ControllerStepState::NotStarted => {
                if actual != step.old {
                    let reason = format!(
                        "unstarted controller {} changed from old {} to {actual}",
                        step.file, step.old
                    );
                    mark_controller_degraded(&mut journal, &reason);
                    persist(&journal)?;
                    return Err(reason);
                }
                step.state = ControllerStepState::Restored;
                step.observed = Some(actual);
                persist(&journal)?;
            }
            ControllerStepState::Intent
            | ControllerStepState::Applied
            | ControllerStepState::UndoIntent => {
                if actual == step.old {
                    step.state = ControllerStepState::Restored;
                    step.observed = Some(actual);
                    persist(&journal)?;
                    continue;
                }
                if actual != step.target {
                    let reason = format!(
                        "controller {} rollback readback is neither old {} nor target {}: {actual}",
                        step.file, step.old, step.target
                    );
                    mark_controller_degraded(&mut journal, &reason);
                    persist(&journal)?;
                    return Err(reason);
                }
                step.state = ControllerStepState::UndoIntent;
                step.observed = Some(actual);
                let file = step.file.clone();
                let old = step.old.clone();
                persist(&journal)?;
                failpoint(&format!("before-rollback-write-{file}"))?;
                verify_claim()?;
                write_controller_value(leaf, &file, &old)?;
                failpoint(&format!("after-rollback-write-{file}"))?;
                failpoint(&format!("before-rollback-readback-{file}"))?;
                let restored = read_controller_value(leaf, &file)?;
                if restored != old {
                    let reason = format!(
                        "controller {} rollback readback mismatch: expected {}, found {restored}",
                        file, old
                    );
                    mark_controller_degraded(&mut journal, &reason);
                    persist(&journal)?;
                    return Err(reason);
                }
                failpoint(&format!("after-rollback-readback-{file}"))?;
                journal.steps[index].state = ControllerStepState::Restored;
                journal.steps[index].observed = Some(restored);
                persist(&journal)?;
            }
            ControllerStepState::Restored => {}
        }
    }
}

#[cfg(test)]
fn controller_test_failpoint(directory: &Path, name: &str) -> Result<(), String> {
    if fs::remove_file(directory.join(format!(".controller.fail-{name}"))).is_ok() {
        Err(format!("injected Host controller failure at {name}"))
    } else {
        Ok(())
    }
}

#[cfg(not(test))]
fn controller_test_failpoint(directory: &Path, name: &str) -> Result<(), String> {
    let Ok(root) = std::env::var("CUBE_SHIM_TEST_FAILPOINT_DIR") else {
        return Ok(());
    };
    let record: LifecycleRecord = read_json(&directory.join(RECORD_FILE))?;
    let root = PathBuf::from(root);
    ensure_directory(&root)?;
    let reached = root.join(format!("controller-{name}-{}.reached", record.instance_id));
    let release = root.join(format!("controller-{name}-{}.release", record.instance_id));
    atomic_write_bytes(&reached, b"reached\n")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while !release.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

pub(crate) struct BootstrapSession {
    handle: LifecycleHandle,
    nonce: Vec<u8>,
    target: HostTarget,
    original_cgroup: String,
    gate_read: Option<OwnedFd>,
    gate_write: Option<OwnedFd>,
    helper_moved: bool,
}

impl BootstrapSession {
    pub(crate) fn prepare(
        params: &BootstrapParams,
        bundle: &Path,
        address: &str,
        executable: &Path,
        debug: bool,
    ) -> Result<Self, String> {
        let original_cgroup = current_process_cgroup(std::process::id() as i32)?;
        // A containerd Sandbox bundle deliberately has no OCI config.json at
        // bootstrap time.  Persist an unclassified lifecycle and let the
        // first identity-bound CreateSandbox/CreateTask RPC claim its kind.
        let classification = Classification::Pending;
        let target = HostTarget::Pending {
            original_cgroup: original_cgroup.clone(),
        };
        verify_watchdog_service()?;
        let nonce = random_nonce()?;
        let root = lifecycle_root()?;
        let handle = LifecycleHandle::create(
            &root,
            params,
            bundle,
            classification,
            target.clone(),
            address,
            &nonce,
            executable,
            debug,
        )?;
        let (gate_read, gate_write) = create_gate()?;
        Ok(Self {
            handle,
            nonce,
            target,
            original_cgroup,
            gate_read: Some(gate_read),
            gate_write: Some(gate_write),
            helper_moved: false,
        })
    }

    pub(crate) fn place_helper(&mut self) -> Result<(), String> {
        if self.target.managed() {
            let operation = self.handle.begin_helper_host_operation()?;
            if let Err(error) =
                create_and_join_target(&self.target, std::process::id() as i32, None)
            {
                self.helper_moved = current_process_cgroup(std::process::id() as i32)
                    .map(|actual| actual == self.target.cgroup())
                    .unwrap_or(false);
                return Err(error);
            }
            self.helper_moved = true;
            let cgroup_path =
                Path::new("/sys/fs/cgroup").join(self.target.cgroup().trim_start_matches('/'));
            let identity = file_identity(&cgroup_path)?;
            self.target.set_leaf_identity(identity.clone());
            self.handle.persist_leaf_identity(identity)?;
            operation.verify()?;
            verify_target_membership(&self.target, std::process::id() as i32)?;
        }
        Ok(())
    }

    pub(crate) fn configure_child(
        &self,
        command: &mut tokio::process::Command,
    ) -> Result<(), String> {
        let gate = self
            .gate_read
            .as_ref()
            .ok_or_else(|| "bootstrap gate read side is unavailable".to_string())?;
        command
            .env(LIFECYCLE_DIR_ENV, &self.handle.directory)
            .env(GATE_FD_ENV, gate.as_raw_fd().to_string())
            .env(LAUNCH_NONCE_ENV, bytes_hex(&self.nonce));
        Ok(())
    }

    pub(crate) fn child_spawned(&mut self) {
        self.gate_read.take();
    }

    pub(crate) fn register_spawned_server(&self, pid: i32) -> Result<(), String> {
        self.handle.register_spawned_server(pid, &self.nonce)
    }

    pub(crate) async fn wait_server_identity(&self, pid: i32) -> Result<(), String> {
        for _ in 0..200 {
            let record = self.handle.read_record()?;
            if let Some(server) = record.server {
                if server.pid != pid {
                    return Err(format!(
                        "registered server pid {} does not match spawned {pid}",
                        server.pid
                    ));
                }
                verify_target_membership(&self.target, pid)?;
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(format!("timed out waiting for server {pid} identity"))
    }

    pub(crate) fn release_gate(&mut self) -> Result<(), String> {
        verify_target_membership(&self.target, std::process::id() as i32)?;
        let gate = self
            .gate_write
            .take()
            .ok_or_else(|| "bootstrap gate is already released".to_string())?;
        let mut file = File::from(gate);
        file.write_all(&[1])
            .and_then(|_| file.flush())
            .map_err(|error| format!("release server bootstrap gate: {error}"))
    }

    pub(crate) fn restore_helper(&mut self) -> Result<(), String> {
        if self.helper_moved {
            move_process_to(&self.original_cgroup, std::process::id() as i32)?;
            if current_process_cgroup(std::process::id() as i32)? != self.original_cgroup {
                return Err("helper cgroup restore readback mismatch".to_string());
            }
            self.helper_moved = false;
        }
        Ok(())
    }

    pub(crate) async fn abort(&mut self, reason: &str) -> Result<(), String> {
        let mut errors = Vec::new();
        if let Err(error) = self.handle.request_cleanup(reason) {
            errors.push(error);
        }
        if let Err(error) = self
            .handle
            .wait_for_phase_at_least(
                LifecyclePhase::CleanupOwnersDurable,
                Duration::from_secs(10),
            )
            .await
        {
            errors.push(error);
        }
        if let Err(error) = self.restore_helper() {
            errors.push(error);
        }
        if let Err(error) = self
            .handle
            .wait_for_phase_at_least(LifecyclePhase::Done, Duration::from_secs(30))
            .await
        {
            errors.push(error);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for BootstrapSession {
    fn drop(&mut self) {
        if self.helper_moved {
            let _ = move_process_to(&self.original_cgroup, std::process::id() as i32);
        }
    }
}

pub(crate) fn early_server_gate() -> Result<(), String> {
    let Some(directory) = std::env::var_os(LIFECYCLE_DIR_ENV) else {
        return Ok(());
    };
    let nonce_hex = std::env::var(LAUNCH_NONCE_ENV)
        .map_err(|error| format!("read {LAUNCH_NONCE_ENV}: {error}"))?;
    let nonce = decode_hex(&nonce_hex)?;
    let fd: RawFd = std::env::var(GATE_FD_ENV)
        .map_err(|error| format!("read {GATE_FD_ENV}: {error}"))?
        .parse()
        .map_err(|error| format!("parse {GATE_FD_ENV}: {error}"))?;
    if fd < 3 {
        return Err(format!("invalid bootstrap gate fd {fd}"));
    }
    let handle = LifecycleHandle {
        directory: PathBuf::from(directory),
    };
    handle.register_server(&nonce)?;
    // SAFETY: this process inherited ownership of the read side from the
    // bootstrap helper and converts it exactly once.
    let mut gate = unsafe { File::from_raw_fd(fd) };
    let mut byte = [0_u8; 1];
    gate.read_exact(&mut byte)
        .map_err(|error| format!("wait for bootstrap gate: {error}"))?;
    if byte != [1] {
        return Err("bootstrap gate returned an invalid token".to_string());
    }
    let record = handle.read_record()?;
    verify_target_membership(&record.target, std::process::id() as i32)
}

pub(crate) fn lifecycle_from_env() -> Result<Option<LifecycleHandle>, String> {
    LifecycleHandle::from_env()
}

pub(crate) fn lifecycle_for_bundle(
    namespace: &str,
    instance_id: &str,
    bundle: &Path,
) -> Result<Option<LifecycleHandle>, String> {
    let root = lifecycle_root()?;
    let bundle = match fs::canonicalize(bundle) {
        Ok(bundle) => bundle,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("canonicalize lifecycle bundle: {error}")),
    };
    let identity = file_identity(&bundle)?;
    let directory = root.join(lifecycle_key(namespace, instance_id, &bundle, &identity));
    if !directory.exists() {
        return Ok(None);
    }
    let handle = LifecycleHandle { directory };
    let record = handle.read_record()?;
    if record.namespace != namespace
        || record.instance_id != instance_id
        || record.bundle_identity != identity
    {
        return Err("lifecycle lookup identity mismatch".to_string());
    }
    Ok(Some(handle))
}

pub(crate) async fn run_watchdog() -> Result<(), String> {
    let root = lifecycle_root()?;
    ensure_directory(&root)?;
    let queue = cleanup_queue_root()?;
    ensure_directory(&queue.join(HOST_QUEUE_DIRECTORY))?;
    ensure_directory(&queue.join(RUNTIME_QUEUE_DIRECTORY))?;
    let lifecycle_worker = async {
        loop {
            if let Err(error) = scan_lifecycle_root(&root, &queue).await {
                eprintln!("CubeShim lifecycle watchdog scan failed: {error}");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    let host_worker = async {
        loop {
            if let Err(error) = scan_host_cleanup_queue_once(&queue).await {
                eprintln!("CubeShim Host cleanup queue scan failed: {error}");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    let runtime_worker = async {
        loop {
            if let Err(error) = scan_runtime_cleanup_queue_once(&queue).await {
                eprintln!("CubeShim RuntimeResource cleanup queue scan failed: {error}");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    let legacy_reaper_worker = async {
        loop {
            if let Err(error) = runtime_resource::scan_persisted_reapers_once().await {
                eprintln!("CubeShim legacy RuntimeResource reaper scan failed: {error}");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    tokio::join!(
        lifecycle_worker,
        host_worker,
        runtime_worker,
        legacy_reaper_worker
    );
    #[allow(unreachable_code)]
    Ok(())
}

pub(crate) fn run_systemd_probe() -> Result<(), String> {
    let parent_path = Path::new("/sys/fs/cgroup/system.slice");
    let parent_identity = file_identity(parent_path)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| format!("read boot id for systemd probe: {error}"))?;
    for iteration in 0..200_u32 {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .map_err(|error| format!("spawn systemd probe member: {error}"))?;
        let unit = format!("cubesandbox-cgroup-probe-{}-{iteration}.scope", boot.trim());
        let cgroup = format!("/system.slice/{unit}");
        let target = HostTarget::Systemd {
            oci_path: format!("system.slice:cubesandbox-cgroup-probe:{iteration}"),
            slice: "system.slice".to_string(),
            unit: unit.clone(),
            cgroup: cgroup.clone(),
            parent_identity: parent_identity.clone(),
            leaf_identity: None,
        };
        let pid = child.id() as i32;
        if let Err(error) = create_and_join_target(&target, pid, None) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("systemd probe iteration {iteration}: {error}"));
        }
        let identity = match file_identity(
            &Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/')),
        ) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("systemd probe iteration {iteration}: {error}"));
            }
        };
        let mut target = target;
        target.set_leaf_identity(identity);
        if let Err(error) = verify_target_membership(&target, pid) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("systemd probe iteration {iteration}: {error}"));
        }
        child
            .kill()
            .map_err(|error| format!("terminate systemd probe member {pid}: {error}"))?;
        child
            .wait()
            .map_err(|error| format!("wait for systemd probe member {pid}: {error}"))?;
        let path = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
        for _ in 0..500 {
            if !path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if path.exists() {
            return Err(format!(
                "systemd probe scope was not collected at iteration {iteration}: {}",
                path.display()
            ));
        }
        for _ in 0..500 {
            if systemd_unit_absent(&unit)? {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !systemd_unit_absent(&unit)? {
            return Err(format!(
                "systemd probe unit was not collected at iteration {iteration}: {unit}"
            ));
        }
    }
    println!(
        "systemd_scope_probe iterations=200 failures=0 left_units=0 left_cgroups=0 cleanup=exact"
    );
    let binary = fs::canonicalize("/proc/self/exe")
        .map_err(|error| format!("resolve systemd probe executable: {error}"))?;
    if binary != Path::new(WATCHDOG_BINARY) {
        return Err(format!(
            "systemd probe executable {} does not match installed path {WATCHDOG_BINARY}",
            binary.display()
        ));
    }
    ensure_directory(Path::new(WATCHDOG_PROBE_STAMP).parent().unwrap())?;
    atomic_write_json(
        Path::new(WATCHDOG_PROBE_STAMP),
        &WatchdogProbeStamp {
            schema_version: SCHEMA_VERSION,
            boot_id: boot.trim().to_string(),
            binary_path: binary.display().to_string(),
            binary_identity: file_identity(&binary)?,
            binary_sha256: sha256_file(&binary)?,
            iterations: 200,
            completed_at_ms: unix_time_ms()?,
        },
    )?;
    Ok(())
}

fn systemd_unit_absent(unit: &str) -> Result<bool, String> {
    let output = Command::new("systemctl")
        .args(["show", unit, "--property=LoadState", "--value"])
        .output()
        .map_err(|error| format!("query systemd unit collection {unit}: {error}"))?;
    systemd_unit_absent_from_output(
        unit,
        output.status.success(),
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    )
}

fn systemd_unit_absent_from_output(
    unit: &str,
    success: bool,
    stdout: &str,
    stderr: &str,
) -> Result<bool, String> {
    // systemctl versions disagree on the exit status for a collected unit:
    // some return non-zero while still printing the authoritative LoadState
    // value on stdout.  Classify that value before considering the status.
    if stdout.trim() == "not-found" {
        return Ok(true);
    }
    if success {
        return Ok(false);
    }
    if stderr.contains("could not be found") || stderr.contains("not found") {
        return Ok(true);
    }
    Err(format!(
        "query systemd unit collection {unit}: {}",
        stderr.trim()
    ))
}

async fn scan_lifecycle_root(root: &Path, queue: &Path) -> Result<(), String> {
    let mut errors = Vec::new();
    let entries = fs::read_dir(root)
        .map_err(|error| format!("scan lifecycle root {}: {error}", root.display()))?;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!("read lifecycle entry: {error}"));
                continue;
            }
        };
        let path = entry.path();
        if entry.file_name() == OsStr::new(SOCKET_LOCK_DIRECTORY) {
            continue;
        }
        if !entry
            .file_type()
            .map(|value| value.is_dir())
            .unwrap_or(false)
        {
            continue;
        }
        let handle = LifecycleHandle { directory: path };
        if let Err(error) = scan_lifecycle(&handle, queue).await {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn scan_host_cleanup_queue_once(queue: &Path) -> Result<(), String> {
    scan_host_cleanup_queue_once_with(queue, |job| {
        let socket_result = cleanup_socket_identity(
            &job.socket,
            job.created_at_ms,
            &job.owner.generation,
            Path::new(&job.lifecycle_root),
        );
        let host_result = match job.owner.state {
            HostOwnerState::Empty => Ok(()),
            HostOwnerState::Intent | HostOwnerState::Allocated => {
                cleanup_host_target(&job.owner.target)
            }
        };
        match (socket_result, host_result) {
            (Ok(()), Ok(())) => Ok(()),
            (socket, host) => {
                let mut errors = Vec::new();
                if let Err(error) = socket {
                    errors.push(format!("Host queue socket cleanup: {error}"));
                }
                if let Err(error) = host {
                    errors.push(format!("Host queue cgroup cleanup: {error}"));
                }
                Err(errors.join("; "))
            }
        }
    })
    .await
}

async fn scan_host_cleanup_queue_once_with<F>(queue: &Path, mut cleanup: F) -> Result<(), String>
where
    F: FnMut(&HostCleanupJob) -> Result<(), String>,
{
    let directory = queue.join(HOST_QUEUE_DIRECTORY);
    let mut errors = Vec::new();
    for entry in fs::read_dir(&directory)
        .map_err(|error| format!("scan Host cleanup queue {}: {error}", directory.display()))?
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!("read Host cleanup queue entry: {error}"));
                continue;
            }
        };
        if !entry
            .file_type()
            .map(|kind| kind.is_file())
            .unwrap_or(false)
        {
            continue;
        }
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let mut job: HostCleanupJob = match read_json(&entry.path()) {
            Ok(job) => job,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        let generation = job.owner.generation.clone();
        if job.owner.schema_version != SCHEMA_VERSION
            || generation.is_empty()
            || !Path::new(&job.socket.path).is_absolute()
            || !Path::new(&job.lifecycle_root).is_absolute()
        {
            errors.push(format!(
                "Host cleanup job has invalid durable identity: {}",
                entry.path().display()
            ));
            continue;
        }
        if entry.file_name() != OsStr::new(&format!("{generation}.json")) {
            errors.push(format!(
                "Host cleanup queue filename/generation mismatch: {}",
                entry.path().display()
            ));
            continue;
        }
        if !job.ready_for_cleanup {
            continue;
        }
        if let Err(error) = reconcile_cleanup_controllers(&entry.path(), &mut job) {
            errors.push(format!("Host queue controller cleanup: {error}"));
            continue;
        }
        match cleanup(&job) {
            Ok(()) => {
                if let Err(error) = acknowledge_queue(queue, HOST_QUEUE_DIRECTORY, &generation) {
                    errors.push(error);
                }
            }
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn scan_runtime_cleanup_queue_once(queue: &Path) -> Result<(), String> {
    scan_runtime_cleanup_queue_once_with(queue, |owner| async move {
        runtime_resource::release_external_owner(&owner).await?;
        cleanup_runtime_owner_local_resources(&owner)
    })
    .await
}

fn cleanup_runtime_owner_local_resources(owner: &RuntimeResourceOwner) -> Result<(), String> {
    let Some(sandbox_id) = owner.sandbox_id.as_ref() else {
        return Ok(());
    };
    // SandBox::init creates /run/vc/vm/<sandbox-id> before StartSandbox. A
    // CubeShim crash before the VMM worker is spawned cannot run delete_shim,
    // so the durable RuntimeResource cleanup consumer must own this local,
    // idempotent cleanup too. The job is acknowledged only after it succeeds.
    Utils::clean_sandbox_resource(sandbox_id)
}

async fn scan_runtime_cleanup_queue_once_with<F, Fut>(
    queue: &Path,
    mut release: F,
) -> Result<(), String>
where
    F: FnMut(RuntimeResourceOwner) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let directory = queue.join(RUNTIME_QUEUE_DIRECTORY);
    let mut errors = Vec::new();
    for entry in fs::read_dir(&directory).map_err(|error| {
        format!(
            "scan RuntimeResource cleanup queue {}: {error}",
            directory.display()
        )
    })? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!("read RuntimeResource cleanup queue entry: {error}"));
                continue;
            }
        };
        if !entry
            .file_type()
            .map(|kind| kind.is_file())
            .unwrap_or(false)
        {
            continue;
        }
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let job: RuntimeCleanupJob = match read_json(&entry.path()) {
            Ok(job) => job,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        let generation = job.owner.generation_id.clone();
        if job.owner.schema_version != SCHEMA_VERSION || generation.is_empty() {
            errors.push(format!(
                "RuntimeResource cleanup job has invalid durable identity: {}",
                entry.path().display()
            ));
            continue;
        }
        if entry.file_name() != OsStr::new(&format!("{generation}.json")) {
            errors.push(format!(
                "RuntimeResource cleanup queue filename/generation mismatch: {}",
                entry.path().display()
            ));
            continue;
        }
        if !job.ready_for_cleanup {
            continue;
        }
        match release(job.owner.clone()).await {
            Ok(()) => {
                if let Err(error) = acknowledge_queue(queue, RUNTIME_QUEUE_DIRECTORY, &generation) {
                    errors.push(error);
                }
            }
            Err(error) => errors.push(format!("RuntimeResource queue cleanup: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn same_scanner_snapshot(snapshot: &LifecycleRecord, current: &LifecycleRecord) -> bool {
    snapshot.generation == current.generation
        && snapshot.sequence == current.sequence
        && snapshot.phase == current.phase
}

fn create_failure_cleanup_ready(record: &LifecycleRecord) -> Result<bool, String> {
    let failure = record
        .failure
        .as_ref()
        .ok_or_else(|| "FAILED Create has no durable failure result".to_string())?;
    Ok(failure.drained || unix_time_ms()?.saturating_sub(failure.published_at_ms) >= 30_000)
}

async fn scan_lifecycle(handle: &LifecycleHandle, queue: &Path) -> Result<(), String> {
    let mut record = match handle.read_record() {
        Ok(record) => record,
        Err(_error) if !handle.directory.join(RECORD_FILE).exists() => {
            return cleanup_interrupted_constructor(handle)
        }
        Err(error) => return Err(error),
    };
    if record.phase == LifecyclePhase::Done {
        return remove_done_lifecycle(handle);
    }
    if record.phase == LifecyclePhase::Prepared && record.server.is_none() {
        if adopt_unregistered_server(handle, &record)? {
            record = handle.read_record()?;
        }
    }

    let helper_alive = immutable_process_is_live(&record.helper)?;
    let server_observation = record.server.as_ref().map(observe_process).transpose()?;
    let worker_observation = observe_allocated_vmm_worker(&record)?;
    let now = unix_time_ms()?;
    let precommit_expired = now.saturating_sub(record.created_at_ms) >= PRECOMMIT_GRACE.as_millis();
    let takeover_expired = record
        .takeover_claimed_at_ms
        .is_some_and(|claimed| now.saturating_sub(claimed) >= PRECOMMIT_GRACE.as_millis());
    let server_dead = matches!(
        &server_observation,
        Some(ProcessObservation::Gone | ProcessObservation::Reused)
    );
    let containment_breach = match &server_observation {
        Some(ProcessObservation::Exact {
            identity,
            containment_ok: false,
            ..
        }) => Some(identity.cgroup.clone()),
        _ => None,
    };
    let worker_containment_breach = match &worker_observation {
        Some(ProcessObservation::Exact {
            identity,
            containment_ok: false,
            ..
        }) => Some(identity.cgroup.clone()),
        _ => None,
    };

    let bootstrap_abandoned = match record.phase {
        LifecyclePhase::Prepared | LifecyclePhase::ServerIdentified => !helper_alive,
        LifecyclePhase::SocketReady => precommit_expired,
        _ => false,
    };
    if matches!(
        record.phase,
        LifecyclePhase::Prepared | LifecyclePhase::ServerIdentified | LifecyclePhase::SocketReady
    ) && (bootstrap_abandoned || containment_breach.is_some())
    {
        if let Some(observed) = containment_breach.as_deref() {
            handle.scanner_request_cleanup_if_current(
                &record,
                "pre-commit server containment breach",
                Some(observed),
            )?;
        } else {
            handle.scanner_request_cleanup_if_current(
                &record,
                "pre-commit helper died or timed out",
                None,
            )?;
        }
    } else if matches!(
        record.phase,
        LifecyclePhase::TakeoverClaimed | LifecyclePhase::ContainerdCommitted
    ) {
        let invalid_server_containment = containment_breach.as_deref().filter(|observed| {
            record.phase != LifecyclePhase::TakeoverClaimed
                || !takeover_cgroup_allowed(&record, observed)
        });
        let invalid_containment = worker_containment_breach
            .as_deref()
            .or(invalid_server_containment);
        let claim_timed_out = record.phase == LifecyclePhase::TakeoverClaimed && takeover_expired;
        // Worker exit is delivered synchronously to the live CubeShim through
        // the event channel. Do not race a normal Join/Shutdown window here;
        // if the Shim also exits, server_dead drives durable cleanup and the
        // recorded worker identity is reaped below.
        let terminal_fault = server_dead || claim_timed_out || invalid_containment.is_some();
        let failure_ready =
            record.create_state == CreateState::Failed && create_failure_cleanup_ready(&record)?;

        if terminal_fault && record.create_state == CreateState::InProgress {
            let (code, message) = if server_dead {
                ("INTERNAL", "CubeShim server exited during Create")
            } else if invalid_containment.is_some() {
                (
                    "INTERNAL",
                    "CubeShim or cube-vmm-worker left the claimed Host cgroup",
                )
            } else {
                ("DEADLINE_EXCEEDED", "Host placement claim timed out")
            };
            handle.scanner_publish_failure_if_current(
                &record,
                code,
                message,
                invalid_containment,
            )?;
        } else if failure_ready
            || (terminal_fault
                && matches!(
                    record.create_state,
                    CreateState::Succeeded | CreateState::None
                ))
        {
            let reason = if invalid_containment.is_some() {
                "committed CubeShim or cube-vmm-worker containment breach"
            } else if server_dead {
                "committed server exited"
            } else if claim_timed_out {
                "Host placement claim timed out"
            } else {
                "Create RPC failed and drained"
            };
            handle.scanner_request_cleanup_if_current(&record, reason, invalid_containment)?;
        } else if record.phase == LifecyclePhase::ContainerdCommitted {
            if let Some(ProcessObservation::Exact {
                identity,
                containment_ok: true,
                ..
            }) = &server_observation
            {
                if let Err(error) = verify_target_membership(&record.target, identity.pid) {
                    let message = format!("committed Host target monitoring failed: {error}");
                    if record.create_state == CreateState::InProgress {
                        handle.scanner_publish_failure_if_current(
                            &record, "INTERNAL", &message, None,
                        )?;
                    } else {
                        handle.scanner_request_cleanup_if_current(&record, &message, None)?;
                    }
                } else {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }
    }

    let phase = handle.read_record()?.phase;
    if matches!(
        phase,
        LifecyclePhase::CleanupRequired
            | LifecyclePhase::CleanupOwnersDurable
            | LifecyclePhase::ServerStopped
    ) {
        converge_cleanup(handle, queue).await?;
    }
    Ok(())
}

fn adopt_unregistered_server(
    handle: &LifecycleHandle,
    record: &LifecycleRecord,
) -> Result<bool, String> {
    let helper_alive = immutable_process_is_live(&record.helper)?;
    let processes = fs::read_dir("/proc")
        .map_err(|error| format!("scan processes for server adoption: {error}"))?;
    let mut candidate = None;
    for process in processes {
        let process = process.map_err(|error| format!("read process adoption entry: {error}"))?;
        let Ok(pid) = process.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if pid == record.helper.pid {
            continue;
        }
        match process_launch_nonce_hash(pid) {
            Ok(Some(hash)) if hash == record.launch_nonce_sha256 => {}
            Ok(_) => continue,
            Err(_error) if !process.path().exists() => continue,
            Err(error) => return Err(error),
        }
        let identity = match server_process_identity(pid) {
            Ok(identity) => identity,
            Err(_error) if !process.path().exists() => continue,
            Err(error) => return Err(error),
        };
        if identity.executable != record.expected_server_executable
            || identity.command_sha256 != record.expected_server_command_sha256
            || identity.cwd != record.bundle_identity
            || identity.cgroup != record.target.cgroup()
        {
            continue;
        }
        let parent = match process_parent_pid(pid) {
            Ok(parent) => parent,
            Err(_error) if !process.path().exists() => continue,
            Err(error) => return Err(error),
        };
        if parent != record.helper.pid && !(parent == 1 && !helper_alive) {
            continue;
        }
        if candidate.replace(identity).is_some() {
            return Err("multiple processes match the unregistered server identity".to_string());
        }
    }
    let Some(identity) = candidate else {
        return Ok(false);
    };
    handle.register_server_identity(identity, &record.launch_nonce_sha256)?;
    Ok(true)
}

fn process_launch_nonce_hash(pid: i32) -> Result<Option<String>, String> {
    let data = fs::read(format!("/proc/{pid}/environ"))
        .map_err(|error| format!("read process {pid} environment: {error}"))?;
    let prefix = format!("{LAUNCH_NONCE_ENV}=");
    for entry in data.split(|byte| *byte == 0) {
        if let Some(value) = entry.strip_prefix(prefix.as_bytes()) {
            let value = std::str::from_utf8(value)
                .map_err(|error| format!("process {pid} launch nonce is not UTF-8: {error}"))?;
            return decode_hex(value).map(|nonce| Some(sha256_hex(&nonce)));
        }
    }
    Ok(None)
}

fn process_environment_value(pid: i32, name: &str) -> Result<Option<String>, String> {
    let data = fs::read(format!("/proc/{pid}/environ"))
        .map_err(|error| format!("read process {pid} environment: {error}"))?;
    let prefix = format!("{name}=");
    for entry in data.split(|byte| *byte == 0) {
        if let Some(value) = entry.strip_prefix(prefix.as_bytes()) {
            return std::str::from_utf8(value)
                .map(|value| Some(value.to_string()))
                .map_err(|error| format!("process {pid} {name} is not UTF-8: {error}"));
        }
    }
    Ok(None)
}

fn observe_allocated_vmm_worker(
    record: &LifecycleRecord,
) -> Result<Option<ProcessObservation>, String> {
    let Some(worker) = record.vmm_worker.as_ref() else {
        return Ok(None);
    };
    validate_vmm_worker_record(record, worker)?;
    if worker.state == VmmWorkerState::SpawnIntent {
        return Ok(None);
    }
    let identity = worker
        .identity
        .as_ref()
        .ok_or_else(|| "allocated cube-vmm-worker has no process identity".to_string())?;
    if identity.executable != worker.expected_executable
        || identity.cgroup != record.target.cgroup()
        || worker.launch_nonce_sha256.is_empty()
    {
        return Err("allocated cube-vmm-worker durable identity is invalid".to_string());
    }
    observe_process(identity).map(Some)
}

fn find_spawn_intent_vmm_worker(
    record: &LifecycleRecord,
    worker: &VmmWorkerRecord,
) -> Result<Option<ProcessIdentity>, String> {
    validate_vmm_worker_record(record, worker)?;
    if worker.state != VmmWorkerState::SpawnIntent || worker.identity.is_some() {
        return Err("cube-vmm-worker is not an unallocated spawn INTENT".to_string());
    }
    let expected_parent = record.server.as_ref().map(|server| server.pid);
    let mut candidate = None;
    for process in
        fs::read_dir("/proc").map_err(|error| format!("scan processes for worker: {error}"))?
    {
        let process = process.map_err(|error| format!("read worker process entry: {error}"))?;
        let Ok(pid) = process.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let nonce = match process_environment_value(pid, "CUBE_VMM_WORKER_NONCE") {
            Ok(Some(nonce)) if sha256_hex(nonce.as_bytes()) == worker.launch_nonce_sha256 => nonce,
            Ok(_) => continue,
            Err(_error) if !process.path().exists() => continue,
            Err(error) => return Err(error),
        };
        if nonce.is_empty() {
            continue;
        }
        let identity = match process_identity(pid) {
            Ok(identity) => identity,
            Err(_error) if !process.path().exists() => continue,
            Err(error) => return Err(error),
        };
        if identity.executable != worker.expected_executable {
            continue;
        }
        let parent = match process_parent_pid(pid) {
            Ok(parent) => parent,
            Err(_error) if !process.path().exists() => continue,
            Err(error) => return Err(error),
        };
        if expected_parent.is_some_and(|expected| parent != expected && parent != 1) {
            continue;
        }
        if candidate.replace(identity).is_some() {
            return Err("multiple processes match cube-vmm-worker spawn INTENT".to_string());
        }
    }
    Ok(candidate)
}

fn terminate_recorded_vmm_worker(record: &LifecycleRecord) -> Result<(), String> {
    let Some(worker) = record.vmm_worker.as_ref() else {
        return Ok(());
    };
    validate_vmm_worker_record(record, worker)?;
    let expected = match worker.state {
        VmmWorkerState::SpawnIntent => find_spawn_intent_vmm_worker(record, worker)?,
        VmmWorkerState::Allocated => Some(
            worker
                .identity
                .clone()
                .ok_or_else(|| "allocated cube-vmm-worker has no identity".to_string())?,
        ),
    };
    let Some(expected) = expected else {
        return Ok(());
    };
    match observe_process(&expected)? {
        ProcessObservation::Gone | ProcessObservation::Reused => Ok(()),
        ProcessObservation::Exact {
            pidfd,
            identity,
            containment_ok,
        } => {
            if worker.state == VmmWorkerState::SpawnIntent {
                let nonce = process_environment_value(identity.pid, "CUBE_VMM_WORKER_NONCE")?
                    .ok_or_else(|| "spawn INTENT worker lost its launch nonce".to_string())?;
                if sha256_hex(nonce.as_bytes()) != worker.launch_nonce_sha256 {
                    return Err("spawn INTENT worker nonce changed before termination".to_string());
                }
            }
            if identity.executable != worker.expected_executable {
                return Err("cube-vmm-worker executable changed before termination".to_string());
            }
            let target_breach = identity.cgroup != record.target.cgroup();
            let allow_durable_breach = worker.state == VmmWorkerState::Allocated
                && !containment_ok
                && target_breach
                && record
                    .containment_breach
                    .as_ref()
                    .is_some_and(|breach| breach.cgroup == identity.cgroup);
            if worker.state == VmmWorkerState::Allocated
                && (!containment_ok || target_breach)
                && !allow_durable_breach
            {
                return Err(
                    "refuse to terminate allocated cube-vmm-worker outside its durable cgroup"
                        .to_string(),
                );
            }
            signal_exact_process(&expected, &pidfd, allow_durable_breach)
        }
    }
}

fn validate_vmm_worker_record(
    record: &LifecycleRecord,
    worker: &VmmWorkerRecord,
) -> Result<(), String> {
    if worker.protocol_version != crate::hypervisor::worker::PROTOCOL_VERSION {
        return Err(format!(
            "cube-vmm-worker durable protocol version {} is not supported",
            worker.protocol_version
        ));
    }
    if worker.operation_epoch == 0 || worker.operation_epoch > record.operation_owner.epoch {
        return Err(format!(
            "cube-vmm-worker durable operation epoch {} is inconsistent with owner epoch {}",
            worker.operation_epoch, record.operation_owner.epoch
        ));
    }
    if worker.launch_nonce_sha256.is_empty() {
        return Err("cube-vmm-worker durable launch nonce is empty".to_string());
    }
    match (&worker.state, &worker.identity) {
        (VmmWorkerState::SpawnIntent, None) | (VmmWorkerState::Allocated, Some(_)) => Ok(()),
        (VmmWorkerState::SpawnIntent, Some(_)) => {
            Err("spawn INTENT cube-vmm-worker unexpectedly has an identity".to_string())
        }
        (VmmWorkerState::Allocated, None) => {
            Err("allocated cube-vmm-worker has no process identity".to_string())
        }
    }
}

fn process_parent_pid(pid: i32) -> Result<i32, String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("read process {pid} stat: {error}"))?;
    let end = stat
        .rfind(')')
        .ok_or_else(|| format!("process {pid} stat has no command terminator"))?;
    stat[end + 1..]
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("process {pid} stat has no parent pid"))?
        .parse()
        .map_err(|error| format!("parse process {pid} parent pid: {error}"))
}

fn cleanup_interrupted_constructor(handle: &LifecycleHandle) -> Result<(), String> {
    let metadata = fs::metadata(&handle.directory).map_err(|error| {
        format!(
            "stat interrupted lifecycle {}: {error}",
            handle.directory.display()
        )
    })?;
    let age = SystemTime::now()
        .duration_since(
            metadata
                .modified()
                .map_err(|error| format!("read interrupted lifecycle mtime: {error}"))?,
        )
        .unwrap_or_default();
    if age < PRECOMMIT_GRACE {
        return Ok(());
    }
    for entry in fs::read_dir(&handle.directory)
        .map_err(|error| format!("scan interrupted lifecycle: {error}"))?
    {
        let entry = entry.map_err(|error| format!("read interrupted lifecycle entry: {error}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let known = matches!(
            name.as_ref(),
            RECORD_LOCK_FILE | OPERATION_LOCK_FILE | HOST_OWNER_FILE | RUNTIME_OWNER_FILE
        ) || (name.starts_with('.') && name.contains(".tmp-"));
        if !known
            || !entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        {
            return Err(format!(
                "refuse to remove unknown interrupted lifecycle entry {}",
                entry.path().display()
            ));
        }
        fs::remove_file(entry.path())
            .map_err(|error| format!("remove interrupted lifecycle entry: {error}"))?;
    }
    fs::remove_dir(&handle.directory).map_err(|error| {
        format!(
            "remove interrupted lifecycle {}: {error}",
            handle.directory.display()
        )
    })?;
    sync_directory(handle.directory.parent().unwrap())
}

#[derive(Debug)]
enum ProcessObservation {
    Gone,
    Reused,
    Exact {
        pidfd: OwnedFd,
        identity: ProcessIdentity,
        containment_ok: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcPresence {
    Present,
    Missing,
    Unknown,
}

fn observe_process(expected: &ProcessIdentity) -> Result<ProcessObservation, String> {
    // SAFETY: pidfd_open returns a new owned descriptor on success.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, expected.pid, 0) as i32 };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        let presence = if error.raw_os_error() == Some(libc::EINVAL) {
            let process_path = PathBuf::from(format!("/proc/{}", expected.pid));
            match process_path.try_exists() {
                Ok(false) => ProcPresence::Missing,
                Ok(true) => ProcPresence::Present,
                Err(proc_error) => {
                    return Err(format!(
                        "pidfd_open lifecycle pid {}: {error}; inspect {}: {proc_error}",
                        expected.pid,
                        process_path.display()
                    ))
                }
            }
        } else {
            ProcPresence::Unknown
        };
        if pidfd_open_failure_means_gone(&error, presence) {
            return Ok(ProcessObservation::Gone);
        }
        return Err(format!(
            "pidfd_open lifecycle pid {}: {error}",
            expected.pid
        ));
    }
    // SAFETY: raw is a new descriptor returned by pidfd_open.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let actual = match process_identity_for_expected(expected) {
        Ok(actual) => actual,
        Err(identity_error) => {
            let process_path = PathBuf::from(format!("/proc/{}", expected.pid));
            match process_path.try_exists() {
                Ok(exists) => {
                    let presence = if exists {
                        ProcPresence::Present
                    } else {
                        ProcPresence::Missing
                    };
                    if process_identity_failure_means_gone(presence) {
                        return Ok(ProcessObservation::Gone);
                    }
                    return Err(identity_error);
                }
                Err(proc_error) => {
                    return Err(format!(
                    "{identity_error}; inspect {} after live pidfd identity error: {proc_error}",
                    process_path.display()
                ))
                }
            }
        }
    };
    if !immutable_identity_matches(expected, &actual) {
        return Ok(ProcessObservation::Reused);
    }
    Ok(ProcessObservation::Exact {
        containment_ok: actual.cgroup == expected.cgroup,
        identity: actual,
        pidfd,
    })
}

fn pidfd_open_failure_means_gone(error: &std::io::Error, presence: ProcPresence) -> bool {
    error.raw_os_error() == Some(libc::ESRCH)
        || (error.raw_os_error() == Some(libc::EINVAL) && presence == ProcPresence::Missing)
}

fn process_identity_failure_means_gone(presence: ProcPresence) -> bool {
    presence == ProcPresence::Missing
}

fn immutable_process_is_live(expected: &ProcessIdentity) -> Result<bool, String> {
    Ok(matches!(
        observe_process(expected)?,
        ProcessObservation::Exact { .. }
    ))
}

async fn converge_cleanup(handle: &LifecycleHandle, queue: &Path) -> Result<(), String> {
    // Host identity reconciliation is deliberately independent from the
    // RuntimeResource handoff.  A missing/changed Host leaf must not leave a
    // provider lease permanently parked behind ready_for_cleanup=false.
    let host_reconcile_error = reconcile_host_target_identity(handle)
        .err()
        .map(|error| format!("Host target identity reconciliation: {error}"));
    ensure_cleanup_handoff(handle, queue)?;
    ensure_scanner_owner(handle)?;
    let mut record = handle.read_record()?;
    if record.phase == LifecyclePhase::CleanupOwnersDurable {
        terminate_recorded_vmm_worker(&record)?;
        if let Some(server) = record.server.as_ref() {
            match observe_process(server)? {
                ProcessObservation::Gone | ProcessObservation::Reused => {}
                ProcessObservation::Exact {
                    pidfd,
                    identity,
                    containment_ok,
                } => {
                    if !containment_ok {
                        handle.request_containment_cleanup(
                            &identity.cgroup,
                            "server containment breach observed during cleanup",
                        )?;
                    }
                    let current = handle.read_record()?;
                    let breach_is_durable = !containment_ok
                        && current.phase == LifecyclePhase::CleanupOwnersDurable
                        && current.containment_breach.is_some();
                    signal_exact_process(server, &pidfd, breach_is_durable)?;
                }
            }
        }
        handle.update_record(|current| {
            if current.phase == LifecyclePhase::CleanupOwnersDurable {
                current.phase = LifecyclePhase::ServerStopped;
            }
            Ok(())
        })?;
        record = handle.read_record()?;
    }
    if record.phase != LifecyclePhase::ServerStopped {
        return Ok(());
    }

    // Revocation and both owner handoffs are durable, and the exact server has
    // now exited. Its death releases any operation.lock held across a stuck
    // provider RPC. Cross that barrier only after signalling/waiting, then
    // enable the independent cleanup consumers; no forward owner can start in
    // SERVER_STOPPED.
    {
        let _operation_barrier = handle.operation_lock()?;
        let _record_lock = handle.record_lock()?;
        let barrier_record = handle.read_record()?;
        if barrier_record.operation_owner.kind != OwnerKind::Scanner
            || barrier_record.phase != LifecyclePhase::ServerStopped
        {
            return Err("cleanup operation barrier lost stopped scanner ownership".to_string());
        }
    }
    mark_runtime_cleanup_ready(queue, &record.generation)?;
    mark_host_cleanup_ready(queue, &record.generation)?;
    let host_pending = cleanup_queue_path(queue, HOST_QUEUE_DIRECTORY, &record.generation).exists();
    let runtime_pending =
        cleanup_queue_path(queue, RUNTIME_QUEUE_DIRECTORY, &record.generation).exists();
    if host_pending || runtime_pending {
        return match host_reconcile_error {
            Some(error) => Err(error),
            None => Ok(()),
        };
    }
    handle.update_record(|current| {
        if current.phase == LifecyclePhase::ServerStopped {
            current.phase = LifecyclePhase::Done;
        }
        Ok(())
    })?;
    match host_reconcile_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn ensure_scanner_owner(handle: &LifecycleHandle) -> Result<(), String> {
    let scanner = process_identity(std::process::id() as i32)?;
    let record = handle.read_record()?;
    if record.operation_owner.kind == OwnerKind::Scanner
        && immutable_identity_matches(&record.operation_owner.identity, &scanner)
    {
        return Ok(());
    }
    if record.operation_owner.kind == OwnerKind::Scanner
        && immutable_process_is_live(&record.operation_owner.identity)?
    {
        return Err(format!(
            "another live watchdog {} owns cleanup epoch {}",
            record.operation_owner.identity.pid, record.operation_owner.epoch
        ));
    }
    handle.update_record(|current| {
        if !matches!(
            current.phase,
            LifecyclePhase::CleanupOwnersDurable | LifecyclePhase::ServerStopped
        ) {
            return Err(format!(
                "scanner takeover requires durable cleanup owners, found {:?}",
                current.phase
            ));
        }
        let old_epoch = current.operation_owner.epoch;
        current.operation_owner = OperationOwner {
            kind: OwnerKind::Scanner,
            epoch: old_epoch
                .checked_add(1)
                .ok_or_else(|| "operation owner epoch overflow".to_string())?,
            identity: scanner,
            revoked_epoch: Some(old_epoch),
        };
        Ok(())
    })?;
    Ok(())
}

fn reconcile_host_target_identity(handle: &LifecycleHandle) -> Result<(), String> {
    let record = handle.read_record()?;
    let host_owner = handle.read_host_owner()?;
    if host_owner.state == HostOwnerState::Empty {
        return Ok(());
    }
    if !record.target.managed() || !record.target.same_location(&host_owner.target) {
        return Err("Host owner location differs from lifecycle record".to_string());
    }
    let leaf_path =
        Path::new("/sys/fs/cgroup").join(record.target.cgroup().trim_start_matches('/'));
    if !leaf_path.exists() {
        return Ok(());
    }
    let parent_identity = record
        .target
        .parent_identity()
        .ok_or_else(|| "managed Host target has no parent identity".to_string())?;
    if file_identity(leaf_path.parent().unwrap())? != *parent_identity {
        return Err("cannot adopt Host leaf after parent identity changed".to_string());
    }
    let actual = file_identity(&leaf_path)?;
    let record_identity = record.target.leaf_identity();
    let owner_identity = host_owner.target.leaf_identity();
    match (record_identity, owner_identity) {
        (Some(recorded), Some(owned)) => {
            if recorded != owned || recorded != &actual {
                return Err(format!(
                    "Host leaf identity differs across durable owners or live path: {}",
                    leaf_path.display()
                ));
            }
            Ok(())
        }
        (Some(recorded), None) => {
            if recorded != &actual {
                return Err(format!(
                    "lifecycle Host leaf identity differs from live path: {}",
                    leaf_path.display()
                ));
            }
            handle.persist_leaf_identity(actual)
        }
        (None, Some(owned)) => {
            if owned != &actual {
                return Err(format!(
                    "Host owner leaf identity differs from live path: {}",
                    leaf_path.display()
                ));
            }
            handle.persist_leaf_identity(actual)
        }
        (None, None) => {
            for pid in cgroup_pids(&leaf_path)? {
                let known = host_owner.server.as_ref().is_some_and(|server| {
                    pid == server.pid && immutable_process_is_live(server).unwrap_or(false)
                });
                if !known {
                    return Err(format!(
                        "refuse to adopt Host leaf {} containing unknown pid {pid}",
                        leaf_path.display()
                    ));
                }
            }
            handle.persist_leaf_identity(actual)
        }
    }
}

fn cgroup_pids(path: &Path) -> Result<Vec<i32>, String> {
    fs::read_to_string(path.join("cgroup.procs"))
        .map_err(|error| format!("read Host leaf members {}: {error}", path.display()))?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.trim()
                .parse()
                .map_err(|error| format!("parse Host leaf pid {line}: {error}"))
        })
        .collect()
}

fn ensure_cleanup_handoff(handle: &LifecycleHandle, queue: &Path) -> Result<(), String> {
    let record = handle.read_record()?;
    if record.phase == LifecyclePhase::CleanupRequired {
        let scanner = process_identity(std::process::id() as i32)?;
        handle.update_record(|current| {
            if current.phase != LifecyclePhase::CleanupRequired {
                return Ok(());
            }
            if current.operation_owner.kind == OwnerKind::Scanner
                && immutable_identity_matches(&current.operation_owner.identity, &scanner)
            {
                return Ok(());
            }
            let old_epoch = current.operation_owner.epoch;
            current.operation_owner = OperationOwner {
                kind: OwnerKind::Scanner,
                epoch: old_epoch
                    .checked_add(1)
                    .ok_or_else(|| "operation owner epoch overflow".to_string())?,
                identity: scanner,
                revoked_epoch: Some(old_epoch),
            };
            Ok(())
        })?;
    }
    let record = handle.read_record()?;
    if matches!(
        record.phase,
        LifecyclePhase::CleanupOwnersDurable | LifecyclePhase::ServerStopped
    ) {
        if record.phase == LifecyclePhase::ServerStopped {
            mark_host_cleanup_ready(queue, &record.generation)?;
        }
        return Ok(());
    }
    if record.phase != LifecyclePhase::CleanupRequired {
        return Ok(());
    }
    let mut errors = Vec::new();
    match read_json::<HostCgroupOwner>(&handle.directory.join(HOST_OWNER_FILE)) {
        Ok(host) => {
            let job = HostCleanupJob {
                owner: host,
                socket: record.socket.clone(),
                created_at_ms: record.created_at_ms,
                lifecycle_root: handle
                    .directory
                    .parent()
                    .unwrap_or_else(|| Path::new("/"))
                    .display()
                    .to_string(),
                ready_for_cleanup: false,
            };
            if let Err(error) = persist_host_cleanup_job(queue, &record.generation, &job) {
                errors.push(format!("Host owner handoff: {error}"));
            }
        }
        Err(error) => errors.push(format!("read Host owner source: {error}")),
    }
    match read_json::<RuntimeResourceOwner>(&handle.directory.join(RUNTIME_OWNER_FILE)) {
        Ok(runtime) => {
            let job = RuntimeCleanupJob {
                owner: runtime,
                ready_for_cleanup: false,
            };
            if let Err(error) = persist_runtime_cleanup_job(queue, &record.generation, &job) {
                errors.push(format!("RuntimeResource owner handoff: {error}"));
            }
        }
        Err(error) => errors.push(format!("read RuntimeResource owner source: {error}")),
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    // Read back both destinations before allowing any signal.
    let _: HostCleanupJob = read_json(&cleanup_queue_path(
        queue,
        HOST_QUEUE_DIRECTORY,
        &record.generation,
    ))?;
    let _: RuntimeCleanupJob = read_json(&cleanup_queue_path(
        queue,
        RUNTIME_QUEUE_DIRECTORY,
        &record.generation,
    ))?;
    handle.update_record(|current| {
        if current.phase == LifecyclePhase::CleanupRequired {
            current.phase = LifecyclePhase::CleanupOwnersDurable;
        }
        Ok(())
    })?;
    Ok(())
}

fn cleanup_queue_path(queue: &Path, kind: &str, generation: &str) -> PathBuf {
    queue.join(kind).join(format!("{generation}.json"))
}

fn persist_host_cleanup_job(
    queue: &Path,
    generation: &str,
    job: &HostCleanupJob,
) -> Result<(), String> {
    persist_cleanup_job(queue, HOST_QUEUE_DIRECTORY, generation, job, |existing| {
        existing.owner == job.owner
            && existing.socket == job.socket
            && existing.created_at_ms == job.created_at_ms
            && existing.lifecycle_root == job.lifecycle_root
    })
}

fn persist_runtime_cleanup_job(
    queue: &Path,
    generation: &str,
    job: &RuntimeCleanupJob,
) -> Result<(), String> {
    persist_cleanup_job(
        queue,
        RUNTIME_QUEUE_DIRECTORY,
        generation,
        job,
        |existing| existing.owner == job.owner,
    )
}

fn persist_cleanup_job<T>(
    queue: &Path,
    kind: &str,
    generation: &str,
    job: &T,
    matches: impl FnOnce(&T) -> bool,
) -> Result<(), String>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let directory = queue.join(kind);
    ensure_directory(&directory)?;
    let path = cleanup_queue_path(queue, kind, generation);
    if path.exists() {
        let existing: T = read_json(&path)?;
        if !matches(&existing) {
            return Err(format!(
                "existing cleanup job differs from canonical source: {}",
                path.display()
            ));
        }
        return Ok(());
    }
    atomic_write_json(&path, job)
}

fn mark_host_cleanup_ready(queue: &Path, generation: &str) -> Result<(), String> {
    let path = cleanup_queue_path(queue, HOST_QUEUE_DIRECTORY, generation);
    if !path.exists() {
        return Ok(());
    }
    let mut job: HostCleanupJob = read_json(&path)?;
    if job.owner.generation != generation {
        return Err("Host cleanup job generation mismatch".to_string());
    }
    if !job.ready_for_cleanup {
        job.ready_for_cleanup = true;
        atomic_write_json(&path, &job)?;
    }
    Ok(())
}

fn mark_runtime_cleanup_ready(queue: &Path, generation: &str) -> Result<(), String> {
    let path = cleanup_queue_path(queue, RUNTIME_QUEUE_DIRECTORY, generation);
    if !path.exists() {
        return Ok(());
    }
    let mut job: RuntimeCleanupJob = read_json(&path)?;
    if job.owner.generation_id != generation {
        return Err("RuntimeResource cleanup job generation mismatch".to_string());
    }
    if !job.ready_for_cleanup {
        job.ready_for_cleanup = true;
        atomic_write_json(&path, &job)?;
    }
    Ok(())
}

fn acknowledge_queue(queue: &Path, kind: &str, generation: &str) -> Result<(), String> {
    let path = queue.join(kind).join(format!("{generation}.json"));
    let parent = path
        .parent()
        .ok_or_else(|| format!("cleanup queue path has no parent: {}", path.display()))?;
    if take_cleanup_unlink_failpoint(&path, "before-unlink") {
        return Err(format!(
            "injected failure before cleanup queue unlink: {}",
            path.display()
        ));
    }
    match fs::remove_file(&path) {
        Ok(()) => {
            if take_cleanup_unlink_failpoint(&path, "after-unlink") {
                return Err(format!(
                    "injected failure after cleanup queue unlink: {}",
                    path.display()
                ));
            }
            sync_directory(parent)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => sync_directory(parent),
        Err(error) => Err(format!(
            "acknowledge cleanup queue {}: {error}",
            path.display()
        )),
    }
}

#[cfg(test)]
fn cleanup_unlink_failpoint_path(path: &Path, stage: &str) -> PathBuf {
    path.parent().unwrap().join(format!(
        ".{}.fail-{stage}",
        path.file_name().and_then(OsStr::to_str).unwrap_or("queue")
    ))
}

#[cfg(test)]
fn take_cleanup_unlink_failpoint(path: &Path, stage: &str) -> bool {
    fs::remove_file(cleanup_unlink_failpoint_path(path, stage)).is_ok()
}

#[cfg(not(test))]
fn take_cleanup_unlink_failpoint(_path: &Path, _stage: &str) -> bool {
    false
}

fn signal_exact_process(
    expected: &ProcessIdentity,
    pidfd: &OwnedFd,
    allow_containment_breach: bool,
) -> Result<(), String> {
    let before = process_identity_for_expected(expected)?;
    if !immutable_identity_matches(expected, &before) {
        return Ok(());
    }
    if before.cgroup != expected.cgroup && !allow_containment_breach {
        return Err(format!(
            "refuse to signal pid {} outside expected cgroup",
            expected.pid
        ));
    }
    let immediately_before = process_identity_for_expected(expected)?;
    if !immutable_identity_matches(expected, &immediately_before) {
        return Ok(());
    }
    if immediately_before.cgroup != expected.cgroup && !allow_containment_breach {
        return Err(format!(
            "refuse to signal pid {} after containment changed",
            expected.pid
        ));
    }
    // SAFETY: pidfd identifies the already verified immutable process.
    let sent = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if sent < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(format!("pidfd_send_signal {}: {error}", expected.pid));
        }
    }
    wait_pidfd(pidfd, expected.pid, Duration::from_secs(30))
}

fn wait_pidfd(pidfd: &OwnedFd, pid: i32, timeout: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let mut descriptor = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one valid pollfd.
        let result = unsafe { libc::poll(&mut descriptor, 1, 100) };
        if result > 0 && descriptor.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(());
        }
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(format!(
                "poll pidfd {pid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("timed out waiting for lifecycle pid {pid}"));
        }
    }
}

fn reconcile_cleanup_controllers(path: &Path, job: &mut HostCleanupJob) -> Result<(), String> {
    let Some(journal) = job.owner.controllers.as_ref() else {
        return Ok(());
    };
    verify_controller_journal_owner(
        journal,
        journal.owner_epoch,
        &journal.owner_identity,
        &journal.create_fingerprint,
    )?;
    let leaf = Path::new("/sys/fs/cgroup").join(job.owner.target.cgroup().trim_start_matches('/'));
    if !leaf.exists() {
        let journal = job.owner.controllers.as_mut().unwrap();
        journal.state = ControllerTransactionState::AbandonedForExactDelete;
        journal.degraded_reason = None;
        persist_host_cleanup_job_exact(path, job)?;
        return Ok(());
    }
    verify_cgroup_cleanup_identity(
        &leaf,
        job.owner
            .target
            .parent_identity()
            .ok_or_else(|| "controller cleanup target has no parent identity".to_string())?,
        job.owner.target.leaf_identity(),
    )?;
    let transaction_id = journal.transaction_id.clone();
    replay_controller_rollback(
        &leaf,
        || {
            let current: HostCleanupJob = read_json(path)?;
            let journal = current
                .owner
                .controllers
                .ok_or_else(|| "cleanup controller journal disappeared".to_string())?;
            if journal.transaction_id != transaction_id {
                return Err("cleanup controller transaction identity changed".to_string());
            }
            Ok(journal)
        },
        |updated| {
            let mut current: HostCleanupJob = read_json(path)?;
            if current
                .owner
                .controllers
                .as_ref()
                .is_none_or(|journal| journal.transaction_id != transaction_id)
            {
                return Err("cleanup controller transaction identity changed".to_string());
            }
            current.owner.controllers = Some(updated.clone());
            persist_host_cleanup_job_exact(path, &current)
        },
    )?;
    let mut current: HostCleanupJob = read_json(path)?;
    let journal = current
        .owner
        .controllers
        .as_ref()
        .ok_or_else(|| "cleanup controller journal disappeared after rollback".to_string())?;
    if journal.transaction_id != transaction_id
        || journal.state != ControllerTransactionState::Restored
    {
        return Err("cleanup controller rollback did not reach RESTORED".to_string());
    }
    clear_restored_controller_journal(&leaf, &mut current.owner.controllers)?;
    persist_host_cleanup_job_exact(path, &current)?;
    *job = current;
    Ok(())
}

fn persist_host_cleanup_job_exact(path: &Path, job: &HostCleanupJob) -> Result<(), String> {
    match atomic_write_json(path, job) {
        Ok(()) => Ok(()),
        Err(error) => {
            let durable: HostCleanupJob = read_json(path)?;
            if durable == *job {
                sync_directory(path.parent().unwrap())
            } else {
                Err(error)
            }
        }
    }
}

fn cleanup_host_target(target: &HostTarget) -> Result<(), String> {
    match target {
        HostTarget::Pending { .. } | HostTarget::Legacy { .. } => Ok(()),
        HostTarget::Cgroupfs {
            cgroup,
            parent_identity,
            leaf_identity,
            ..
        } => {
            let path = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
            if !path.exists() {
                return Ok(());
            }
            verify_cgroup_cleanup_identity(&path, parent_identity, leaf_identity.as_ref())?;
            verify_empty_cgroup(&path)?;
            fs::remove_dir(&path)
                .map_err(|error| format!("remove empty cgroupfs leaf {}: {error}", path.display()))
        }
        HostTarget::Systemd {
            unit,
            cgroup,
            parent_identity,
            leaf_identity,
            ..
        } => {
            let path = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
            cleanup_systemd_target_with(
                unit,
                &path,
                parent_identity,
                leaf_identity.as_ref(),
                || systemd_properties(unit),
                || systemd_unit_absent(unit),
                || reset_failed_systemd_unit(unit),
            )
        }
    }
}

fn cleanup_systemd_target_with<P, A, R>(
    unit: &str,
    path: &Path,
    parent_identity: &FileIdentity,
    leaf_identity: Option<&FileIdentity>,
    mut properties: P,
    mut unit_absent: A,
    mut reset_failed: R,
) -> Result<(), String>
where
    P: FnMut() -> Result<HashMap<String, String>, String>,
    A: FnMut() -> Result<bool, String>,
    R: FnMut() -> Result<(), String>,
{
    if !path.exists() {
        return if unit_absent()? {
            Ok(())
        } else {
            Err(format!(
                "systemd scope {unit} remains loaded after cgroup disappeared"
            ))
        };
    }
    verify_cgroup_cleanup_identity(path, parent_identity, leaf_identity)?;

    let values = {
        let mut query_attempt = 0;
        loop {
            match properties() {
                Ok(values) => break values,
                Err(query_error) => {
                    // systemctl show races scope collection: it can fail
                    // while LoadState still reports loaded, then become
                    // inactive or absent milliseconds later. Retry only
                    // after the exact path identity was verified above; an
                    // absent unit still requires an empty identity-bound leaf.
                    if unit_absent()? {
                        if path.exists() {
                            verify_cgroup_cleanup_identity(path, parent_identity, leaf_identity)?;
                            verify_empty_cgroup(path)?;
                        }
                        return Ok(());
                    }
                    query_attempt += 1;
                    if query_attempt >= 100 {
                        return Err(query_error);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    };

    match values.get("ActiveState").map(String::as_str) {
        Some("inactive") | Some("dead") => {
            // The property retry above is intentionally bounded but may span
            // collection and recreation of the same pathname. Revalidate the
            // durable identity after the final query before accepting state.
            verify_cgroup_cleanup_identity(path, parent_identity, leaf_identity)?;
            verify_empty_cgroup(path)?;
            verify_cgroup_cleanup_identity(path, parent_identity, leaf_identity)?;
            Ok(())
        }
        Some("failed") => {
            // Resetting a failed scope may cause systemd to collect its
            // cgroup. Only do so after the exact leaf is proven empty; never
            // use reset-failed as a process-removal operation.
            verify_cgroup_cleanup_identity(path, parent_identity, leaf_identity)?;
            verify_empty_cgroup(path)?;
            verify_cgroup_cleanup_identity(path, parent_identity, leaf_identity)?;
            reset_failed()
        }
        _ => Err(format!("systemd scope {unit} has not been collected yet")),
    }
}

fn reset_failed_systemd_unit(unit: &str) -> Result<(), String> {
    let output = Command::new("systemctl")
        .args(["reset-failed", unit])
        .output()
        .map_err(|error| format!("reset failed scope {unit}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "reset failed scope {unit}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn verify_empty_cgroup(path: &Path) -> Result<(), String> {
    let events = fs::read_to_string(path.join("cgroup.events"))
        .map_err(|error| format!("read cgroup.events for {}: {error}", path.display()))?;
    if !events
        .lines()
        .any(|line| line.split_whitespace().eq(["populated", "0"]))
    {
        return Err(format!("Host leaf is still populated: {}", path.display()));
    }
    if fs::read_to_string(path.join("cgroup.procs"))
        .map_err(|error| format!("read cgroup.procs for {}: {error}", path.display()))?
        .lines()
        .any(|line| !line.trim().is_empty())
    {
        return Err(format!(
            "Host leaf still contains processes: {}",
            path.display()
        ));
    }
    let has_child = fs::read_dir(path)
        .map_err(|error| format!("scan Host leaf {}: {error}", path.display()))?
        .filter_map(Result::ok)
        .any(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false));
    if has_child {
        return Err(format!("Host leaf still has children: {}", path.display()));
    }
    Ok(())
}

fn verify_cgroup_cleanup_identity(
    path: &Path,
    expected_parent: &FileIdentity,
    expected_leaf: Option<&FileIdentity>,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Host leaf has no parent: {}", path.display()))?;
    if file_identity(parent)? != *expected_parent {
        return Err(format!(
            "Host leaf parent identity changed: {}",
            parent.display()
        ));
    }
    let Some(expected_leaf) = expected_leaf else {
        return Err(format!(
            "Host leaf exists without a durable post-create identity: {}",
            path.display()
        ));
    };
    if file_identity(path)? != *expected_leaf {
        return Err(format!("Host leaf identity changed: {}", path.display()));
    }
    Ok(())
}

fn cleanup_socket_identity(
    socket: &SocketIdentity,
    created_at_ms: u128,
    generation: &str,
    root: &Path,
) -> Result<(), String> {
    cleanup_socket_identity_with_hook(socket, created_at_ms, generation, root, || {})
}

fn cleanup_socket_identity_with_hook(
    socket: &SocketIdentity,
    created_at_ms: u128,
    generation: &str,
    root: &Path,
    before_unlink: impl FnOnce(),
) -> Result<(), String> {
    let path = Path::new(&socket.path);
    // Preparation, bind/registration, and cleanup all use this lifecycle-root
    // external lock.  Therefore no cooperating generation can publish or bind
    // a replacement between the final identity check and pathname unlink.
    let _socket_guard = acquire_socket_path_lock(root, path)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("stat cleanup socket {}: {error}", path.display())),
    };
    if !metadata.file_type().is_socket() || file_identity(path.parent().unwrap())? != socket.parent
    {
        return Err(format!(
            "socket cleanup identity mismatch: {}",
            path.display()
        ));
    }
    let original_identity = FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let registered = socket.device.zip(socket.inode);
    if let Some((device, inode)) = registered {
        if metadata.dev() != device || metadata.ino() != inode {
            return Err(format!("socket inode changed: {}", path.display()));
        }
    } else {
        if !socket.absent_at_prepare
            || metadata.mtime() < i64::try_from(created_at_ms / 1000).unwrap_or(i64::MAX)
            || socket_has_live_owner(path)?
            || another_record_owns_socket(root, Some(generation), path)?
        {
            return Err(format!(
                "unregistered socket cannot be proven stale: {}",
                path.display()
            ));
        }
    }
    // The owner scan is necessarily lock-free with respect to a new bind.
    // Fence the unlink with a second complete filesystem/generation readback.
    let final_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("restat cleanup socket {}: {error}", path.display()))?;
    if !final_metadata.file_type().is_socket()
        || (FileIdentity {
            device: final_metadata.dev(),
            inode: final_metadata.ino(),
        }) != original_identity
        || file_identity(path.parent().unwrap())? != socket.parent
        || another_record_owns_socket(root, Some(generation), path)?
    {
        return Err(format!(
            "socket identity changed before unlink: {}",
            path.display()
        ));
    }
    before_unlink();
    fs::remove_file(path).map_err(|error| format!("unlink socket {}: {error}", path.display()))
}

fn unix_socket_kernel_inodes(path: &Path) -> Result<HashSet<u64>, String> {
    let data = fs::read_to_string("/proc/net/unix")
        .map_err(|error| format!("read /proc/net/unix: {error}"))?;
    let expected = path
        .to_str()
        .ok_or_else(|| format!("socket path is not UTF-8: {}", path.display()))?;
    let mut inodes = HashSet::new();
    for (line_number, line) in data.lines().enumerate().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 7 {
            return Err(format!(
                "malformed /proc/net/unix row {}: {line}",
                line_number + 1
            ));
        }
        if fields.len() >= 8 && fields[7..].join(" ") == expected {
            let inode = fields[6].parse::<u64>().map_err(|error| {
                format!(
                    "parse /proc/net/unix inode on row {}: {error}",
                    line_number + 1
                )
            })?;
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}

fn socket_has_live_owner(path: &Path) -> Result<bool, String> {
    let kernel_inodes = unix_socket_kernel_inodes(path)?;
    if kernel_inodes.is_empty() {
        // A pathname remains after its last listener closes, but its kernel
        // row disappears.  Require two stable observations before treating
        // that state as ownerless; a concurrent rebind becomes fail-closed.
        std::thread::yield_now();
        if unix_socket_kernel_inodes(path)?.is_empty() {
            return Ok(false);
        }
        return Err(format!(
            "socket kernel identity appeared while checking owners: {}",
            path.display()
        ));
    }
    let processes = fs::read_dir("/proc").map_err(|error| format!("scan /proc: {error}"))?;
    for process in processes {
        let process = process.map_err(|error| format!("scan /proc entry: {error}"))?;
        if !process
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let process_path = process.path();
        let fds = match fs::read_dir(process_path.join("fd")) {
            Ok(fds) => fds,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && !process_path.exists() =>
            {
                continue
            }
            Err(error) => {
                return Err(format!(
                    "scan process fd directory {}: {error}",
                    process_path.display()
                ))
            }
        };
        for fd in fds {
            let fd = fd.map_err(|error| {
                format!("scan process fd entry {}: {error}", process_path.display())
            })?;
            let target = match fs::read_link(fd.path()) {
                Ok(target) => target,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!("read process fd {}: {error}", fd.path().display()))
                }
            };
            let target = target.to_string_lossy();
            if let Some(raw) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
            {
                let inode = raw.parse::<u64>().map_err(|error| {
                    format!("parse process socket fd {}: {error}", fd.path().display())
                })?;
                if kernel_inodes.contains(&inode) {
                    return Ok(true);
                }
            }
        }
    }
    if unix_socket_kernel_inodes(path)? != kernel_inodes {
        return Err(format!(
            "socket kernel identity changed while scanning owners: {}",
            path.display()
        ));
    }
    Ok(false)
}

fn another_record_owns_socket(
    root: &Path,
    generation: Option<&str>,
    socket_path: &Path,
) -> Result<bool, String> {
    let socket_parent = socket_path
        .parent()
        .ok_or_else(|| format!("shim socket has no parent: {}", socket_path.display()))?;
    let socket_parent_identity = file_identity(socket_parent)?;
    let socket_name = socket_path.file_name().ok_or_else(|| {
        format!(
            "shim socket path must contain a basename: {}",
            socket_path.display()
        )
    })?;
    for entry in fs::read_dir(root).map_err(|error| format!("scan socket owners: {error}"))? {
        let entry = entry.map_err(|error| format!("read socket owner entry: {error}"))?;
        let path = entry.path().join(RECORD_FILE);
        let record = match read_json::<LifecycleRecord>(&path) {
            Ok(record) => record,
            Err(_error) if !path.exists() => continue,
            Err(error) => return Err(error),
        };
        let is_current_generation = generation == Some(record.generation.as_str());
        if !is_current_generation && record.phase != LifecyclePhase::Done {
            let record_name = Path::new(&record.socket.path).file_name().ok_or_else(|| {
                format!(
                    "recorded shim socket path has no basename: {}",
                    record.socket.path
                )
            })?;
            // The kernel pathname owner is identified by the directory object
            // plus the entry name, not by one userspace spelling. This also
            // closes bind-mount aliases that canonicalize() cannot collapse.
            if record.socket.parent != socket_parent_identity || record_name != socket_name {
                continue;
            }
            return Ok(true);
        }
    }
    Ok(false)
}

fn remove_done_lifecycle(handle: &LifecycleHandle) -> Result<(), String> {
    for name in [
        CLEANUP_REASON_FILE,
        RUNTIME_OWNER_FILE,
        HOST_OWNER_FILE,
        RECORD_FILE,
        OPERATION_LOCK_FILE,
        RECORD_LOCK_FILE,
    ] {
        match fs::remove_file(handle.directory.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("remove completed lifecycle {name}: {error}")),
        }
    }
    fs::remove_dir(&handle.directory).map_err(|error| {
        format!(
            "remove completed lifecycle {}: {error}",
            handle.directory.display()
        )
    })?;
    sync_directory(handle.directory.parent().unwrap())
}

fn cleanup_queue_root() -> Result<PathBuf, String> {
    let root = std::env::var_os(CLEANUP_QUEUE_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CLEANUP_QUEUE_ROOT));
    if !root.is_absolute() {
        return Err(format!("{CLEANUP_QUEUE_ROOT_ENV} must be absolute"));
    }
    Ok(root)
}

fn phase_rank(phase: LifecyclePhase) -> u8 {
    match phase {
        LifecyclePhase::Prepared => 0,
        LifecyclePhase::ServerIdentified => 1,
        LifecyclePhase::SocketReady => 2,
        LifecyclePhase::TakeoverClaimed => 3,
        LifecyclePhase::ContainerdCommitted => 4,
        LifecyclePhase::CleanupRequired => 5,
        LifecyclePhase::CleanupOwnersDurable => 6,
        LifecyclePhase::ServerStopped => 7,
        LifecyclePhase::Done => 8,
    }
}

fn load_spec(bundle: &Path) -> Result<Spec, String> {
    let path = bundle.join("config.json");
    let data = fs::read(&path)
        .map_err(|error| format!("read sandbox OCI spec {}: {error}", path.display()))?;
    serde_json::from_slice(&data)
        .map_err(|error| format!("decode sandbox OCI spec {}: {error}", path.display()))
}

fn validate_takeover_bundle_identity(
    record: &LifecycleRecord,
    bundle: &Path,
) -> Result<PathBuf, String> {
    let bundle = fs::canonicalize(bundle)
        .map_err(|error| format!("canonicalize takeover bundle {}: {error}", bundle.display()))?;
    if file_identity(&bundle)? != record.bundle_identity
        || bundle.display().to_string() != record.bundle
    {
        return Err("takeover bundle identity does not match PREPARED".to_string());
    }
    Ok(bundle)
}

fn takeover_cgroup_allowed(record: &LifecycleRecord, cgroup: &str) -> bool {
    let original = record.helper.cgroup.as_str();
    match record.classification {
        Classification::ManagedSandbox => cgroup == original || cgroup == record.target.cgroup(),
        Classification::LegacyTask | Classification::Pending => cgroup == original,
    }
}

fn target_from_cri_parent(parent: &str, instance_id: &str) -> Result<HostTarget, String> {
    validate_containerd_id(instance_id)?;
    let target = target_path_from_cri_parent(parent, instance_id)?;
    parse_host_target(&target, instance_id)
}

fn target_path_from_cri_parent(parent: &str, instance_id: &str) -> Result<PathBuf, String> {
    let canonical_parent = canonical_cri_cgroup_parent(parent)?;
    let parent_path = Path::new(&canonical_parent);
    let basename = parent_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| format!("CRI cgroup_parent has no UTF-8 basename: {canonical_parent}"))?;

    // Kubelet/containerd may encode a systemd parent either as the slice unit
    // name or as its expanded cgroup-v2 path.  The latter is what CRI v1.36
    // sends on the target node.  Re-expanding the basename proves the absolute
    // path is exactly that slice hierarchy before selecting a transient scope.
    if basename.ends_with(".slice") {
        let expanded = expand_slice(basename)
            .map_err(|error| format!("expand CRI systemd parent {basename}: {error}"))?;
        if canonical_parent != format!("/{expanded}") {
            return Err(format!(
                "CRI systemd parent path does not match slice {basename}: {canonical_parent}"
            ));
        }
        return Ok(PathBuf::from(format!(
            "{basename}:cri-containerd:{instance_id}"
        )));
    }

    Ok(parent_path.join(instance_id))
}

fn classify_and_target(
    spec: &Spec,
    params: &BootstrapParams,
    original_cgroup: &str,
) -> Result<(Classification, HostTarget), String> {
    let annotations = spec.annotations().as_ref();
    let container_type = annotations.and_then(|values| values.get(CONTAINER_TYPE_ANNOTATION));
    let sandbox_id = annotations.and_then(|values| values.get(SANDBOX_ID_ANNOTATION));
    match (container_type.map(String::as_str), sandbox_id) {
        (Some("sandbox"), Some(sandbox_id)) => {
            if params.namespace != "k8s.io" {
                return Err("managed sandbox requires bootstrap namespace k8s.io".to_string());
            }
            if sandbox_id != &params.instance_id {
                return Err(format!(
                    "sandbox annotation id {sandbox_id} does not match bootstrap {}",
                    params.instance_id
                ));
            }
            validate_containerd_id(sandbox_id)?;
            let cgroups_path = spec
                .linux()
                .as_ref()
                .and_then(|linux| linux.cgroups_path().as_ref())
                .ok_or_else(|| "managed sandbox OCI spec has no linux.cgroupsPath".to_string())?;
            let target = parse_host_target(cgroups_path, &params.instance_id)?;
            Ok((Classification::ManagedSandbox, target))
        }
        (Some("container"), Some(sandbox_id)) => {
            if params.namespace != "k8s.io" {
                return Err("CRI container requires bootstrap namespace k8s.io".to_string());
            }
            validate_containerd_id(sandbox_id)?;
            Ok((
                Classification::LegacyTask,
                HostTarget::Legacy {
                    cgroup: original_cgroup.to_string(),
                },
            ))
        }
        (None, None) => Ok((
            Classification::LegacyTask,
            HostTarget::Legacy {
                cgroup: original_cgroup.to_string(),
            },
        )),
        (Some(other), Some(_)) => Err(format!("unsupported CRI container type {other}")),
        _ => Err("CRI classification annotations must be both present or both absent".to_string()),
    }
}

fn validate_containerd_id(value: &str) -> Result<(), String> {
    Utils::validate_sandbox_id(value)
}

fn parse_host_target(path: &Path, instance_id: &str) -> Result<HostTarget, String> {
    validate_unified_cgroup_mount()?;
    let text = path
        .to_str()
        .ok_or_else(|| "OCI cgroupsPath is not UTF-8".to_string())?;
    if text.contains(':') {
        let (slice, unit) = parse_systemd_target_components(text, instance_id)?;
        let expanded = expand_slice(&slice)
            .map_err(|error| format!("expand systemd slice {slice}: {error}"))?;
        let cgroup = format!("/{expanded}/{unit}");
        let parent_identity = validate_cgroup_parent(&cgroup)?;
        let leaf_path = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
        let leaf_identity = leaf_path
            .exists()
            .then(|| file_identity(&leaf_path))
            .transpose()?;
        return Ok(HostTarget::Systemd {
            oci_path: text.to_string(),
            slice,
            unit,
            cgroup,
            parent_identity,
            leaf_identity,
        });
    }

    let relative = normalized_cgroup_relative(path)?;
    if relative.file_name() != Some(OsStr::new(instance_id)) {
        return Err(format!(
            "cgroupfs leaf {} does not match sandbox {instance_id}",
            relative.display()
        ));
    }
    let cgroup = format!("/{}", relative.display());
    let parent_identity = validate_cgroup_parent(&cgroup)?;
    let leaf_path = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
    let leaf_identity = leaf_path
        .exists()
        .then(|| file_identity(&leaf_path))
        .transpose()?;
    Ok(HostTarget::Cgroupfs {
        oci_path: text.to_string(),
        cgroup,
        parent_identity,
        leaf_identity,
    })
}

fn parse_systemd_target_components(
    path: &str,
    instance_id: &str,
) -> Result<(String, String), String> {
    let parts: Vec<_> = path.split(':').collect();
    if parts.len() != 3
        || parts[0].is_empty()
        || parts[1] != "cri-containerd"
        || parts[2] != instance_id
    {
        return Err(format!("invalid managed systemd cgroupsPath {path}"));
    }
    Ok((
        parts[0].to_string(),
        format!("cri-containerd-{instance_id}.scope"),
    ))
}

fn validate_unified_cgroup_mount() -> Result<(), String> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("read cgroup mountinfo: {error}"))?;
    validate_unified_cgroup_mountinfo(&mountinfo)
}

fn validate_unified_cgroup_mountinfo(mountinfo: &str) -> Result<(), String> {
    let mut cgroup2_mounts = Vec::new();
    for line in mountinfo.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            return Err("malformed /proc/self/mountinfo entry".to_string());
        };
        let Some(file_system) = after.split_whitespace().next() else {
            return Err("mountinfo entry has no filesystem type".to_string());
        };
        if file_system != "cgroup2" {
            continue;
        }
        let fields: Vec<_> = before.split_whitespace().collect();
        let hierarchy = fields
            .get(2)
            .ok_or_else(|| "cgroup2 mountinfo entry has no major:minor".to_string())?;
        let mountpoint = fields
            .get(4)
            .ok_or_else(|| "cgroup2 mountinfo entry has no mountpoint".to_string())?;
        cgroup2_mounts.push((hierarchy.to_string(), mountpoint.to_string()));
    }
    let primary: Vec<_> = cgroup2_mounts
        .iter()
        .filter(|(_, mountpoint)| mountpoint == "/sys/fs/cgroup")
        .collect();
    if primary.len() != 1 {
        return Err(format!(
            "require exactly one primary cgroup-v2 mount at /sys/fs/cgroup, found {cgroup2_mounts:?}"
        ));
    }
    let hierarchy = &primary[0].0;
    if cgroup2_mounts
        .iter()
        .any(|(candidate, _)| candidate != hierarchy)
    {
        return Err(format!(
            "multiple cgroup-v2 hierarchies are visible, found {cgroup2_mounts:?}"
        ));
    }
    // Cilium and similar node agents may bind-mount the same hierarchy at an
    // additional path.  The major:minor identity proves it is an alias, not a
    // second controller hierarchy; Cube still performs every operation only
    // through the canonical /sys/fs/cgroup mount.
    Ok(())
}

fn canonical_cri_cgroup_parent(parent: &str) -> Result<String, String> {
    let parent = parent.trim();
    if parent.is_empty() {
        return Err("managed CRI cgroup_parent is empty".to_string());
    }
    if parent.contains(':') {
        return Err(format!("CRI cgroup_parent is not a parent path: {parent}"));
    }
    if !parent.contains('/') && parent.ends_with(".slice") {
        let expanded = expand_slice(parent)
            .map_err(|error| format!("expand CRI systemd parent {parent}: {error}"))?;
        return Ok(format!("/{expanded}"));
    }
    let relative = normalized_cgroup_relative(Path::new(parent))?;
    Ok(format!("/{}", relative.display()))
}

fn normalized_cgroup_relative(path: &Path) -> Result<PathBuf, String> {
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => relative.push(value),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(format!("invalid cgroupfs path {}", path.display()))
            }
        }
    }
    if relative.as_os_str().is_empty() {
        return Err("cgroupfs path cannot be root".to_string());
    }
    Ok(relative)
}

fn validate_cgroup_parent(cgroup: &str) -> Result<FileIdentity, String> {
    validate_unified_cgroup_mount()?;
    let relative = cgroup.trim_start_matches('/');
    let parent = Path::new("/sys/fs/cgroup")
        .join(relative)
        .parent()
        .ok_or_else(|| format!("cgroup path has no parent: {cgroup}"))?
        .to_path_buf();
    let canonical = fs::canonicalize(&parent)
        .map_err(|error| format!("canonicalize cgroup parent {}: {error}", parent.display()))?;
    if !canonical.starts_with("/sys/fs/cgroup")
        || canonical == Path::new("/sys/fs/cgroup")
        || canonical != parent
    {
        return Err(format!(
            "managed cgroup parent escapes delegated hierarchy: {}",
            canonical.display()
        ));
    }
    file_identity(&canonical)
}

fn create_and_join_target(
    target: &HostTarget,
    pid: i32,
    trace_sandbox_id: Option<&str>,
) -> Result<(), String> {
    match target {
        HostTarget::Systemd { slice, unit, .. } => {
            let sandbox_id = trace_sandbox_id.unwrap_or("host-probe");
            let mut properties = PropertiesBuilder::default_cgroup(slice, unit)
                .pids(vec![pid as u32])
                .build();
            properties.push(("CollectMode", ZbusValue::Str("inactive-or-failed".into())));
            let client = SystemdClient::new(unit, properties)
                .map_err(|error| format!("construct systemd scope {unit}: {error}"))?;
            let phase_started = Instant::now();
            let exists = client.exists();
            crate::cube_perf!(
                "cube_perf component=shim operation=create phase=systemd-exists sandbox_id={} operation_id={} unit={} target_pid={} ts_mono_us={} duration_us={} exists={}",
                sandbox_id,
                sandbox_id,
                unit,
                pid,
                Utils::monotonic_time_micros(),
                phase_started.elapsed().as_micros(),
                exists
            );
            if exists {
                return Err(format!("refuse to reuse existing systemd scope {unit}"));
            }
            let phase_started = Instant::now();
            let result = client
                .start()
                .map_err(|error| format!("start systemd scope {unit}: {error}"));
            crate::cube_perf!(
                "cube_perf component=shim operation=create phase=systemd-start-transient sandbox_id={} operation_id={} unit={} target_pid={} ts_mono_us={} duration_us={} success={}",
                sandbox_id,
                sandbox_id,
                unit,
                pid,
                Utils::monotonic_time_micros(),
                phase_started.elapsed().as_micros(),
                result.is_ok()
            );
            result?;
            verify_systemd_placement(target, pid, trace_sandbox_id)
        }
        HostTarget::Cgroupfs { cgroup, .. } => {
            let path = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
            fs::create_dir(&path)
                .map_err(|error| format!("create cgroupfs leaf {}: {error}", path.display()))?;
            // cgroup2 is a kernel control filesystem, not durable storage.
            // fsync(2) on its directories returns EINVAL on the target Linux
            // 6.6 node.  Durability comes from the owner INTENT written before
            // this mutation; identity and membership are read back below.
            move_process_to(cgroup, pid)
        }
        HostTarget::Pending { .. } | HostTarget::Legacy { .. } => Ok(()),
    }
}

fn verify_target_membership(target: &HostTarget, pid: i32) -> Result<(), String> {
    // The systemd target receives the expensive stability gate exactly once,
    // immediately after StartTransientUnit.  Every later lifecycle operation
    // is fenced by the persisted parent/leaf inode identities and an exact
    // /proc cgroup membership check, so it does not need to spawn systemctl.
    verify_live_target_identity(target)?;
    let actual = current_process_cgroup(pid)?;
    if actual != target.cgroup() {
        return Err(format!(
            "process {pid} is in {actual}, expected {}",
            target.cgroup()
        ));
    }
    Ok(())
}

fn verify_live_target_identity(target: &HostTarget) -> Result<(), String> {
    let Some(parent_identity) = target.parent_identity() else {
        return Ok(());
    };
    let path = Path::new("/sys/fs/cgroup").join(target.cgroup().trim_start_matches('/'));
    let parent = path
        .parent()
        .ok_or_else(|| format!("Host target has no parent: {}", path.display()))?;
    if file_identity(parent)? != *parent_identity {
        return Err(format!(
            "Host target parent identity changed: {}",
            parent.display()
        ));
    }
    if let Some(leaf_identity) = target.leaf_identity() {
        if file_identity(&path)? != *leaf_identity {
            return Err(format!(
                "Host target leaf identity changed: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn verify_systemd_placement(
    target: &HostTarget,
    pid: i32,
    trace_sandbox_id: Option<&str>,
) -> Result<(), String> {
    let HostTarget::Systemd { cgroup, .. } = target else {
        return Err("systemd verification called for non-systemd target".to_string());
    };
    let path = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
    let parent = path
        .parent()
        .ok_or_else(|| format!("systemd target has no parent: {}", path.display()))?;
    let expected_parent = target
        .parent_identity()
        .ok_or_else(|| "systemd target has no durable parent identity".to_string())?;
    let sandbox_id = trace_sandbox_id.unwrap_or("host-probe");
    // StartTransientUnit returns after systemd has accepted the job.  Wait for
    // the kernel-visible cgroup placement, then prove that the same parent,
    // leaf, and process membership remain stable before persisting the leaf.
    let readiness_started = Instant::now();
    let mut leaf_identity = None;
    for _ in 0..200 {
        if path.exists()
            && current_process_cgroup(pid).ok().as_deref() == Some(cgroup.as_str())
            && file_identity(parent).ok().as_ref() == Some(expected_parent)
        {
            leaf_identity = Some(file_identity(&path)?);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let leaf_identity = leaf_identity.ok_or_else(|| {
        format!(
            "systemd placement did not create {} with process {pid}",
            path.display()
        )
    })?;
    crate::cube_perf!(
        "cube_perf component=shim operation=create phase=systemd-placement-ready sandbox_id={} operation_id={} target_pid={} ts_mono_us={} duration_us={} success=true",
        sandbox_id,
        sandbox_id,
        pid,
        Utils::monotonic_time_micros(),
        readiness_started.elapsed().as_micros()
    );
    // The readiness loop above is the event gate: it observes the leaf, the
    // exact parent identity, and PID membership together. Re-read all three
    // once after capturing the leaf inode. Fixed time samples cannot prove
    // stronger ownership than this identity-bound readback and added 80 ms
    // to every Pod. Durable ALLOCATED/CONTAINERD_COMMITTED publication later
    // performs another exact membership check.
    let stability_started = Instant::now();
    let actual = current_process_cgroup(pid)?;
    if file_identity(parent)? != *expected_parent
        || file_identity(&path)? != leaf_identity
        || actual != *cgroup
    {
        return Err(format!(
            "systemd placement gate failed for pid {pid}: cgroup={actual} expected={cgroup}"
        ));
    }
    crate::cube_perf!(
        "cube_perf component=shim operation=create phase=systemd-stability-gate sandbox_id={} operation_id={} target_pid={} samples=2 strategy=event-exact-readback ts_mono_us={} duration_us={} success=true",
        sandbox_id,
        sandbox_id,
        pid,
        Utils::monotonic_time_micros(),
        stability_started.elapsed().as_micros()
    );
    Ok(())
}

fn systemd_properties(unit: &str) -> Result<HashMap<String, String>, String> {
    let output = Command::new("systemctl")
        .args([
            "show",
            unit,
            "--property=Job",
            "--property=ActiveState",
            "--property=SubState",
            "--property=ControlGroup",
            "--property=MainPID",
        ])
        .output()
        .map_err(|error| format!("query systemd unit {unit}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "query systemd unit {unit} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut values = HashMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.to_string(), value.to_string());
        }
    }
    Ok(values)
}

fn verify_watchdog_service() -> Result<(), String> {
    const WATCHDOG_CGROUP: &str = "/system.slice/cubesandbox-shim-watchdog.service";
    let expected_binary = Path::new(WATCHDOG_BINARY);
    let expected_executable = file_identity(expected_binary)?;
    let expected_argv = vec![
        WATCHDOG_BINARY.to_string(),
        "-namespace".to_string(),
        "cube-watchdog".to_string(),
        "-id".to_string(),
        "node".to_string(),
        WATCHDOG_ACTION.to_string(),
    ];
    let expected_command = command_sha256(&expected_argv);
    let cgroup_procs = Path::new("/sys/fs/cgroup")
        .join(WATCHDOG_CGROUP.trim_start_matches('/'))
        .join("cgroup.procs");
    // The watchdog's cgroup and immutable process identity are the authority;
    // consulting systemctl here would put a CLI fork on every Pod start.
    let mut candidates = Vec::new();
    for line in fs::read_to_string(&cgroup_procs)
        .map_err(|error| format!("read {}: {error}", cgroup_procs.display()))?
        .lines()
    {
        let pid = line
            .parse::<i32>()
            .map_err(|error| format!("parse watchdog cgroup pid {line:?}: {error}"))?;
        let Ok(identity) = process_identity(pid) else {
            continue;
        };
        if identity.cgroup == WATCHDOG_CGROUP
            && identity.executable == expected_executable
            && identity.command_sha256 == expected_command
        {
            candidates.push(identity);
        }
    }
    if candidates.len() != 1 {
        return Err(format!(
            "{WATCHDOG_UNIT} expected one exact process in {WATCHDOG_CGROUP}, found {}",
            candidates.len()
        ));
    }
    let watchdog = candidates.remove(0);
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| format!("read boot id for watchdog verification: {error}"))?;
    if watchdog.boot_id != boot_id.trim() || watchdog.start_time_ticks == 0 {
        return Err(format!(
            "{WATCHDOG_UNIT} boot/starttime identity is invalid"
        ));
    }
    let stamp: WatchdogProbeStamp = read_json(Path::new(WATCHDOG_PROBE_STAMP))?;
    let binary_sha256 = sha256_file(expected_binary)?;
    let current_sha256 = sha256_file(Path::new("/proc/self/exe"))?;
    if stamp.schema_version != SCHEMA_VERSION
        || stamp.boot_id != boot_id.trim()
        || stamp.binary_path != WATCHDOG_BINARY
        || stamp.binary_identity != expected_executable
        || stamp.binary_sha256 != binary_sha256
        || current_sha256 != binary_sha256
        || stamp.iterations != 200
        || stamp.completed_at_ms == 0
    {
        return Err(format!(
            "{WATCHDOG_UNIT} probe stamp does not match this boot and build"
        ));
    }
    Ok(())
}

fn move_process_to(cgroup: &str, pid: i32) -> Result<(), String> {
    let path = Path::new("/sys/fs/cgroup")
        .join(cgroup.trim_start_matches('/'))
        .join("cgroup.procs");
    fs::write(&path, pid.to_string())
        .map_err(|error| format!("move pid {pid} through {}: {error}", path.display()))?;
    let actual = current_process_cgroup(pid)?;
    if actual != cgroup {
        return Err(format!("pid {pid} moved to {actual}, expected {cgroup}"));
    }
    Ok(())
}

fn process_identity(pid: i32) -> Result<ProcessIdentity, String> {
    capture_process_identity(pid, None)
}

fn server_process_identity(pid: i32) -> Result<ProcessIdentity, String> {
    let nonce_hash = process_launch_nonce_hash(pid)?
        .ok_or_else(|| format!("server process {pid} has no {LAUNCH_NONCE_ENV}"))?;
    capture_process_identity(pid, Some(nonce_hash))
}

#[cfg(not(test))]
fn current_claim_server_identity() -> Result<ProcessIdentity, String> {
    server_process_identity(std::process::id() as i32)
}

#[cfg(test)]
fn current_claim_server_identity() -> Result<ProcessIdentity, String> {
    // Unit tests run inside Cargo's harness rather than the exec'd shim
    // server. Production builds always require the launch nonce above.
    process_identity(std::process::id() as i32)
}

fn process_identity_for_expected(expected: &ProcessIdentity) -> Result<ProcessIdentity, String> {
    if expected.launch_nonce_sha256.is_some() {
        server_process_identity(expected.pid)
    } else {
        process_identity(expected.pid)
    }
}

fn capture_process_identity(
    pid: i32,
    nonce_hash: Option<String>,
) -> Result<ProcessIdentity, String> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let stat = fs::read_to_string(proc.join("stat"))
        .map_err(|error| format!("read process {pid} stat: {error}"))?;
    let end = stat
        .rfind(')')
        .ok_or_else(|| format!("process {pid} stat has no command terminator"))?;
    let fields: Vec<_> = stat[end + 1..].split_whitespace().collect();
    let start_time_ticks = fields
        .get(19)
        .ok_or_else(|| format!("process {pid} stat has no starttime"))?
        .parse()
        .map_err(|error| format!("parse process {pid} starttime: {error}"))?;
    let command = fs::read(proc.join("cmdline"))
        .map_err(|error| format!("read process {pid} cmdline: {error}"))?;
    Ok(ProcessIdentity {
        pid,
        boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| format!("read boot id: {error}"))?
            .trim()
            .to_string(),
        start_time_ticks,
        executable: file_identity(&proc.join("exe"))?,
        command_sha256: sha256_hex(&command),
        cwd: file_identity(&proc.join("cwd"))?,
        cgroup: current_process_cgroup(pid)?,
        launch_nonce_sha256: nonce_hash,
    })
}

fn immutable_identity_matches(expected: &ProcessIdentity, actual: &ProcessIdentity) -> bool {
    expected.pid == actual.pid
        && expected.boot_id == actual.boot_id
        && expected.start_time_ticks == actual.start_time_ticks
        && expected.executable == actual.executable
        && expected.command_sha256 == actual.command_sha256
        && expected.cwd == actual.cwd
        && expected.launch_nonce_sha256 == actual.launch_nonce_sha256
}

fn current_process_cgroup(pid: i32) -> Result<String, String> {
    let data = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|error| format!("read process {pid} cgroup: {error}"))?;
    let mut unified = data.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = unified
        .next()
        .ok_or_else(|| format!("process {pid} has no unified cgroup"))?;
    if unified.next().is_some() || !value.starts_with('/') {
        return Err(format!("process {pid} has invalid unified cgroup data"));
    }
    Ok(value.to_string())
}

fn containment_identity(cgroup: &str) -> Result<ContainmentIdentity, String> {
    if !cgroup.starts_with('/') {
        return Err(format!("observed cgroup is not absolute: {cgroup}"));
    }
    let path = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
    match fs::symlink_metadata(&path) {
        Ok(metadata) => Ok(ContainmentIdentity {
            cgroup: cgroup.to_string(),
            device: Some(metadata.dev()),
            inode: Some(metadata.ino()),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ContainmentIdentity {
            cgroup: cgroup.to_string(),
            device: None,
            inode: None,
        }),
        Err(error) => Err(format!(
            "capture observed cgroup identity {}: {error}",
            path.display()
        )),
    }
}

fn create_gate() -> Result<(OwnedFd, OwnedFd), String> {
    let mut descriptors = [0_i32; 2];
    // SAFETY: descriptors points to two writable integers for pipe2(2).
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!(
            "create bootstrap gate: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Only the read side crosses exec.  The write side must stay CLOEXEC so a
    // helper crash produces EOF instead of leaving the server holding its own
    // gate open forever.
    if unsafe { libc::fcntl(descriptors[0], libc::F_SETFD, 0) } < 0 {
        let error = std::io::Error::last_os_error();
        // SAFETY: both descriptors were created above and are still owned here.
        unsafe {
            libc::close(descriptors[0]);
            libc::close(descriptors[1]);
        }
        return Err(format!(
            "make bootstrap gate read side inheritable: {error}"
        ));
    }
    // SAFETY: pipe returned two new owned descriptors.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

fn random_nonce() -> Result<Vec<u8>, String> {
    let mut nonce = vec![0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut nonce))
        .map_err(|error| format!("read launch nonce: {error}"))?;
    Ok(nonce)
}

fn lifecycle_root() -> Result<PathBuf, String> {
    let root = std::env::var_os(LIFECYCLE_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LIFECYCLE_ROOT));
    if !root.is_absolute() {
        return Err(format!(
            "{LIFECYCLE_ROOT_ENV} must be absolute: {}",
            root.display()
        ));
    }
    Ok(root)
}

fn lifecycle_key(namespace: &str, id: &str, bundle: &Path, identity: &FileIdentity) -> String {
    let mut hasher = Sha256::new();
    for value in [
        namespace.as_bytes(),
        id.as_bytes(),
        bundle.as_os_str().as_encoded_bytes(),
        &identity.device.to_be_bytes(),
        &identity.inode.to_be_bytes(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("{:x}", hasher.finalize())
}

pub(crate) fn unix_socket_path(address: &str) -> Result<PathBuf, String> {
    let path = address
        .strip_prefix("unix://")
        .ok_or_else(|| format!("only unix shim sockets are supported: {address}"))?;
    canonical_socket_path(Path::new(path))
}

fn canonical_socket_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!(
            "shim socket path must be absolute: {}",
            path.display()
        ));
    }
    let name = path.file_name().ok_or_else(|| {
        format!(
            "shim socket path must contain a normal basename: {}",
            path.display()
        )
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("shim socket has no parent: {}", path.display()))?;
    let canonical_parent = fs::canonicalize(parent).map_err(|error| {
        format!(
            "canonicalize shim socket parent {}: {error}",
            parent.display()
        )
    })?;
    let canonical = canonical_parent.join(name);
    // A single canonical spelling is the ownership key. Reject rather than
    // normalize aliases so the address sent to the child, lifecycle record,
    // owner scan, path lock and cleanup can never diverge.
    if canonical.as_os_str() != path.as_os_str() {
        return Err(format!(
            "shim socket path must use its canonical parent without '.', '..', duplicate separators, or symlink aliases: {} (canonical {})",
            path.display(),
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn file_identity(path: &Path) -> Result<FileIdentity, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("stat identity {}: {error}", path.display()))?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn ensure_directory(path: &Path) -> Result<(), String> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => return sync_directory(path),
        Ok(_) => return Err(format!("path is not a directory: {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("stat directory {}: {error}", path.display())),
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("directory has no parent: {}", path.display()))?;
    ensure_directory(parent)?;
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !fs::metadata(path)
                .map_err(|error| format!("stat raced directory {}: {error}", path.display()))?
                .is_dir()
            {
                return Err(format!("path is not a directory: {}", path.display()));
            }
        }
        Err(error) => {
            return Err(format!("create directory {}: {error}", path.display()));
        }
    }
    sync_directory(parent)?;
    sync_directory(path)
}

fn sync_directory(path: &Path) -> Result<(), String> {
    let started = Instant::now();
    let result = File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync directory {}: {error}", path.display()));
    crate::cube_perf!(
        "cube_perf component=shim operation=persist phase=directory-fsync target={} ts_mono_us={} duration_us={} success={}",
        path.display(),
        Utils::monotonic_time_micros(),
        started.elapsed().as_micros(),
        result.is_ok()
    );
    result
}

fn atomic_write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let started = Instant::now();
    let parent = path
        .parent()
        .ok_or_else(|| format!("record has no parent: {}", path.display()))?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name().and_then(OsStr::to_str).unwrap_or("record"),
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let data = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("encode record {}: {error}", path.display()))?;
    if take_atomic_write_failpoint(path, "temp") {
        return Err(format!(
            "injected failure before temporary record creation: {}",
            path.display()
        ));
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("create temporary record {}: {error}", temporary.display()))?;
    if let Err(error) = file.write_all(&data) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("persist record {}: {error}", temporary.display()));
    }
    if take_atomic_write_failpoint(path, "file-fsync") {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "injected failure before record fsync: {}",
            path.display()
        ));
    }
    if let Err(error) = file.sync_all() {
        let _ = fs::remove_file(&temporary);
        return Err(format!("persist record {}: {error}", temporary.display()));
    }
    if take_atomic_write_failpoint(path, "rename") {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "injected failure before record rename: {}",
            path.display()
        ));
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("commit record {}: {error}", path.display()));
    }
    if take_atomic_write_failpoint(path, "parent-fsync") {
        return Err(format!(
            "injected failure before record parent fsync: {}",
            path.display()
        ));
    }
    let result = sync_directory(parent);
    crate::cube_perf!(
        "cube_perf component=shim operation=persist phase=atomic-write-json target={} ts_mono_us={} duration_us={} success={}",
        path.display(),
        Utils::monotonic_time_micros(),
        started.elapsed().as_micros(),
        result.is_ok()
    );
    result
}

#[cfg(test)]
fn atomic_write_failpoint_path(path: &Path, stage: &str) -> PathBuf {
    path.parent().unwrap().join(format!(
        ".{}.fail-{stage}",
        path.file_name().and_then(OsStr::to_str).unwrap_or("record")
    ))
}

#[cfg(test)]
fn take_atomic_write_failpoint(path: &Path, stage: &str) -> bool {
    fs::remove_file(atomic_write_failpoint_path(path, stage)).is_ok()
}

#[cfg(not(test))]
fn take_atomic_write_failpoint(_path: &Path, _stage: &str) -> bool {
    false
}

fn atomic_write_bytes(path: &Path, data: &[u8]) -> Result<(), String> {
    let started = Instant::now();
    let parent = path
        .parent()
        .ok_or_else(|| format!("record has no parent: {}", path.display()))?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name().and_then(OsStr::to_str).unwrap_or("record"),
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("create temporary record {}: {error}", temporary.display()))?;
    if let Err(error) = file.write_all(data).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("persist record {}: {error}", temporary.display()));
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("commit record {}: {error}", path.display()));
    }
    let result = sync_directory(parent);
    crate::cube_perf!(
        "cube_perf component=shim operation=persist phase=atomic-write-bytes target={} ts_mono_us={} duration_us={} success={}",
        path.display(),
        Utils::monotonic_time_micros(),
        started.elapsed().as_micros(),
        result.is_ok()
    );
    result
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let data =
        fs::read(path).map_err(|error| format!("read record {}: {error}", path.display()))?;
    serde_json::from_slice(&data)
        .map_err(|error| format!("decode record {}: {error}", path.display()))
}

fn unix_time_ms() -> Result<u128, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|error| format!("system clock is before UNIX epoch: {error}"))
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("open binary for SHA-256 {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("read binary for SHA-256 {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn expected_server_argv(
    params: &BootstrapParams,
    address: &str,
    executable: &Path,
    debug: bool,
) -> Result<Vec<String>, String> {
    let executable = executable
        .to_str()
        .ok_or_else(|| "CubeShim executable path is not UTF-8".to_string())?;
    let mut argv = vec![
        executable.to_string(),
        "-namespace".to_string(),
        params.namespace.clone(),
        "-id".to_string(),
        params.instance_id.clone(),
        "-address".to_string(),
        params.containerd_grpc_address.clone(),
        "-socket".to_string(),
        address.to_string(),
    ];
    if debug {
        argv.push("-debug".to_string());
    }
    Ok(argv)
}

fn command_sha256(argv: &[String]) -> String {
    let mut command = Vec::new();
    for argument in argv {
        command.extend_from_slice(argument.as_bytes());
        command.push(0);
    }
    sha256_hex(&command)
}

fn bytes_hex(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len() * 2);
    for byte in data {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex launch nonce has odd length".to_string());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|error| format!("decode launch nonce: {error}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{LinuxBuilder, SpecBuilder};
    use std::os::unix::net::UnixListener;
    use std::process::Command as ProcessCommand;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;

    fn params(namespace: &str, id: &str) -> BootstrapParams {
        BootstrapParams {
            instance_id: id.to_string(),
            namespace: namespace.to_string(),
            containerd_ttrpc_address: "/run/containerd/containerd.sock.ttrpc".to_string(),
            containerd_grpc_address: "/run/containerd/containerd.sock".to_string(),
            ..Default::default()
        }
    }

    fn spec(annotations: HashMap<String, String>, cgroup: Option<&str>) -> Spec {
        let linux = match cgroup {
            Some(cgroup) => LinuxBuilder::default()
                .cgroups_path(PathBuf::from(cgroup))
                .build()
                .unwrap(),
            None => LinuxBuilder::default().build().unwrap(),
        };
        SpecBuilder::default()
            .annotations(annotations)
            .linux(linux)
            .build()
            .unwrap()
    }

    fn controller_fixture() -> (PathBuf, ControllerJournal) {
        let root =
            std::env::temp_dir().join(format!("cube-host-controller-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        for (file, value) in [
            ("memory.oom.group", "0"),
            ("pids.max", "max"),
            ("memory.max", "max"),
            ("cpu.max", "max 100000"),
            ("pids.current", "1"),
            ("memory.current", "4096"),
        ] {
            fs::write(root.join(file), value).unwrap();
        }
        let identity = process_identity(std::process::id() as i32).unwrap();
        let journal = ControllerJournal {
            schema_version: 1,
            transaction_id: uuid::Uuid::new_v4().to_string(),
            owner_epoch: 2,
            owner_identity: identity,
            create_fingerprint: "fingerprint".to_string(),
            state: ControllerTransactionState::Prepared,
            steps: vec![
                ControllerStep {
                    file: "memory.oom.group".to_string(),
                    old: "0".to_string(),
                    target: "1".to_string(),
                    state: ControllerStepState::NotStarted,
                    observed: None,
                },
                ControllerStep {
                    file: "pids.max".to_string(),
                    old: "max".to_string(),
                    target: "512".to_string(),
                    state: ControllerStepState::NotStarted,
                    observed: None,
                },
                ControllerStep {
                    file: "memory.max".to_string(),
                    old: "max".to_string(),
                    target: "536870912".to_string(),
                    state: ControllerStepState::NotStarted,
                    observed: None,
                },
                ControllerStep {
                    file: "cpu.max".to_string(),
                    old: "max 100000".to_string(),
                    target: "125000 100000".to_string(),
                    state: ControllerStepState::NotStarted,
                    observed: None,
                },
            ],
            degraded_reason: None,
        };
        (root, journal)
    }

    #[test]
    fn controller_preflight_and_canonical_values_are_strict() {
        let (root, journal) = controller_fixture();
        preflight_controller_targets(&root, &journal.steps).unwrap();
        assert_eq!(
            canonical_controller_value("cpu.max", "125000  100000\n").unwrap(),
            "125000 100000"
        );
        assert!(canonical_controller_value("cpu.max", "125000").is_err());
        assert!(canonical_controller_value("memory.oom.group", "2").is_err());
        assert!(canonical_controller_value(
            "pids.max",
            &(runtime_resource::LINUX_PIDS_MAX_LIMIT + 1).to_string()
        )
        .is_err());
        fs::write(root.join("pids.current"), "513").unwrap();
        assert!(preflight_controller_targets(&root, &journal.steps)
            .unwrap_err()
            .contains("pids.current"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn controller_preflight_rejects_invalid_pids_target_without_controller_writes() {
        let (root, mut journal) = controller_fixture();
        journal.steps[1].target = u64::MAX.to_string();
        let before = journal
            .steps
            .iter()
            .map(|step| {
                (
                    step.file.clone(),
                    fs::read_to_string(root.join(&step.file)).unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();

        assert!(preflight_controller_targets(&root, &journal.steps)
            .unwrap_err()
            .contains("exceeds Linux numeric limit"));
        for (file, expected) in before {
            assert_eq!(fs::read_to_string(root.join(file)).unwrap(), expected);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn controller_rollback_replays_reverse_order_with_durable_undo_intent() {
        let (root, mut journal) = controller_fixture();
        journal.state = ControllerTransactionState::ControllersCommitted;
        for step in &mut journal.steps {
            step.state = ControllerStepState::Applied;
            fs::write(root.join(&step.file), &step.target).unwrap();
        }
        let stored = Arc::new(std::sync::Mutex::new(journal));
        let observed = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        replay_controller_rollback(
            &root,
            {
                let stored = Arc::clone(&stored);
                move || Ok(stored.lock().unwrap().clone())
            },
            {
                let stored = Arc::clone(&stored);
                let observed = Arc::clone(&observed);
                move |updated| {
                    for step in &updated.steps {
                        if step.state == ControllerStepState::UndoIntent
                            && !observed.lock().unwrap().contains(&step.file)
                        {
                            observed.lock().unwrap().push(step.file.clone());
                        }
                    }
                    *stored.lock().unwrap() = updated.clone();
                    Ok(())
                }
            },
        )
        .unwrap();
        assert_eq!(
            *observed.lock().unwrap(),
            ["cpu.max", "memory.max", "pids.max", "memory.oom.group"]
        );
        let final_journal = stored.lock().unwrap().clone();
        assert_eq!(final_journal.state, ControllerTransactionState::Restored);
        exact_controller_readback(&root, &final_journal, false).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn controller_rollback_recovers_intent_readback_and_degrades_on_foreign_value() {
        for intent_value_is_target in [false, true] {
            let (root, mut journal) = controller_fixture();
            journal.state = ControllerTransactionState::Applying;
            journal.steps[0].state = ControllerStepState::Intent;
            let value = if intent_value_is_target {
                journal.steps[0].target.clone()
            } else {
                journal.steps[0].old.clone()
            };
            fs::write(root.join(&journal.steps[0].file), value).unwrap();
            let stored = Arc::new(std::sync::Mutex::new(journal));
            replay_controller_rollback(
                &root,
                {
                    let stored = Arc::clone(&stored);
                    move || Ok(stored.lock().unwrap().clone())
                },
                {
                    let stored = Arc::clone(&stored);
                    move |updated| {
                        *stored.lock().unwrap() = updated.clone();
                        Ok(())
                    }
                },
            )
            .unwrap();
            assert_eq!(
                stored.lock().unwrap().state,
                ControllerTransactionState::Restored
            );
            fs::remove_dir_all(root).unwrap();
        }

        let (root, mut journal) = controller_fixture();
        journal.state = ControllerTransactionState::Applying;
        journal.steps[2].state = ControllerStepState::Intent;
        fs::write(root.join("memory.max"), "123456").unwrap();
        let stored = Arc::new(std::sync::Mutex::new(journal));
        let error = replay_controller_rollback(
            &root,
            {
                let stored = Arc::clone(&stored);
                move || Ok(stored.lock().unwrap().clone())
            },
            {
                let stored = Arc::clone(&stored);
                move |updated| {
                    *stored.lock().unwrap() = updated.clone();
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert!(error.contains("neither old"));
        assert_eq!(
            stored.lock().unwrap().state,
            ControllerTransactionState::Degraded
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn controller_forward_journal_atomic_persistence_matrix_converges() {
        for persistence_index in 1..=9 {
            for stage in ["temp", "file-fsync", "rename", "parent-fsync"] {
                let (root, journal) = controller_fixture();
                let journal_path = root.join("controller-journal.json");
                atomic_write_json(&journal_path, &journal).unwrap();
                let mut persistence_count = 0;
                let error = replay_controller_forward_state(
                    &root,
                    || read_json(&journal_path),
                    |updated| {
                        persistence_count += 1;
                        if persistence_count == persistence_index {
                            fs::write(atomic_write_failpoint_path(&journal_path, stage), b"fail")
                                .unwrap();
                        }
                        atomic_write_json(&journal_path, updated)
                    },
                    || Ok(()),
                    |_| Ok(()),
                )
                .unwrap_err();
                assert!(
                    error.contains("injected failure"),
                    "{persistence_index}/{stage}: {error}"
                );

                replay_controller_forward_state(
                    &root,
                    || read_json(&journal_path),
                    |updated| atomic_write_json(&journal_path, updated),
                    || Ok(()),
                    |_| Ok(()),
                )
                .unwrap();
                let durable: ControllerJournal = read_json(&journal_path).unwrap();
                assert_eq!(
                    durable.state,
                    ControllerTransactionState::ControllersCommitted
                );
                exact_controller_readback(&root, &durable, true).unwrap();
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[test]
    fn controller_rollback_journal_atomic_persistence_matrix_converges() {
        for persistence_index in 1..=10 {
            for stage in ["temp", "file-fsync", "rename", "parent-fsync"] {
                let (root, mut journal) = controller_fixture();
                journal.state = ControllerTransactionState::ControllersCommitted;
                for step in &mut journal.steps {
                    step.state = ControllerStepState::Applied;
                    step.observed = Some(step.target.clone());
                    fs::write(root.join(&step.file), &step.target).unwrap();
                }
                let journal_path = root.join("controller-journal.json");
                atomic_write_json(&journal_path, &journal).unwrap();
                let mut persistence_count = 0;
                let error = replay_controller_rollback(
                    &root,
                    || read_json(&journal_path),
                    |updated| {
                        persistence_count += 1;
                        if persistence_count == persistence_index {
                            fs::write(atomic_write_failpoint_path(&journal_path, stage), b"fail")
                                .unwrap();
                        }
                        atomic_write_json(&journal_path, updated)
                    },
                )
                .unwrap_err();
                assert!(
                    error.contains("injected failure"),
                    "{persistence_index}/{stage}: {error}"
                );

                replay_controller_rollback(
                    &root,
                    || read_json(&journal_path),
                    |updated| atomic_write_json(&journal_path, updated),
                )
                .unwrap();
                let durable: ControllerJournal = read_json(&journal_path).unwrap();
                assert_eq!(durable.state, ControllerTransactionState::Restored);
                exact_controller_readback(&root, &durable, false).unwrap();
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[test]
    fn restored_embedded_controller_journal_removal_is_crash_recoverable() {
        #[derive(Deserialize, Eq, PartialEq, Serialize)]
        struct EmbeddedJournal {
            controllers: Option<ControllerJournal>,
        }

        for stage in ["temp", "file-fsync", "rename", "parent-fsync"] {
            let (root, mut journal) = controller_fixture();
            journal.state = ControllerTransactionState::Restored;
            for step in &mut journal.steps {
                step.state = ControllerStepState::Restored;
                step.observed = Some(step.old.clone());
            }
            let path = root.join("owner-with-embedded-journal.json");
            atomic_write_json(
                &path,
                &EmbeddedJournal {
                    controllers: Some(journal),
                },
            )
            .unwrap();

            let mut owner: EmbeddedJournal = read_json(&path).unwrap();
            clear_restored_controller_journal(&root, &mut owner.controllers).unwrap();
            fs::write(atomic_write_failpoint_path(&path, stage), b"fail").unwrap();
            assert!(atomic_write_json(&path, &owner).is_err());

            let mut recovered: EmbeddedJournal = read_json(&path).unwrap();
            clear_restored_controller_journal(&root, &mut recovered.controllers).unwrap();
            atomic_write_json(&path, &recovered).unwrap();
            let durable: EmbeddedJournal = read_json(&path).unwrap();
            assert!(durable.controllers.is_none());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn controller_forward_write_readback_and_step_crash_matrix_rolls_back() {
        let mut crash_points = vec!["after-prepared".to_string()];
        for file in ["memory.oom.group", "pids.max", "memory.max", "cpu.max"] {
            for boundary in [
                "before-write",
                "after-write",
                "before-readback",
                "after-readback",
                "after-applied",
            ] {
                crash_points.push(format!("{boundary}-{file}"));
            }
        }

        for crash_point in crash_points {
            let (root, journal) = controller_fixture();
            let stored = Arc::new(std::sync::Mutex::new(journal));
            if crash_point != "after-prepared" {
                let armed = std::cell::Cell::new(true);
                let error = replay_controller_forward_state(
                    &root,
                    {
                        let stored = Arc::clone(&stored);
                        move || Ok(stored.lock().unwrap().clone())
                    },
                    {
                        let stored = Arc::clone(&stored);
                        move |updated| {
                            *stored.lock().unwrap() = updated.clone();
                            Ok(())
                        }
                    },
                    || Ok(()),
                    |name| {
                        if armed.get() && name == crash_point {
                            armed.set(false);
                            Err(format!("injected crash at {name}"))
                        } else {
                            Ok(())
                        }
                    },
                )
                .unwrap_err();
                assert!(error.contains(&crash_point), "{crash_point}: {error}");
            }

            replay_controller_rollback(
                &root,
                {
                    let stored = Arc::clone(&stored);
                    move || Ok(stored.lock().unwrap().clone())
                },
                {
                    let stored = Arc::clone(&stored);
                    move |updated| {
                        *stored.lock().unwrap() = updated.clone();
                        Ok(())
                    }
                },
            )
            .unwrap();
            let durable = stored.lock().unwrap().clone();
            assert_eq!(durable.state, ControllerTransactionState::Restored);
            exact_controller_readback(&root, &durable, false).unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn controller_rollback_write_and_readback_crash_matrix_converges() {
        for file in ["memory.oom.group", "pids.max", "memory.max", "cpu.max"] {
            for boundary in [
                "before-rollback-write",
                "after-rollback-write",
                "before-rollback-readback",
                "after-rollback-readback",
            ] {
                let crash_point = format!("{boundary}-{file}");
                let (root, mut journal) = controller_fixture();
                journal.state = ControllerTransactionState::ControllersCommitted;
                for step in &mut journal.steps {
                    step.state = ControllerStepState::Applied;
                    step.observed = Some(step.target.clone());
                    fs::write(root.join(&step.file), &step.target).unwrap();
                }
                let stored = Arc::new(std::sync::Mutex::new(journal));
                let armed = std::cell::Cell::new(true);
                let error = replay_controller_rollback_with_failpoint(
                    &root,
                    {
                        let stored = Arc::clone(&stored);
                        move || Ok(stored.lock().unwrap().clone())
                    },
                    {
                        let stored = Arc::clone(&stored);
                        move |updated| {
                            *stored.lock().unwrap() = updated.clone();
                            Ok(())
                        }
                    },
                    || Ok(()),
                    |name| {
                        if armed.get() && name == crash_point {
                            armed.set(false);
                            Err(format!("injected crash at {name}"))
                        } else {
                            Ok(())
                        }
                    },
                )
                .unwrap_err();
                assert!(error.contains(&crash_point), "{crash_point}: {error}");

                replay_controller_rollback(
                    &root,
                    {
                        let stored = Arc::clone(&stored);
                        move || Ok(stored.lock().unwrap().clone())
                    },
                    {
                        let stored = Arc::clone(&stored);
                        move |updated| {
                            *stored.lock().unwrap() = updated.clone();
                            Ok(())
                        }
                    },
                )
                .unwrap();
                let durable = stored.lock().unwrap().clone();
                assert_eq!(durable.state, ControllerTransactionState::Restored);
                exact_controller_readback(&root, &durable, false).unwrap();
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[test]
    fn revoked_epoch_fences_controller_rollback_before_external_write() {
        let (root, mut journal) = controller_fixture();
        journal.state = ControllerTransactionState::ControllersCommitted;
        for step in &mut journal.steps {
            step.state = ControllerStepState::Applied;
            step.observed = Some(step.target.clone());
            fs::write(root.join(&step.file), &step.target).unwrap();
        }
        let expected = journal
            .steps
            .iter()
            .map(|step| (step.file.clone(), step.target.clone()))
            .collect::<Vec<_>>();
        let stored = Arc::new(std::sync::Mutex::new(journal));
        let error = replay_controller_rollback_with_failpoint(
            &root,
            {
                let stored = Arc::clone(&stored);
                move || Ok(stored.lock().unwrap().clone())
            },
            {
                let stored = Arc::clone(&stored);
                move |updated| {
                    *stored.lock().unwrap() = updated.clone();
                    Ok(())
                }
            },
            || Err("operation owner epoch was revoked".to_string()),
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(error.contains("epoch was revoked"));
        assert_eq!(
            stored.lock().unwrap().steps[3].state,
            ControllerStepState::UndoIntent
        );
        for (file, target) in expected {
            assert_eq!(read_controller_value(&root, &file).unwrap(), target);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_queue_unlink_crash_matrix_is_idempotent_and_fsyncs_retry() {
        for stage in ["before-unlink", "after-unlink"] {
            let root = std::env::temp_dir().join(format!(
                "cube-cleanup-unlink-{}-{}",
                stage,
                uuid::Uuid::new_v4()
            ));
            let directory = root.join(HOST_QUEUE_DIRECTORY);
            fs::create_dir_all(&directory).unwrap();
            let generation = "generation";
            let path = cleanup_queue_path(&root, HOST_QUEUE_DIRECTORY, generation);
            fs::write(&path, b"job").unwrap();
            fs::write(cleanup_unlink_failpoint_path(&path, stage), b"fail").unwrap();
            assert!(acknowledge_queue(&root, HOST_QUEUE_DIRECTORY, generation).is_err());
            assert_eq!(path.exists(), stage == "before-unlink");
            acknowledge_queue(&root, HOST_QUEUE_DIRECTORY, generation).unwrap();
            assert!(!path.exists());
            acknowledge_queue(&root, HOST_QUEUE_DIRECTORY, generation).unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn ensure_directory_accepts_concurrent_creators() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-directory-race-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let directory = root.join("shared");
        let barrier = Arc::new(Barrier::new(32));
        let workers: Vec<_> = (0..32)
            .map(|_| {
                let directory = directory.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    ensure_directory(&directory)
                })
            })
            .collect();

        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        assert!(directory.is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    fn empty_systemd_cleanup_fixture(name: &str) -> (PathBuf, PathBuf, FileIdentity, FileIdentity) {
        let root = std::env::temp_dir().join(format!(
            "cube-systemd-cleanup-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        let leaf = root.join("fixture.scope");
        fs::create_dir_all(&leaf).unwrap();
        fs::write(leaf.join("cgroup.events"), "populated 0\n").unwrap();
        fs::write(leaf.join("cgroup.procs"), "").unwrap();
        let parent_identity = file_identity(&root).unwrap();
        let leaf_identity = file_identity(&leaf).unwrap();
        (root, leaf, parent_identity, leaf_identity)
    }

    #[test]
    fn systemd_cleanup_accepts_exact_empty_inactive_and_collection_race() {
        let (root, leaf, parent, identity) = empty_systemd_cleanup_fixture("inactive");
        cleanup_systemd_target_with(
            "fixture.scope",
            &leaf,
            &parent,
            Some(&identity),
            || {
                Ok(HashMap::from([(
                    "ActiveState".to_string(),
                    "inactive".to_string(),
                )]))
            },
            || panic!("inactive state must not require an absence query"),
            || panic!("inactive state must not reset the unit"),
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();

        let (root, leaf, parent, identity) = empty_systemd_cleanup_fixture("collected");
        cleanup_systemd_target_with(
            "fixture.scope",
            &leaf,
            &parent,
            Some(&identity),
            || Err("injected systemctl show collection race".to_string()),
            || Ok(true),
            || panic!("an absent unit must not be reset"),
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();

        let (root, leaf, parent, identity) = empty_systemd_cleanup_fixture("collecting");
        let property_calls = Arc::new(AtomicUsize::new(0));
        let property_call = Arc::clone(&property_calls);
        cleanup_systemd_target_with(
            "fixture.scope",
            &leaf,
            &parent,
            Some(&identity),
            move || {
                if property_call.fetch_add(1, Ordering::AcqRel) < 2 {
                    Err("injected transient systemctl show failure".to_string())
                } else {
                    Ok(HashMap::from([(
                        "ActiveState".to_string(),
                        "inactive".to_string(),
                    )]))
                }
            },
            || Ok(false),
            || panic!("inactive state must not reset the unit"),
        )
        .unwrap();
        assert_eq!(property_calls.load(Ordering::Acquire), 3);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn systemd_absence_accepts_not_found_stdout_with_nonzero_status() {
        assert!(
            systemd_unit_absent_from_output("collected.scope", false, "not-found\n", "").unwrap()
        );
        assert!(!systemd_unit_absent_from_output("loaded.scope", true, "loaded\n", "").unwrap());
        assert!(systemd_unit_absent_from_output(
            "legacy.scope",
            false,
            "",
            "Unit legacy.scope could not be found."
        )
        .unwrap());
        assert!(
            systemd_unit_absent_from_output("broken.scope", false, "", "")
                .unwrap_err()
                .contains("query systemd unit collection broken.scope")
        );
    }

    #[test]
    fn systemd_cleanup_resets_only_exact_empty_failed_scope() {
        let (root, leaf, parent, identity) = empty_systemd_cleanup_fixture("failed");
        let reset = Arc::new(AtomicBool::new(false));
        let reset_call = Arc::clone(&reset);
        cleanup_systemd_target_with(
            "fixture.scope",
            &leaf,
            &parent,
            Some(&identity),
            || {
                Ok(HashMap::from([(
                    "ActiveState".to_string(),
                    "failed".to_string(),
                )]))
            },
            || panic!("failed state must not require an absence query"),
            move || {
                reset_call.store(true, Ordering::Release);
                Ok(())
            },
        )
        .unwrap();
        assert!(reset.load(Ordering::Acquire));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn systemd_cleanup_rejects_leaf_replacement_during_property_retry() {
        for final_state in ["inactive", "failed"] {
            let (root, leaf, parent, identity) =
                empty_systemd_cleanup_fixture(&format!("replacement-{final_state}"));
            let calls = Arc::new(AtomicUsize::new(0));
            let property_calls = Arc::clone(&calls);
            let replacement = leaf.clone();
            let retired = root.join("retired-leaf");
            let reset = Arc::new(AtomicBool::new(false));
            let reset_call = Arc::clone(&reset);
            let error = cleanup_systemd_target_with(
                "fixture.scope",
                &leaf,
                &parent,
                Some(&identity),
                move || {
                    if property_calls.fetch_add(1, Ordering::AcqRel) == 0 {
                        fs::rename(&replacement, &retired).unwrap();
                        fs::create_dir(&replacement).unwrap();
                        fs::write(replacement.join("cgroup.events"), "populated 0\n").unwrap();
                        fs::write(replacement.join("cgroup.procs"), "").unwrap();
                        Err("injected systemctl show collection race".to_string())
                    } else {
                        Ok(HashMap::from([(
                            "ActiveState".to_string(),
                            final_state.to_string(),
                        )]))
                    }
                },
                || Ok(false),
                move || {
                    reset_call.store(true, Ordering::Release);
                    Ok(())
                },
            )
            .unwrap_err();
            assert!(error.contains("leaf identity changed"), "{error}");
            assert_eq!(calls.load(Ordering::Acquire), 2);
            assert!(!reset.load(Ordering::Acquire));
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn systemd_cleanup_fails_closed_for_live_or_uncertain_identity() {
        let (root, leaf, parent, identity) = empty_systemd_cleanup_fixture("active");
        let error = cleanup_systemd_target_with(
            "fixture.scope",
            &leaf,
            &parent,
            Some(&identity),
            || {
                Ok(HashMap::from([(
                    "ActiveState".to_string(),
                    "active".to_string(),
                )]))
            },
            || Ok(false),
            || Ok(()),
        )
        .unwrap_err();
        assert!(error.contains("has not been collected"));

        let bait = root.join("bait");
        fs::create_dir(&bait).unwrap();
        let wrong_identity = file_identity(&bait).unwrap();
        let error = cleanup_systemd_target_with(
            "fixture.scope",
            &leaf,
            &parent,
            Some(&wrong_identity),
            || Err("injected systemctl show collection race".to_string()),
            || Ok(true),
            || Ok(()),
        )
        .unwrap_err();
        assert!(error.contains("leaf identity changed"));

        fs::write(leaf.join("cgroup.events"), "populated 1\n").unwrap();
        let error = cleanup_systemd_target_with(
            "fixture.scope",
            &leaf,
            &parent,
            Some(&identity),
            || {
                Ok(HashMap::from([(
                    "ActiveState".to_string(),
                    "inactive".to_string(),
                )]))
            },
            || Ok(false),
            || Ok(()),
        )
        .unwrap_err();
        assert!(error.contains("still populated"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn classifier_accepts_exact_managed_sandbox() {
        let id = "a".repeat(64);
        let annotations = HashMap::from([
            (CONTAINER_TYPE_ANNOTATION.to_string(), "sandbox".to_string()),
            (SANDBOX_ID_ANNOTATION.to_string(), id.clone()),
        ]);
        let spec = spec(
            annotations,
            Some(&format!(
                "kubepods-burstable-podabc.slice:cri-containerd:{id}"
            )),
        );
        // Path parsing requires a real parent; pure classifier path details
        // are covered separately with cgroupfs paths below.
        let error = classify_and_target(&spec, &params("k8s.io", &id), "/original").unwrap_err();
        assert!(error.contains("canonicalize cgroup parent"));
    }

    #[test]
    fn managed_systemd_target_parser_accepts_exact_cri_shape() {
        let id = "b".repeat(64);
        let input = format!("kubepods-burstable-podabc.slice:cri-containerd:{id}");
        let (slice, unit) = parse_systemd_target_components(&input, &id).unwrap();
        assert_eq!(slice, "kubepods-burstable-podabc.slice");
        assert_eq!(unit, format!("cri-containerd-{id}.scope"));
        assert!(parse_systemd_target_components(
            &format!("kubepods-burstable-podabc.slice:runc:{id}"),
            &id
        )
        .is_err());
    }

    #[test]
    fn cri_parent_normalization_matches_systemd_and_cgroupfs_forms() {
        let id = "c".repeat(64);
        assert_eq!(
            canonical_cri_cgroup_parent("kubepods-burstable-podabc.slice").unwrap(),
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice"
        );
        assert_eq!(
            target_path_from_cri_parent("kubepods-burstable-podabc.slice", &id).unwrap(),
            PathBuf::from(format!(
                "kubepods-burstable-podabc.slice:cri-containerd:{id}"
            ))
        );
        assert_eq!(
            target_path_from_cri_parent(
                "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice",
                &id,
            )
            .unwrap(),
            PathBuf::from(format!(
                "kubepods-burstable-podabc.slice:cri-containerd:{id}"
            ))
        );
        assert_eq!(
            canonical_cri_cgroup_parent("/kubepods/burstable/podabc").unwrap(),
            "/kubepods/burstable/podabc"
        );
        assert_eq!(
            target_path_from_cri_parent("/kubepods/burstable/podabc", &id).unwrap(),
            PathBuf::from(format!("/kubepods/burstable/podabc/{id}"))
        );
        assert!(
            target_path_from_cri_parent("/wrong/kubepods-burstable-podabc.slice", &id).is_err()
        );
        assert!(canonical_cri_cgroup_parent("").is_err());
        assert!(canonical_cri_cgroup_parent("parent:child").is_err());
    }

    #[test]
    fn unified_cgroup_validation_allows_same_hierarchy_bind_aliases() {
        let mountinfo = concat!(
            "30 20 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
            "31 20 0:27 / /run/cilium/cgroupv2 rw - cgroup2 cgroup rw\n",
        );
        validate_unified_cgroup_mountinfo(mountinfo).unwrap();

        let different = concat!(
            "30 20 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
            "31 20 0:28 / /run/other/cgroup2 rw - cgroup2 cgroup rw\n",
        );
        assert!(validate_unified_cgroup_mountinfo(different).is_err());
        assert!(validate_unified_cgroup_mountinfo(
            "31 20 0:27 / /run/cilium/cgroupv2 rw - cgroup2 cgroup rw\n"
        )
        .is_err());
    }

    #[test]
    fn classifier_accepts_cri_container_and_direct_legacy() {
        let cri = spec(
            HashMap::from([
                (
                    CONTAINER_TYPE_ANNOTATION.to_string(),
                    "container".to_string(),
                ),
                (SANDBOX_ID_ANNOTATION.to_string(), "sandbox-1".to_string()),
            ]),
            None,
        );
        assert_eq!(
            classify_and_target(&cri, &params("k8s.io", "container-1"), "/original")
                .unwrap()
                .0,
            Classification::LegacyTask
        );
        let direct = spec(HashMap::new(), None);
        assert_eq!(
            classify_and_target(&direct, &params("default", "task-1"), "/original")
                .unwrap()
                .0,
            Classification::LegacyTask
        );
    }

    #[test]
    fn classifier_rejects_partial_unknown_and_conflicting_annotations() {
        for annotations in [
            HashMap::from([(CONTAINER_TYPE_ANNOTATION.to_string(), "sandbox".to_string())]),
            HashMap::from([(SANDBOX_ID_ANNOTATION.to_string(), "sandbox-1".to_string())]),
            HashMap::from([
                (CONTAINER_TYPE_ANNOTATION.to_string(), "unknown".to_string()),
                (SANDBOX_ID_ANNOTATION.to_string(), "sandbox-1".to_string()),
            ]),
        ] {
            assert!(classify_and_target(
                &spec(annotations, None),
                &params("k8s.io", "sandbox-1"),
                "/original"
            )
            .is_err());
        }
    }

    #[test]
    fn cgroupfs_normalization_rejects_escape_and_wrong_leaf() {
        assert!(normalized_cgroup_relative(Path::new("/a/../b")).is_err());
        let normalized = normalized_cgroup_relative(Path::new("/a/b/id")).unwrap();
        assert_eq!(normalized, PathBuf::from("a/b/id"));
        assert!(parse_host_target(Path::new("/a/b/wrong"), "id").is_err());
    }

    #[test]
    fn immutable_identity_ignores_only_containment() {
        let mut current = process_identity(std::process::id() as i32).unwrap();
        current.launch_nonce_sha256 = Some("nonce".to_string());
        let mut sibling = current.clone();
        sibling.cgroup = "/sibling".to_string();
        assert!(immutable_identity_matches(&current, &sibling));
        sibling.start_time_ticks += 1;
        assert!(!immutable_identity_matches(&current, &sibling));
    }

    #[test]
    fn atomic_record_round_trip_rejects_no_data_loss() {
        let root =
            std::env::temp_dir().join(format!("cube-host-cgroup-record-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let path = root.join("owner.json");
        let owner = RuntimeResourceOwner::empty("generation-a".to_string());
        atomic_write_json(&path, &owner).unwrap();
        assert_eq!(read_json::<RuntimeResourceOwner>(&path).unwrap(), owner);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn vmm_worker_spawn_intent_precedes_identity_allocation() {
        let root = std::env::temp_dir().join(format!(
            "cube-vmm-worker-placement-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.phase = LifecyclePhase::ContainerdCommitted;
                record.create_state = CreateState::Succeeded;
                record.server = Some(server.clone());
                record.target = HostTarget::Legacy {
                    cgroup: server.cgroup.clone(),
                };
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 2,
                    identity: server.clone(),
                    revoked_epoch: None,
                };
                Ok(())
            })
            .unwrap();

        let operation = handle.begin_start_operation().unwrap();
        let executable = fs::canonicalize("/bin/sleep").unwrap();
        let nonce = uuid::Uuid::new_v4().to_string();
        crate::hypervisor::worker::WorkerPlacement::prepare_vmm_worker_spawn(
            &operation,
            &executable,
            &nonce,
            crate::hypervisor::worker::PROTOCOL_VERSION,
        )
        .unwrap();
        let intent = handle.read_record().unwrap().vmm_worker.unwrap();
        assert_eq!(intent.state, VmmWorkerState::SpawnIntent);
        assert_eq!(intent.operation_epoch, 2);
        assert_eq!(intent.launch_nonce_sha256, sha256_hex(nonce.as_bytes()));
        assert!(intent.identity.is_none());

        let mut child = ProcessCommand::new(&executable)
            .arg("30")
            .env("CUBE_VMM_WORKER_NONCE", &nonce)
            .spawn()
            .unwrap();
        let spawn_record = handle.read_record().unwrap();
        let discovered =
            find_spawn_intent_vmm_worker(&spawn_record, spawn_record.vmm_worker.as_ref().unwrap())
                .unwrap()
                .unwrap();
        assert_eq!(discovered.pid, child.id() as i32);
        crate::hypervisor::worker::WorkerPlacement::place_vmm_worker(&operation, child.id())
            .unwrap();
        let allocated_record = handle.read_record().unwrap();
        let allocated = allocated_record.vmm_worker.as_ref().unwrap();
        assert_eq!(allocated.state, VmmWorkerState::Allocated);
        assert_eq!(allocated.operation_epoch, 2);
        assert_eq!(allocated.launch_nonce_sha256, sha256_hex(nonce.as_bytes()));
        let identity = allocated.identity.as_ref().unwrap();
        assert_eq!(identity.pid, child.id() as i32);
        assert_eq!(identity.executable, file_identity(&executable).unwrap());

        terminate_recorded_vmm_worker(&allocated_record).unwrap();
        child.wait().unwrap();
        drop(operation);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn vmm_worker_spawn_intent_cleanup_does_not_require_placement() {
        let root = std::env::temp_dir().join(format!(
            "cube-vmm-worker-intent-cleanup-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.phase = LifecyclePhase::ContainerdCommitted;
                record.create_state = CreateState::Succeeded;
                record.server = Some(server.clone());
                record.target = HostTarget::Legacy {
                    cgroup: server.cgroup.clone(),
                };
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 2,
                    identity: server.clone(),
                    revoked_epoch: None,
                };
                Ok(())
            })
            .unwrap();
        let operation = handle.begin_start_operation().unwrap();
        let executable = fs::canonicalize("/bin/sleep").unwrap();
        let nonce = uuid::Uuid::new_v4().to_string();
        crate::hypervisor::worker::WorkerPlacement::prepare_vmm_worker_spawn(
            &operation,
            &executable,
            &nonce,
            crate::hypervisor::worker::PROTOCOL_VERSION,
        )
        .unwrap();
        let mut child = ProcessCommand::new(&executable)
            .arg("30")
            .env("CUBE_VMM_WORKER_NONCE", &nonce)
            .spawn()
            .unwrap();

        let mut record = handle.read_record().unwrap();
        record.operation_owner.epoch = 2;
        record.target = HostTarget::Legacy {
            cgroup: "/not-yet-placed".to_string(),
        };
        terminate_recorded_vmm_worker(&record).unwrap();
        child.wait().unwrap();

        drop(operation);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn vmm_worker_allocated_containment_breach_requires_durable_identity() {
        let root = std::env::temp_dir().join(format!(
            "cube-vmm-worker-breach-cleanup-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let executable = fs::canonicalize("/bin/sleep").unwrap();
        let mut child = ProcessCommand::new(&executable).arg("30").spawn().unwrap();
        let actual = process_identity(child.id() as i32).unwrap();
        let mut recorded = actual.clone();
        recorded.cgroup = "/durable-target".to_string();
        let mut record = handle.read_record().unwrap();
        record.operation_owner.epoch = 2;
        record.target = HostTarget::Legacy {
            cgroup: recorded.cgroup.clone(),
        };
        record.vmm_worker = Some(VmmWorkerRecord {
            state: VmmWorkerState::Allocated,
            operation_epoch: 2,
            protocol_version: crate::hypervisor::worker::PROTOCOL_VERSION,
            launch_nonce_sha256: "durable-nonce".to_string(),
            expected_executable: recorded.executable.clone(),
            identity: Some(recorded),
        });
        assert!(terminate_recorded_vmm_worker(&record)
            .unwrap_err()
            .contains("outside its durable cgroup"));
        assert!(child.try_wait().unwrap().is_none());

        record.containment_breach = Some(containment_identity(&actual.cgroup).unwrap());
        terminate_recorded_vmm_worker(&record).unwrap();
        child.wait().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn scanner_server_death_converges_allocated_worker() {
        let root = std::env::temp_dir().join(format!(
            "cube-vmm-worker-server-death-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let queue = root.join("queue");
        fs::create_dir_all(queue.join(HOST_QUEUE_DIRECTORY)).unwrap();
        fs::create_dir_all(queue.join(RUNTIME_QUEUE_DIRECTORY)).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let mut server = ProcessCommand::new("sleep").arg("30").spawn().unwrap();
        let server_identity = process_identity(server.id() as i32).unwrap();
        let mut worker = ProcessCommand::new("sleep").arg("30").spawn().unwrap();
        let worker_identity = process_identity(worker.id() as i32).unwrap();
        assert_eq!(server_identity.cgroup, worker_identity.cgroup);
        handle
            .update_record(|record| {
                record.phase = LifecyclePhase::ContainerdCommitted;
                record.create_state = CreateState::Succeeded;
                record.server = Some(server_identity.clone());
                record.target = HostTarget::Legacy {
                    cgroup: worker_identity.cgroup.clone(),
                };
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 2,
                    identity: server_identity.clone(),
                    revoked_epoch: None,
                };
                record.vmm_worker = Some(VmmWorkerRecord {
                    state: VmmWorkerState::Allocated,
                    operation_epoch: 2,
                    protocol_version: crate::hypervisor::worker::PROTOCOL_VERSION,
                    launch_nonce_sha256: sha256_hex(b"allocated-worker"),
                    expected_executable: worker_identity.executable.clone(),
                    identity: Some(worker_identity.clone()),
                });
                Ok(())
            })
            .unwrap();
        server.kill().unwrap();
        server.wait().unwrap();

        scan_lifecycle(&handle, &queue).await.unwrap();
        worker.wait().unwrap();
        let record = handle.read_record().unwrap();
        assert_eq!(record.phase, LifecyclePhase::ServerStopped);
        assert_eq!(record.operation_owner.kind, OwnerKind::Scanner);
        assert!(cleanup_queue_path(&queue, HOST_QUEUE_DIRECTORY, &record.generation).is_file());
        assert!(cleanup_queue_path(&queue, RUNTIME_QUEUE_DIRECTORY, &record.generation).is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multiple_spawn_intent_workers_fail_closed() {
        let root = std::env::temp_dir().join(format!(
            "cube-vmm-worker-multiple-intent-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let executable = fs::canonicalize("/bin/sleep").unwrap();
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut first = ProcessCommand::new(&executable)
            .arg("30")
            .env("CUBE_VMM_WORKER_NONCE", &nonce)
            .spawn()
            .unwrap();
        let mut second = ProcessCommand::new(&executable)
            .arg("30")
            .env("CUBE_VMM_WORKER_NONCE", &nonce)
            .spawn()
            .unwrap();
        let mut record = handle.read_record().unwrap();
        record.server = Some(process_identity(std::process::id() as i32).unwrap());
        record.vmm_worker = Some(VmmWorkerRecord {
            state: VmmWorkerState::SpawnIntent,
            operation_epoch: 1,
            protocol_version: crate::hypervisor::worker::PROTOCOL_VERSION,
            launch_nonce_sha256: sha256_hex(nonce.as_bytes()),
            expected_executable: file_identity(&executable).unwrap(),
            identity: None,
        });
        let error =
            find_spawn_intent_vmm_worker(&record, record.vmm_worker.as_ref().unwrap()).unwrap_err();
        assert!(error.contains("multiple processes match"), "{error}");
        assert!(first.try_wait().unwrap().is_none());
        assert!(second.try_wait().unwrap().is_none());
        first.kill().unwrap();
        second.kill().unwrap();
        first.wait().unwrap();
        second.wait().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scanner_rejects_incoherent_worker_protocol_and_epoch() {
        let root = std::env::temp_dir().join(format!(
            "cube-vmm-worker-invalid-record-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let identity = process_identity(std::process::id() as i32).unwrap();
        let mut record = handle.read_record().unwrap();
        record.vmm_worker = Some(VmmWorkerRecord {
            state: VmmWorkerState::Allocated,
            operation_epoch: 1,
            protocol_version: crate::hypervisor::worker::PROTOCOL_VERSION + 1,
            launch_nonce_sha256: sha256_hex(b"invalid-record"),
            expected_executable: identity.executable.clone(),
            identity: Some(identity),
        });
        assert!(observe_allocated_vmm_worker(&record)
            .unwrap_err()
            .contains("protocol version"));
        let worker = record.vmm_worker.as_mut().unwrap();
        worker.protocol_version = crate::hypervisor::worker::PROTOCOL_VERSION;
        worker.operation_epoch = record.operation_owner.epoch + 1;
        assert!(observe_allocated_vmm_worker(&record)
            .unwrap_err()
            .contains("operation epoch"));
        fs::remove_dir_all(root).unwrap();
    }

    fn lifecycle_fixture(root: &Path, phase: LifecyclePhase) -> LifecycleHandle {
        let directory = root.join("lifecycle");
        fs::create_dir_all(&directory).unwrap();
        for name in [RECORD_LOCK_FILE, OPERATION_LOCK_FILE] {
            File::create(directory.join(name)).unwrap();
        }
        let identity = process_identity(std::process::id() as i32).unwrap();
        let generation = "fixture-generation".to_string();
        let target = HostTarget::Legacy {
            cgroup: identity.cgroup.clone(),
        };
        let record = LifecycleRecord {
            schema_version: SCHEMA_VERSION,
            sequence: 1,
            generation: generation.clone(),
            phase,
            classification: Classification::LegacyTask,
            namespace: "fixture".to_string(),
            instance_id: "fixture".to_string(),
            bundle: root.display().to_string(),
            bundle_identity: file_identity(root).unwrap(),
            created_at_ms: unix_time_ms().unwrap(),
            takeover_claimed_at_ms: None,
            launch_nonce_sha256: sha256_hex(b"fixture"),
            expected_server_path: "/fixture/server".to_string(),
            expected_server_executable: identity.executable.clone(),
            expected_server_argv: vec!["fixture".to_string()],
            expected_server_command_sha256: identity.command_sha256.clone(),
            helper: identity.clone(),
            server: None,
            target: target.clone(),
            socket: SocketIdentity {
                path: root.join("shim.sock").display().to_string(),
                parent: file_identity(root).unwrap(),
                device: None,
                inode: None,
                absent_at_prepare: true,
            },
            operation_owner: OperationOwner {
                kind: OwnerKind::Helper,
                epoch: 1,
                identity,
                revoked_epoch: None,
            },
            create_state: CreateState::None,
            create_fingerprint: None,
            create_waiters: 0,
            failure: None,
            containment_breach: None,
            vmm_worker: None,
            degraded_reason: None,
        };
        atomic_write_json(&directory.join(RECORD_FILE), &record).unwrap();
        atomic_write_json(
            &directory.join(HOST_OWNER_FILE),
            &HostCgroupOwner {
                schema_version: SCHEMA_VERSION,
                generation: generation.clone(),
                namespace: "fixture".to_string(),
                instance_id: "fixture".to_string(),
                state: HostOwnerState::Empty,
                target,
                original_cgroup: record.helper.cgroup.clone(),
                server: None,
                controllers: None,
            },
        )
        .unwrap();
        atomic_write_json(
            &directory.join(RUNTIME_OWNER_FILE),
            &RuntimeResourceOwner::empty(generation),
        )
        .unwrap();
        LifecycleHandle { directory }
    }

    fn pending_socket_ready_fixture(root: &Path) -> LifecycleHandle {
        let handle = lifecycle_fixture(root, LifecyclePhase::SocketReady);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.classification = Classification::Pending;
                record.target = HostTarget::Pending {
                    original_cgroup: server.cgroup.clone(),
                };
                record.server = Some(server.clone());
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Helper,
                    epoch: 1,
                    identity: server.clone(),
                    revoked_epoch: None,
                };
                Ok(())
            })
            .unwrap();
        let mut owner: HostCgroupOwner =
            read_json(&handle.directory.join(HOST_OWNER_FILE)).unwrap();
        owner.state = HostOwnerState::Empty;
        owner.target = HostTarget::Pending {
            original_cgroup: server.cgroup,
        };
        owner.server = None;
        atomic_write_json(&handle.directory.join(HOST_OWNER_FILE), &owner).unwrap();
        handle
    }

    #[test]
    fn duplicate_server_identity_registration_does_not_rewrite_record() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-idempotent-server-register-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::Prepared);
        let nonce_hash = sha256_hex(b"idempotent-server-register");
        let mut identity = process_identity(std::process::id() as i32).unwrap();
        identity.launch_nonce_sha256 = Some(nonce_hash.clone());
        let expected_path = fs::read_link("/proc/self/exe").unwrap();
        handle
            .update_record(|record| {
                record.launch_nonce_sha256 = nonce_hash.clone();
                record.expected_server_path = expected_path.display().to_string();
                record.expected_server_executable = identity.executable.clone();
                record.expected_server_command_sha256 = identity.command_sha256.clone();
                record.bundle_identity = identity.cwd.clone();
                record.target = HostTarget::Legacy {
                    cgroup: identity.cgroup.clone(),
                };
                Ok(())
            })
            .unwrap();

        let before = handle.read_record().unwrap().sequence;
        handle
            .register_server_identity(identity.clone(), &nonce_hash)
            .unwrap();
        let registered = handle.read_record().unwrap();
        assert_eq!(registered.sequence, before + 1);
        handle
            .register_server_identity(identity, &nonce_hash)
            .unwrap();
        assert_eq!(handle.read_record().unwrap().sequence, registered.sequence);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_first_rpc_claims_without_sandbox_config_json() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-pending-managed-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = pending_socket_ready_fixture(&root);
        assert!(!root.join("config.json").exists());

        let id = "a".repeat(64);
        handle
            .update_record(|record| {
                record.namespace = "k8s.io".to_string();
                record.instance_id = id.clone();
                Ok(())
            })
            .unwrap();
        let mut owner: HostCgroupOwner =
            read_json(&handle.directory.join(HOST_OWNER_FILE)).unwrap();
        owner.namespace = "k8s.io".to_string();
        owner.instance_id = id;
        atomic_write_json(&handle.directory.join(HOST_OWNER_FILE), &owner).unwrap();

        assert_eq!(
            handle
                .begin_managed_create(&root, "system.slice", b"managed-create")
                .unwrap(),
            CreateAdmission::First
        );
        let record = handle.read_record().unwrap();
        assert_eq!(record.phase, LifecyclePhase::TakeoverClaimed);
        assert_eq!(record.classification, Classification::ManagedSandbox);
        assert!(record.target.managed());
        assert_eq!(
            handle
                .begin_managed_create(&root, "system.slice", b"managed-create")
                .unwrap(),
            CreateAdmission::RetryInProgress
        );
        assert!(matches!(
            handle.begin_managed_create(&root, "system.slice", b"different-create"),
            Err(BeginCreateError::Conflict(_))
        ));
        assert!(matches!(
            handle.begin_managed_create(
                &root,
                "../../caller-parent-must-not-be-read",
                b"different-parent-fingerprint",
            ),
            Err(BeginCreateError::Conflict(_))
        ));
        fs::write(
            root.join("config.json"),
            serde_json::to_vec(&spec(HashMap::new(), None)).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            handle.begin_legacy_create(&root, &"a".repeat(64), b"managed-create"),
            Err(BeginCreateError::Conflict(_))
        ));
        let owner: HostCgroupOwner = read_json(&handle.directory.join(HOST_OWNER_FILE)).unwrap();
        assert_eq!(owner.state, HostOwnerState::Empty);
        assert!(matches!(owner.target, HostTarget::Pending { .. }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_v12_rejects_adversarial_cri_collection_collision() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-v12-cri-collision-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = pending_socket_ready_fixture(&root);
        let id = "a".repeat(64);
        handle
            .update_record(|record| {
                record.namespace = "k8s.io".to_string();
                record.instance_id = id.clone();
                Ok(())
            })
            .unwrap();
        let mut owner: HostCgroupOwner =
            read_json(&handle.directory.join(HOST_OWNER_FILE)).unwrap();
        owner.namespace = "k8s.io".to_string();
        owner.instance_id = id;
        atomic_write_json(&handle.directory.join(HOST_OWNER_FILE), &owner).unwrap();

        let (first, conflicting) =
            runtime_resource::cri_collection_collision_regression_fingerprints();
        assert_ne!(first, conflicting);
        assert_eq!(
            handle
                .begin_managed_create(&root, "system.slice", first.as_bytes())
                .unwrap(),
            CreateAdmission::First
        );
        let durable = handle.read_record().unwrap();
        assert!(matches!(
            handle.begin_managed_create(&root, "user.slice", conflicting.as_bytes()),
            Err(BeginCreateError::Conflict(_))
        ));
        let after_conflict = handle.read_record().unwrap();
        assert_eq!(after_conflict.target, durable.target);
        assert_eq!(
            after_conflict.create_fingerprint,
            durable.create_fingerprint
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_rpc_claim_is_retryable_across_every_atomic_record_stage() {
        for stage in ["temp", "file-fsync", "rename", "parent-fsync"] {
            let root = std::env::temp_dir().join(format!(
                "cube-host-cgroup-claim-{stage}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).unwrap();
            let handle = pending_socket_ready_fixture(&root);
            let id = "b".repeat(64);
            handle
                .update_record(|record| {
                    record.namespace = "k8s.io".to_string();
                    record.instance_id = id.clone();
                    Ok(())
                })
                .unwrap();
            let mut owner = handle.read_host_owner().unwrap();
            owner.namespace = "k8s.io".to_string();
            owner.instance_id = id;
            atomic_write_json(&handle.directory.join(HOST_OWNER_FILE), &owner).unwrap();
            File::create(atomic_write_failpoint_path(
                &handle.directory.join(RECORD_FILE),
                stage,
            ))
            .unwrap();

            let first = handle.begin_managed_create(&root, "system.slice", b"managed-create");
            let durable_phase = handle.read_record().unwrap().phase;
            let retry = handle
                .begin_managed_create(&root, "system.slice", b"managed-create")
                .unwrap();
            if stage == "parent-fsync" {
                assert_eq!(first.unwrap(), CreateAdmission::First);
                assert_eq!(durable_phase, LifecyclePhase::TakeoverClaimed);
                assert_eq!(retry, CreateAdmission::RetryInProgress);
            } else {
                assert!(first.is_err());
                assert_eq!(durable_phase, LifecyclePhase::SocketReady);
                assert_eq!(retry, CreateAdmission::First);
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn retry_waiter_is_counted_exactly_once_across_atomic_record_stages() {
        for stage in ["temp", "file-fsync", "rename", "parent-fsync"] {
            let root = std::env::temp_dir().join(format!(
                "cube-host-cgroup-retry-waiter-{stage}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).unwrap();
            let handle = pending_socket_ready_fixture(&root);
            let id = "f".repeat(64);
            handle
                .update_record(|record| {
                    record.namespace = "k8s.io".to_string();
                    record.instance_id = id.clone();
                    Ok(())
                })
                .unwrap();
            let mut owner = handle.read_host_owner().unwrap();
            owner.namespace = "k8s.io".to_string();
            owner.instance_id = id;
            atomic_write_json(&handle.directory.join(HOST_OWNER_FILE), &owner).unwrap();
            assert_eq!(
                handle
                    .begin_managed_create(&root, "system.slice", b"managed-create")
                    .unwrap(),
                CreateAdmission::First
            );
            let before = handle.read_record().unwrap();
            assert_eq!(before.create_waiters, 1);
            File::create(atomic_write_failpoint_path(
                &handle.directory.join(RECORD_FILE),
                stage,
            ))
            .unwrap();

            let retry = handle.begin_managed_create(&root, "system.slice", b"managed-create");
            let after = handle.read_record().unwrap();
            if stage == "parent-fsync" {
                assert_eq!(retry.unwrap(), CreateAdmission::RetryInProgress);
                assert_eq!(after.sequence, before.sequence + 1);
                assert_eq!(after.create_waiters, 2);
            } else {
                assert!(retry.is_err());
                assert_eq!(after.sequence, before.sequence);
                assert_eq!(after.create_waiters, 1);
                assert_eq!(
                    handle
                        .begin_managed_create(&root, "system.slice", b"managed-create")
                        .unwrap(),
                    CreateAdmission::RetryInProgress
                );
                assert_eq!(handle.read_record().unwrap().create_waiters, 2);
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn scanner_cannot_revoke_a_newer_first_rpc_claim() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-stale-scanner-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = pending_socket_ready_fixture(&root);
        let id = "c".repeat(64);
        handle
            .update_record(|record| {
                record.namespace = "k8s.io".to_string();
                record.instance_id = id.clone();
                Ok(())
            })
            .unwrap();
        let mut owner = handle.read_host_owner().unwrap();
        owner.namespace = "k8s.io".to_string();
        owner.instance_id = id;
        atomic_write_json(&handle.directory.join(HOST_OWNER_FILE), &owner).unwrap();
        let stale = handle.read_record().unwrap();

        assert_eq!(
            handle
                .begin_managed_create(&root, "system.slice", b"managed-create")
                .unwrap(),
            CreateAdmission::First
        );
        assert!(!handle
            .scanner_request_cleanup_if_current(&stale, "stale timeout", None)
            .unwrap());
        let current = handle.read_record().unwrap();
        assert_eq!(current.phase, LifecyclePhase::TakeoverClaimed);
        assert_eq!(current.create_state, CreateState::InProgress);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_sandbox_and_task_claim_have_one_durable_winner() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-claim-race-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = pending_socket_ready_fixture(&root);
        let id = "e".repeat(64);
        handle
            .update_record(|record| {
                record.namespace = "k8s.io".to_string();
                record.instance_id = id.clone();
                Ok(())
            })
            .unwrap();
        let mut owner = handle.read_host_owner().unwrap();
        owner.namespace = "k8s.io".to_string();
        owner.instance_id = id.clone();
        atomic_write_json(&handle.directory.join(HOST_OWNER_FILE), &owner).unwrap();
        fs::write(
            root.join("config.json"),
            serde_json::to_vec(&spec(HashMap::new(), None)).unwrap(),
        )
        .unwrap();

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let managed_handle = handle.clone();
        let managed_root = root.clone();
        let managed_barrier = barrier.clone();
        let managed = std::thread::spawn(move || {
            managed_barrier.wait();
            managed_handle.begin_managed_create(&managed_root, "system.slice", b"managed-create")
        });
        let legacy_handle = handle.clone();
        let legacy_root = root.clone();
        let legacy_id = id.clone();
        let legacy_barrier = barrier.clone();
        let legacy = std::thread::spawn(move || {
            legacy_barrier.wait();
            legacy_handle.begin_legacy_create(&legacy_root, &legacy_id, b"legacy-create")
        });
        barrier.wait();
        let results = [managed.join().unwrap(), legacy.join().unwrap()];
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(CreateAdmission::First)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(BeginCreateError::Conflict(_))))
                .count(),
            1
        );
        let record = handle.read_record().unwrap();
        assert_eq!(record.phase, LifecyclePhase::TakeoverClaimed);
        assert_eq!(record.create_state, CreateState::InProgress);
        assert_eq!(record.create_waiters, 1);
        assert_eq!(
            handle.read_host_owner().unwrap().state,
            HostOwnerState::Empty
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn scanner_publishes_failure_before_cleaning_abandoned_claim() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-scanner-result-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let queue = root.join("queue");
        fs::create_dir_all(queue.join(HOST_QUEUE_DIRECTORY)).unwrap();
        fs::create_dir_all(queue.join(RUNTIME_QUEUE_DIRECTORY)).unwrap();
        let handle = pending_socket_ready_fixture(&root);
        let id = "d".repeat(64);
        handle
            .update_record(|record| {
                record.namespace = "k8s.io".to_string();
                record.instance_id = id.clone();
                Ok(())
            })
            .unwrap();
        let mut owner = handle.read_host_owner().unwrap();
        owner.namespace = "k8s.io".to_string();
        owner.instance_id = id;
        atomic_write_json(&handle.directory.join(HOST_OWNER_FILE), &owner).unwrap();
        handle
            .begin_managed_create(&root, "system.slice", b"managed-create")
            .unwrap();
        handle
            .update_record(|record| {
                record.takeover_claimed_at_ms = Some(0);
                Ok(())
            })
            .unwrap();

        scan_lifecycle(&handle, &queue).await.unwrap();
        let failed = handle.read_record().unwrap();
        assert_eq!(failed.phase, LifecyclePhase::TakeoverClaimed);
        assert_eq!(failed.create_state, CreateState::Failed);
        assert_eq!(
            handle.current_create_result().unwrap(),
            Some(PersistedCreateResult::Failed {
                code: "DEADLINE_EXCEEDED".to_string(),
                message: "Host placement claim timed out".to_string(),
            })
        );
        publish_create_result_once(&handle, &PersistedCreateResult::Succeeded).unwrap();
        assert_eq!(
            handle.read_record().unwrap().create_state,
            CreateState::Failed
        );

        handle.finish_create_waiter().unwrap();
        let drained = handle.read_record().unwrap();
        assert!(handle
            .scanner_request_cleanup_if_current(&drained, "claim timed out", None)
            .unwrap());
        assert_eq!(
            handle.read_record().unwrap().phase,
            LifecyclePhase::CleanupRequired
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn current_schema_is_required_for_lifecycle_and_host_owner() {
        let root =
            std::env::temp_dir().join(format!("cube-host-cgroup-schema-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::SocketReady);
        let mut record = handle.read_record().unwrap();
        record.schema_version = SCHEMA_VERSION - 1;
        atomic_write_json(&handle.directory.join(RECORD_FILE), &record).unwrap();
        assert!(handle.read_record().is_err());

        record.schema_version = SCHEMA_VERSION;
        atomic_write_json(&handle.directory.join(RECORD_FILE), &record).unwrap();
        let mut owner = handle.read_host_owner().unwrap();
        owner.schema_version = SCHEMA_VERSION - 1;
        atomic_write_json(&handle.directory.join(HOST_OWNER_FILE), &owner).unwrap();
        assert!(handle.read_host_owner().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_first_rpc_claims_only_with_real_task_spec() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-pending-legacy-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = pending_socket_ready_fixture(&root);
        assert!(handle
            .begin_legacy_create(&root, "fixture", b"legacy")
            .is_err());
        fs::write(
            root.join("config.json"),
            serde_json::to_vec(&spec(HashMap::new(), None)).unwrap(),
        )
        .unwrap();
        assert!(handle
            .begin_legacy_create(&root, "wrong", b"legacy")
            .is_err());
        assert_eq!(
            handle
                .begin_legacy_create(&root, "fixture", b"legacy")
                .unwrap(),
            CreateAdmission::First
        );
        handle.commit_legacy_takeover().unwrap();
        let record = handle.read_record().unwrap();
        assert_eq!(record.phase, LifecyclePhase::ContainerdCommitted);
        assert_eq!(record.classification, Classification::LegacyTask);
        let owner: HostCgroupOwner = read_json(&handle.directory.join(HOST_OWNER_FILE)).unwrap();
        assert_eq!(owner.state, HostOwnerState::Empty);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delete_fences_takeover_before_host_commit() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-delete-before-commit-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let handle = pending_socket_ready_fixture(&root);
        fs::write(
            root.join("config.json"),
            serde_json::to_vec(&spec(HashMap::new(), None)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            handle
                .begin_legacy_create(&root, "fixture", b"legacy")
                .unwrap(),
            CreateAdmission::First
        );
        let claimed = handle.read_record().unwrap();

        handle.request_cleanup("delete before Host commit").unwrap();
        let failed = handle.read_record().unwrap();
        assert_eq!(failed.phase, LifecyclePhase::TakeoverClaimed);
        assert_eq!(failed.create_state, CreateState::Failed);
        assert_eq!(
            failed.operation_owner.epoch,
            claimed.operation_owner.epoch + 1
        );
        assert!(handle.commit_legacy_takeover().is_err());
        assert_eq!(
            handle.read_host_owner().unwrap().state,
            HostOwnerState::Empty
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn socket_ready_does_not_treat_normal_helper_exit_as_abandonment() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-helper-exit-grace-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).unwrap();
        let queue = root.join("queue");
        fs::create_dir_all(queue.join(HOST_QUEUE_DIRECTORY)).unwrap();
        fs::create_dir_all(queue.join(RUNTIME_QUEUE_DIRECTORY)).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::SocketReady);
        let mut child = ProcessCommand::new("sleep").arg("1").spawn().unwrap();
        let child_identity = process_identity(child.id() as i32).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.helper = child_identity;
                record.server = Some(server.clone());
                record.target = HostTarget::Legacy {
                    cgroup: server.cgroup.clone(),
                };
                Ok(())
            })
            .unwrap();

        scan_lifecycle(&handle, &queue).await.unwrap();
        assert_eq!(
            handle.read_record().unwrap().phase,
            LifecyclePhase::SocketReady
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_handoff_persists_both_owners_before_durable_phase() {
        let root =
            std::env::temp_dir().join(format!("cube-host-cgroup-handoff-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        let handle = lifecycle_fixture(&root, LifecyclePhase::SocketReady);

        handle.request_cleanup("unit test").unwrap();
        ensure_cleanup_handoff(&handle, &queue).unwrap();

        let record = handle.read_record().unwrap();
        assert_eq!(record.phase, LifecyclePhase::CleanupOwnersDurable);
        assert_eq!(record.operation_owner.kind, OwnerKind::Scanner);
        assert_eq!(record.operation_owner.epoch, 3);
        assert_eq!(record.operation_owner.revoked_epoch, Some(2));
        assert!(queue
            .join(HOST_QUEUE_DIRECTORY)
            .join(format!("{}.json", record.generation))
            .is_file());
        assert!(queue
            .join(RUNTIME_QUEUE_DIRECTORY)
            .join(format!("{}.json", record.generation))
            .is_file());
        let runtime_job: RuntimeCleanupJob = read_json(&cleanup_queue_path(
            &queue,
            RUNTIME_QUEUE_DIRECTORY,
            &record.generation,
        ))
        .unwrap();
        assert!(!runtime_job.ready_for_cleanup);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_handoff_attempts_both_owners_and_rejects_mismatched_destination() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-handoff-mismatch-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        let handle = lifecycle_fixture(&root, LifecyclePhase::SocketReady);
        handle.request_cleanup("unit test").unwrap();
        let record = handle.read_record().unwrap();
        let host_directory = queue.join(HOST_QUEUE_DIRECTORY);
        fs::create_dir_all(&host_directory).unwrap();
        atomic_write_json(
            &host_directory.join(format!("{}.json", record.generation)),
            &serde_json::json!({"wrong": true}),
        )
        .unwrap();

        let error = ensure_cleanup_handoff(&handle, &queue).unwrap_err();
        assert!(error.contains("decode record") || error.contains("differs from canonical source"));
        assert!(queue
            .join(RUNTIME_QUEUE_DIRECTORY)
            .join(format!("{}.json", record.generation))
            .is_file());
        assert_eq!(
            handle.read_record().unwrap().phase,
            LifecyclePhase::CleanupRequired
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_create_is_not_drained_until_last_waiter_exits() {
        let root =
            std::env::temp_dir().join(format!("cube-host-cgroup-waiters-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        handle
            .update_record(|record| {
                record.create_state = CreateState::InProgress;
                record.create_waiters = 2;
                Ok(())
            })
            .unwrap();

        handle
            .finish_create_failure("INVALID_ARGUMENT", "fixture")
            .unwrap();
        let published = handle.read_record().unwrap().failure.unwrap();
        assert!(handle
            .finish_create_failure("INTERNAL", "must not replace first result")
            .is_err());
        assert_eq!(handle.read_record().unwrap().failure.unwrap(), published);
        handle.finish_create_waiter().unwrap();
        assert!(!handle.read_record().unwrap().failure.unwrap().drained);
        handle.finish_create_waiter().unwrap();
        assert!(handle.read_record().unwrap().failure.unwrap().drained);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delete_during_create_publishes_failure_before_cleanup() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-delete-during-create-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 7,
                    identity: server,
                    revoked_epoch: None,
                };
                record.create_state = CreateState::InProgress;
                record.create_waiters = 1;
                record.create_fingerprint = Some("fixture-create".to_string());
                Ok(())
            })
            .unwrap();
        let in_progress = handle.read_record().unwrap();

        handle.request_cleanup("containerd delete action").unwrap();
        let failed = handle.read_record().unwrap();
        assert_eq!(failed.phase, LifecyclePhase::ContainerdCommitted);
        assert_eq!(failed.create_state, CreateState::Failed);
        assert_eq!(failed.create_waiters, 1);
        assert_eq!(
            failed.operation_owner.epoch,
            in_progress.operation_owner.epoch + 1
        );
        assert_eq!(
            failed.operation_owner.revoked_epoch,
            Some(in_progress.operation_owner.epoch)
        );
        let failure = failed.failure.as_ref().unwrap();
        assert_eq!(failure.code, "CANCELLED");
        assert_eq!(failure.message, "containerd delete action");
        assert_eq!(failure.waiter_count, 1);
        assert!(!failure.drained);
        let intent = RuntimeResourceOwner::intent(
            "/run/cubelet.sock".to_string(),
            "sandbox".to_string(),
            "lease".to_string(),
            1,
            "allocation".to_string(),
        );
        assert!(handle.begin_runtime_intent(&intent).is_err());
        assert!(handle.begin_start_operation().is_err());
        assert!(handle.begin_create_readback_operation().is_err());
        assert!(handle.begin_runtime_release().is_err());
        assert_eq!(
            handle.runtime_owner().unwrap().state(),
            RuntimeOwnerState::Empty
        );

        assert!(!handle
            .scanner_publish_failure_if_current(
                &in_progress,
                "INTERNAL",
                "scanner must not replace delete failure",
                None,
            )
            .unwrap());
        handle.request_cleanup("duplicate delete action").unwrap();
        let duplicate = handle.read_record().unwrap();
        assert_eq!(duplicate.phase, LifecyclePhase::ContainerdCommitted);
        assert_eq!(duplicate.failure, failed.failure);

        handle.finish_create_waiter().unwrap();
        let drained = handle.read_record().unwrap();
        assert!(drained.failure.as_ref().unwrap().drained);
        handle.request_cleanup("drained delete action").unwrap();
        let cleanup = handle.read_record().unwrap();
        assert_eq!(cleanup.phase, LifecyclePhase::CleanupRequired);
        assert_eq!(
            cleanup.failure,
            failed.failure.map(|mut failure| {
                failure.drained = true;
                failure
            })
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scanner_fences_and_handoffs_before_waiting_for_operation_barrier() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-scanner-fence-before-barrier-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        fs::create_dir_all(queue.join(HOST_QUEUE_DIRECTORY)).unwrap();
        fs::create_dir_all(queue.join(RUNTIME_QUEUE_DIRECTORY)).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 17,
                    identity: server,
                    revoked_epoch: None,
                };
                record.create_state = CreateState::InProgress;
                Ok(())
            })
            .unwrap();
        let operation = handle
            .begin_runtime_intent(&RuntimeResourceOwner::intent(
                "/run/cubelet.sock".to_string(),
                "sandbox".to_string(),
                "lease".to_string(),
                1,
                "allocation".to_string(),
            ))
            .unwrap();

        let snapshot = handle.read_record().unwrap();
        let publisher = handle.clone();
        let (published_tx, published_rx) = mpsc::channel();
        let publish_thread = thread::spawn(move || {
            published_tx
                .send(publisher.scanner_publish_failure_if_current(
                    &snapshot,
                    "DEADLINE_EXCEEDED",
                    "provider operation stuck",
                    None,
                ))
                .unwrap();
        });
        assert!(published_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("scanner failure publication waited for operation.lock")
            .unwrap());
        publish_thread.join().unwrap();

        let failed = handle.read_record().unwrap();
        assert_eq!(failed.create_state, CreateState::Failed);
        assert_eq!(failed.operation_owner.epoch, 18);
        assert_eq!(failed.operation_owner.revoked_epoch, Some(17));
        assert!(operation.verify().is_err());

        let cleanup = handle.clone();
        let cleanup_queue = queue.clone();
        let (handoff_tx, handoff_rx) = mpsc::channel();
        let handoff_thread = thread::spawn(move || {
            let result = (|| {
                let current = cleanup.read_record()?;
                if !cleanup.scanner_request_cleanup_if_current(
                    &current,
                    "provider operation stuck",
                    None,
                )? {
                    return Err("scanner cleanup snapshot unexpectedly changed".to_string());
                }
                ensure_cleanup_handoff(&cleanup, &cleanup_queue)?;
                Ok(cleanup.read_record()?.phase)
            })();
            handoff_tx.send(result).unwrap();
        });
        assert_eq!(
            handoff_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("scanner owner handoff waited for operation.lock")
                .unwrap(),
            LifecyclePhase::CleanupOwnersDurable
        );
        handoff_thread.join().unwrap();

        let queued: RuntimeCleanupJob = read_json(&cleanup_queue_path(
            &queue,
            RUNTIME_QUEUE_DIRECTORY,
            "fixture-generation",
        ))
        .unwrap();
        assert_eq!(queued.owner.state(), RuntimeOwnerState::Intent);
        assert!(!queued.ready_for_cleanup);
        drop(operation);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn cleanup_signals_stuck_server_before_operation_barrier() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-signal-before-barrier-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        fs::create_dir_all(queue.join(HOST_QUEUE_DIRECTORY)).unwrap();
        fs::create_dir_all(queue.join(RUNTIME_QUEUE_DIRECTORY)).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let mut child = ProcessCommand::new("sleep").arg("5").spawn().unwrap();
        let child_identity = process_identity(child.id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.server = Some(child_identity.clone());
                record.target = HostTarget::Legacy {
                    cgroup: child_identity.cgroup.clone(),
                };
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 23,
                    identity: child_identity.clone(),
                    revoked_epoch: None,
                };
                record.create_state = CreateState::Failed;
                record.failure = Some(FailureResult {
                    code: "DEADLINE_EXCEEDED".to_string(),
                    message: "provider operation stuck".to_string(),
                    published_at_ms: unix_time_ms().unwrap(),
                    waiter_count: 0,
                    drained: true,
                });
                Ok(())
            })
            .unwrap();
        let runtime_owner = RuntimeResourceOwner::intent(
            "/run/cubelet.sock".to_string(),
            "sandbox".to_string(),
            "lease".to_string(),
            1,
            "allocation".to_string(),
        );
        let mut runtime_owner = runtime_owner;
        runtime_owner.generation_id = "fixture-generation".to_string();
        atomic_write_json(&handle.directory.join(RUNTIME_OWNER_FILE), &runtime_owner).unwrap();

        let child_dead = Arc::new(AtomicBool::new(false));
        let reaped = Arc::clone(&child_dead);
        let reaper = thread::spawn(move || {
            child.wait().unwrap();
            reaped.store(true, Ordering::Release);
        });
        let lock_handle = handle.clone();
        let lock_released = Arc::clone(&child_dead);
        let (locked_tx, locked_rx) = mpsc::channel();
        let holder = thread::spawn(move || {
            let operation_lock = lock_handle.operation_lock().unwrap();
            locked_tx.send(()).unwrap();
            while !lock_released.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(5));
            }
            drop(operation_lock);
        });
        locked_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let snapshot = handle.read_record().unwrap();
        assert!(handle
            .scanner_request_cleanup_if_current(&snapshot, "provider operation stuck", None)
            .unwrap());
        ensure_cleanup_handoff(&handle, &queue).unwrap();
        assert_eq!(
            handle.read_record().unwrap().phase,
            LifecyclePhase::CleanupOwnersDurable
        );

        let started = std::time::Instant::now();
        converge_cleanup(&handle, &queue).await.unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cleanup waited for operation.lock before signalling the server"
        );
        reaper.join().unwrap();
        holder.join().unwrap();
        assert_eq!(
            handle.read_record().unwrap().phase,
            LifecyclePhase::ServerStopped
        );
        let host: HostCleanupJob = read_json(&cleanup_queue_path(
            &queue,
            HOST_QUEUE_DIRECTORY,
            "fixture-generation",
        ))
        .unwrap();
        let runtime: RuntimeCleanupJob = read_json(&cleanup_queue_path(
            &queue,
            RUNTIME_QUEUE_DIRECTORY,
            "fixture-generation",
        ))
        .unwrap();
        assert!(host.ready_for_cleanup);
        assert!(runtime.ready_for_cleanup);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn dropped_create_waiter_never_publishes_operation_result() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-cancelled-waiter-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        handle
            .update_record(|record| {
                record.create_state = CreateState::InProgress;
                record.create_waiters = 1;
                Ok(())
            })
            .unwrap();
        let waiter = handle.create_waiter_guard();
        drop(waiter);
        let record = handle.read_record().unwrap();
        assert_eq!(record.create_waiters, 0);
        assert_eq!(record.create_state, CreateState::InProgress);
        assert!(record.failure.is_none());

        handle
            .create_publisher_guard()
            .success_until_durable()
            .await;
        assert_eq!(
            handle.read_record().unwrap().create_state,
            CreateState::Succeeded
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn create_result_publisher_retries_each_atomic_commit_stage_without_identity_loss() {
        for (index, stage) in ["temp", "file-fsync", "rename", "parent-fsync"]
            .into_iter()
            .enumerate()
        {
            let root = std::env::temp_dir().join(format!(
                "cube-host-cgroup-result-retry-{stage}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&root).unwrap();
            let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
            handle
                .update_record(|record| {
                    record.create_state = CreateState::InProgress;
                    record.create_waiters = 1;
                    Ok(())
                })
                .unwrap();
            File::create(atomic_write_failpoint_path(
                &handle.directory.join(RECORD_FILE),
                stage,
            ))
            .unwrap();
            let publisher = handle.create_publisher_guard();
            if index % 2 == 0 {
                tokio::time::timeout(Duration::from_secs(1), publisher.success_until_durable())
                    .await
                    .unwrap();
                assert_eq!(
                    handle.current_create_result().unwrap(),
                    Some(PersistedCreateResult::Succeeded)
                );
            } else {
                publisher
                    .failure_until_durable("INVALID_ARGUMENT", "exact semantic failure")
                    .await;
                assert_eq!(
                    handle.current_create_result().unwrap(),
                    Some(PersistedCreateResult::Failed {
                        code: "INVALID_ARGUMENT".to_string(),
                        message: "exact semantic failure".to_string(),
                    })
                );
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_first_create_detaches_exact_failure_across_all_atomic_stages() {
        for classification in [Classification::ManagedSandbox, Classification::LegacyTask] {
            for stage in ["temp", "file-fsync", "rename", "parent-fsync"] {
                let root = std::env::temp_dir().join(format!(
                    "cube-host-cgroup-cancelled-{classification:?}-{stage}-{}",
                    uuid::Uuid::new_v4()
                ));
                fs::create_dir_all(&root).unwrap();
                let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
                handle
                    .update_record(|record| {
                        record.classification = classification;
                        record.create_state = CreateState::InProgress;
                        record.create_waiters = 1;
                        Ok(())
                    })
                    .unwrap();
                File::create(atomic_write_failpoint_path(
                    &handle.directory.join(RECORD_FILE),
                    stage,
                ))
                .unwrap();

                // Models cancellation at after-create-commit, before either
                // the managed semantic path or the legacy handler has selected
                // its result. Drop must transfer ownership to a retry actor.
                drop(handle.create_publisher_guard());

                let expected = PersistedCreateResult::Failed {
                    code: "CANCELLED".to_string(),
                    message: "first Create operation ended before selecting its durable result"
                        .to_string(),
                };
                tokio::time::timeout(Duration::from_secs(1), async {
                    loop {
                        if handle.current_create_result().unwrap() == Some(expected.clone()) {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
                assert_ne!(
                    handle.read_record().unwrap().create_state,
                    CreateState::InProgress
                );
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn independent_cleanup_queues_work_without_lifecycle_source() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-independent-queue-{}",
            uuid::Uuid::new_v4()
        ));
        let queue = root.join("queue");
        fs::create_dir_all(queue.join(HOST_QUEUE_DIRECTORY)).unwrap();
        fs::create_dir_all(queue.join(RUNTIME_QUEUE_DIRECTORY)).unwrap();
        let generation = "orphaned-generation".to_string();
        let host_job = HostCleanupJob {
            owner: HostCgroupOwner {
                schema_version: SCHEMA_VERSION,
                generation: generation.clone(),
                namespace: "fixture".to_string(),
                instance_id: "fixture".to_string(),
                state: HostOwnerState::Empty,
                target: HostTarget::Legacy {
                    cgroup: current_process_cgroup(std::process::id() as i32).unwrap(),
                },
                original_cgroup: current_process_cgroup(std::process::id() as i32).unwrap(),
                server: None,
                controllers: None,
            },
            socket: SocketIdentity {
                path: root.join("absent.sock").display().to_string(),
                parent: file_identity(&root).unwrap(),
                device: None,
                inode: None,
                absent_at_prepare: true,
            },
            created_at_ms: unix_time_ms().unwrap(),
            lifecycle_root: root.join("no-lifecycle-source").display().to_string(),
            ready_for_cleanup: true,
        };
        atomic_write_json(
            &cleanup_queue_path(&queue, HOST_QUEUE_DIRECTORY, &generation),
            &host_job,
        )
        .unwrap();
        atomic_write_json(
            &cleanup_queue_path(&queue, RUNTIME_QUEUE_DIRECTORY, &generation),
            &RuntimeCleanupJob {
                owner: RuntimeResourceOwner::empty(generation.clone()),
                ready_for_cleanup: true,
            },
        )
        .unwrap();

        scan_host_cleanup_queue_once(&queue).await.unwrap();
        scan_runtime_cleanup_queue_once(&queue).await.unwrap();
        assert!(!cleanup_queue_path(&queue, HOST_QUEUE_DIRECTORY, &generation).exists());
        assert!(!cleanup_queue_path(&queue, RUNTIME_QUEUE_DIRECTORY, &generation).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn runtime_queue_replays_intent_and_allocated_without_lifecycle_source() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-runtime-owner-queue-{}",
            uuid::Uuid::new_v4()
        ));
        let queue = root.join("queue");
        fs::create_dir_all(queue.join(RUNTIME_QUEUE_DIRECTORY)).unwrap();
        let mut intent = RuntimeResourceOwner::intent(
            "/run/cubelet.sock".to_string(),
            "sandbox-intent".to_string(),
            "lease-intent".to_string(),
            1,
            "key-intent".to_string(),
        );
        intent.generation_id = "generation-intent".to_string();
        let mut allocated = RuntimeResourceOwner::intent(
            "/run/cubelet.sock".to_string(),
            "sandbox-allocated".to_string(),
            "lease-allocated".to_string(),
            2,
            "key-allocated".to_string(),
        );
        allocated.generation_id = "generation-allocated".to_string();
        allocated.mark_allocated();
        for owner in [intent, allocated] {
            atomic_write_json(
                &cleanup_queue_path(&queue, RUNTIME_QUEUE_DIRECTORY, &owner.generation_id),
                &RuntimeCleanupJob {
                    owner,
                    ready_for_cleanup: true,
                },
            )
            .unwrap();
        }
        let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = observed.clone();
        scan_runtime_cleanup_queue_once_with(&queue, move |owner| {
            let captured = captured.clone();
            async move {
                captured.lock().unwrap().push(owner.state());
                Ok(())
            }
        })
        .await
        .unwrap();
        let mut states = observed.lock().unwrap().clone();
        states.sort_by_key(|state| match state {
            RuntimeOwnerState::Intent => 0,
            RuntimeOwnerState::Allocated => 1,
            RuntimeOwnerState::Empty => 2,
            RuntimeOwnerState::Released => 3,
        });
        assert_eq!(
            states,
            vec![RuntimeOwnerState::Intent, RuntimeOwnerState::Allocated]
        );
        assert_eq!(
            fs::read_dir(queue.join(RUNTIME_QUEUE_DIRECTORY))
                .unwrap()
                .count(),
            0
        );
        assert!(!root.join("lifecycle").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_owner_cleanup_removes_pre_worker_sandbox_resources() {
        let sandbox_id = format!("s55d2a-local-cleanup-{}", uuid::Uuid::new_v4());
        let vm_dir = PathBuf::from(crate::common::utils::VM_PATH).join(&sandbox_id);
        if let Err(error) = fs::create_dir_all(&vm_dir) {
            // Unprivileged and filesystem-sandboxed test runners may expose
            // /run read-only. Privileged Host tests exercise the real path;
            // only an explicit access/EROFS environment skips this fixture.
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(libc::EROFS)
            {
                return;
            }
            panic!("create pre-worker VM fixture {}: {error}", vm_dir.display());
        }
        fs::write(vm_dir.join("pre-worker-marker"), b"durable cleanup fixture").unwrap();

        let owner = RuntimeResourceOwner::intent(
            "/run/cubelet.sock".to_string(),
            sandbox_id,
            "lease-local-cleanup".to_string(),
            1,
            "allocation-local-cleanup".to_string(),
        );
        cleanup_runtime_owner_local_resources(&owner).unwrap();
        assert!(!vm_dir.exists());

        // Cleanup replay remains idempotent after the directory is gone.
        cleanup_runtime_owner_local_resources(&owner).unwrap();
    }

    #[tokio::test]
    async fn host_queue_replays_managed_leaf_and_socket_without_lifecycle_source() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-managed-owner-queue-{}",
            uuid::Uuid::new_v4()
        ));
        let queue = root.join("queue");
        fs::create_dir_all(queue.join(HOST_QUEUE_DIRECTORY)).unwrap();
        let leaf = root.join("managed-leaf");
        fs::create_dir_all(&leaf).unwrap();
        let socket = root.join("managed.sock");
        let created_at_ms = unix_time_ms().unwrap().saturating_sub(1_000);
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(root).unwrap();
                return;
            }
            Err(error) => panic!("bind managed queue socket: {error}"),
        };
        drop(listener);
        let generation = "managed-generation".to_string();
        let job = HostCleanupJob {
            owner: HostCgroupOwner {
                schema_version: SCHEMA_VERSION,
                generation: generation.clone(),
                namespace: "fixture".to_string(),
                instance_id: "fixture".to_string(),
                state: HostOwnerState::Allocated,
                target: HostTarget::Cgroupfs {
                    oci_path: "/fixture".to_string(),
                    cgroup: "/fixture/managed-leaf".to_string(),
                    parent_identity: file_identity(&root).unwrap(),
                    leaf_identity: Some(file_identity(&leaf).unwrap()),
                },
                original_cgroup: "/fixture".to_string(),
                server: None,
                controllers: None,
            },
            socket: SocketIdentity {
                path: socket.display().to_string(),
                parent: file_identity(&root).unwrap(),
                device: None,
                inode: None,
                absent_at_prepare: true,
            },
            created_at_ms,
            lifecycle_root: root.display().to_string(),
            ready_for_cleanup: true,
        };
        atomic_write_json(
            &cleanup_queue_path(&queue, HOST_QUEUE_DIRECTORY, &generation),
            &job,
        )
        .unwrap();
        let cleanup_root = root.clone();
        let cleanup_leaf = leaf.clone();
        scan_host_cleanup_queue_once_with(&queue, move |job| {
            assert!(job.owner.target.managed());
            cleanup_socket_identity(
                &job.socket,
                job.created_at_ms,
                &job.owner.generation,
                &cleanup_root,
            )?;
            let HostTarget::Cgroupfs {
                leaf_identity: Some(expected),
                ..
            } = &job.owner.target
            else {
                return Err("expected managed cgroupfs fixture".to_string());
            };
            if file_identity(&cleanup_leaf)? != *expected {
                return Err("managed leaf identity changed".to_string());
            }
            fs::remove_dir(&cleanup_leaf).map_err(|error| format!("remove fixture leaf: {error}"))
        })
        .await
        .unwrap();
        assert!(!socket.exists());
        assert!(!leaf.exists());
        assert!(!cleanup_queue_path(&queue, HOST_QUEUE_DIRECTORY, &generation).exists());
        assert!(!root.join("lifecycle").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unregistered_bound_socket_is_detected_by_kernel_inode() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-live-socket-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("bait.sock");
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(root).unwrap();
                return;
            }
            Err(error) => panic!("bind live socket bait: {error}"),
        };
        assert!(socket_has_live_owner(&socket).unwrap());
        drop(listener);
        fs::remove_file(&socket).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unregistered_closed_socket_is_removed_after_stable_owner_scan() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-stale-socket-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("stale.sock");
        let created_at_ms = unix_time_ms().unwrap().saturating_sub(1_000);
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(root).unwrap();
                return;
            }
            Err(error) => panic!("bind stale socket fixture: {error}"),
        };
        drop(listener);
        let identity = SocketIdentity {
            path: socket.display().to_string(),
            parent: file_identity(&root).unwrap(),
            device: None,
            inode: None,
            absent_at_prepare: true,
        };

        cleanup_socket_identity(&identity, created_at_ms, "fixture-generation", &root).unwrap();
        assert!(!socket.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pidfd_fencing_terminates_only_the_recorded_identity() {
        let mut server = ProcessCommand::new("sleep").arg("30").spawn().unwrap();
        let mut bait = ProcessCommand::new("sleep").arg("30").spawn().unwrap();
        let expected = process_identity(server.id() as i32).unwrap();
        let observation = observe_process(&expected).unwrap();
        let ProcessObservation::Exact { pidfd, .. } = observation else {
            panic!("spawned server was not observed exactly");
        };

        signal_exact_process(&expected, &pidfd, false).unwrap();
        assert!(!server.wait().unwrap().success());
        assert!(bait.try_wait().unwrap().is_none());
        bait.kill().unwrap();
        bait.wait().unwrap();
    }

    #[test]
    fn stale_pidfd_is_gone_after_proc_disappears() {
        let mut expected = process_identity(std::process::id() as i32).unwrap();
        expected.pid = i32::MAX;
        assert!(matches!(
            observe_process(&expected).unwrap(),
            ProcessObservation::Gone
        ));
    }

    #[test]
    fn pidfd_einval_requires_confirmed_missing_proc_entry() {
        let einval = std::io::Error::from_raw_os_error(libc::EINVAL);
        let esrch = std::io::Error::from_raw_os_error(libc::ESRCH);
        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);

        assert!(pidfd_open_failure_means_gone(
            &einval,
            ProcPresence::Missing
        ));
        assert!(!pidfd_open_failure_means_gone(
            &einval,
            ProcPresence::Present
        ));
        assert!(!pidfd_open_failure_means_gone(
            &einval,
            ProcPresence::Unknown
        ));
        assert!(pidfd_open_failure_means_gone(&esrch, ProcPresence::Unknown));
        assert!(!pidfd_open_failure_means_gone(
            &eperm,
            ProcPresence::Missing
        ));
        assert!(process_identity_failure_means_gone(ProcPresence::Missing));
        assert!(!process_identity_failure_means_gone(ProcPresence::Present));
        assert!(!process_identity_failure_means_gone(ProcPresence::Unknown));
    }

    #[test]
    fn server_identity_reads_nonce_from_target_environment() {
        let nonce = vec![9_u8; 32];
        let mut child = ProcessCommand::new("sleep")
            .arg("30")
            .env(LAUNCH_NONCE_ENV, bytes_hex(&nonce))
            .spawn()
            .unwrap();
        let actual = (0..100)
            .find_map(|_| {
                let identity = server_process_identity(child.id() as i32).ok();
                if identity.is_none() {
                    std::thread::sleep(Duration::from_millis(10));
                }
                identity
            })
            .expect("capture child nonce from /proc environment");
        assert_eq!(actual.launch_nonce_sha256, Some(sha256_hex(&nonce)));
        let mut forged = actual.clone();
        forged.launch_nonce_sha256 = Some(sha256_hex(b"caller supplied fake nonce"));
        assert!(matches!(
            observe_process(&forged).unwrap(),
            ProcessObservation::Reused
        ));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn revoked_server_epoch_cannot_publish_runtime_side_effect() {
        let root =
            std::env::temp_dir().join(format!("cube-host-cgroup-epoch-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 7,
                    identity: server,
                    revoked_epoch: None,
                };
                record.create_state = CreateState::Succeeded;
                Ok(())
            })
            .unwrap();
        let operation = handle.begin_runtime_release().unwrap();

        handle.request_cleanup("epoch race").unwrap();

        assert!(operation.mark_released().is_err());
        assert_eq!(handle.read_record().unwrap().operation_owner.epoch, 8);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn revoked_epoch_cannot_replace_empty_handoff_with_runtime_intent() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-intent-race-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 7,
                    identity: server,
                    revoked_epoch: None,
                };
                Ok(())
            })
            .unwrap();
        handle.request_cleanup("revoke before intent").unwrap();
        ensure_cleanup_handoff(&handle, &queue).unwrap();

        let intent = RuntimeResourceOwner::intent(
            "/run/cubelet.sock".to_string(),
            "sandbox".to_string(),
            "lease".to_string(),
            1,
            "allocation".to_string(),
        );
        assert!(handle.begin_runtime_intent(&intent).is_err());
        assert_eq!(
            handle.runtime_owner().unwrap().state(),
            RuntimeOwnerState::Empty
        );
        let queued: RuntimeCleanupJob = read_json(
            &queue
                .join(RUNTIME_QUEUE_DIRECTORY)
                .join("fixture-generation.json"),
        )
        .unwrap();
        assert_eq!(queued.owner.state(), RuntimeOwnerState::Empty);
        assert!(!queued.ready_for_cleanup);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn revoke_at_pre_tap_preserves_durable_intent_for_cleanup() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-pre-tap-revoke-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 7,
                    identity: server,
                    revoked_epoch: None,
                };
                record.create_state = CreateState::InProgress;
                Ok(())
            })
            .unwrap();
        let prepare = handle
            .begin_runtime_intent(&RuntimeResourceOwner::intent(
                "/run/cubelet.sock".to_string(),
                "sandbox".to_string(),
                "lease".to_string(),
                1,
                "allocation".to_string(),
            ))
            .unwrap();
        prepare.mark_allocated().unwrap();
        drop(prepare);
        handle
            .update_record(|record| {
                record.create_state = CreateState::Succeeded;
                Ok(())
            })
            .unwrap();

        let start = handle.begin_start_operation().unwrap();
        start
            .mark_tap_intent("provider-release=sandbox/lease")
            .unwrap();
        handle.request_cleanup("revoke at pre-start-tap").unwrap();
        assert!(start.verify().is_err());
        drop(start);
        ensure_cleanup_handoff(&handle, &queue).unwrap();
        let queued: RuntimeCleanupJob = read_json(&cleanup_queue_path(
            &queue,
            RUNTIME_QUEUE_DIRECTORY,
            "fixture-generation",
        ))
        .unwrap();
        assert_eq!(queued.owner.tap_state, ForwardResourceState::Intent);
        assert_eq!(queued.owner.vm_state, ForwardResourceState::None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn revoke_after_runtime_intent_before_prepare_rpc_is_cleanup_replayable() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-runtime-pre-rpc-revoke-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 9,
                    identity: server,
                    revoked_epoch: None,
                };
                record.create_state = CreateState::InProgress;
                Ok(())
            })
            .unwrap();
        let operation = handle
            .begin_runtime_intent(&RuntimeResourceOwner::intent(
                "/run/cubelet.sock".to_string(),
                "sandbox".to_string(),
                "lease".to_string(),
                1,
                "allocation".to_string(),
            ))
            .unwrap();
        handle
            .request_cleanup("revoke after INTENT before provider RPC")
            .unwrap();
        assert!(operation.verify().is_err());
        drop(operation);
        handle
            .request_cleanup("drain cancelled Create after INTENT")
            .unwrap();
        ensure_cleanup_handoff(&handle, &queue).unwrap();
        let queued: RuntimeCleanupJob = read_json(&cleanup_queue_path(
            &queue,
            RUNTIME_QUEUE_DIRECTORY,
            "fixture-generation",
        ))
        .unwrap();
        assert_eq!(queued.owner.state(), RuntimeOwnerState::Intent);
        assert_eq!(
            queued.owner.release_identity(),
            Some(("/run/cubelet.sock", "sandbox", "lease", 1))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn revoke_at_pre_vm_preserves_tap_and_vm_cleanup_identity() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-pre-vm-revoke-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 11,
                    identity: server,
                    revoked_epoch: None,
                };
                record.create_state = CreateState::InProgress;
                Ok(())
            })
            .unwrap();
        let prepare = handle
            .begin_runtime_intent(&RuntimeResourceOwner::intent(
                "/run/cubelet.sock".to_string(),
                "sandbox".to_string(),
                "lease".to_string(),
                1,
                "allocation".to_string(),
            ))
            .unwrap();
        prepare.mark_allocated().unwrap();
        drop(prepare);
        handle
            .update_record(|record| {
                record.create_state = CreateState::Succeeded;
                Ok(())
            })
            .unwrap();

        let start = handle.begin_start_operation().unwrap();
        start
            .mark_tap_intent("provider-release=sandbox/lease")
            .unwrap();
        start.mark_tap_allocated_and_vm_intent().unwrap();
        handle.request_cleanup("revoke at pre-start-vm").unwrap();
        assert!(start.verify().is_err());
        drop(start);
        ensure_cleanup_handoff(&handle, &queue).unwrap();
        let queued: RuntimeCleanupJob = read_json(&cleanup_queue_path(
            &queue,
            RUNTIME_QUEUE_DIRECTORY,
            "fixture-generation",
        ))
        .unwrap();
        assert_eq!(queued.owner.tap_state, ForwardResourceState::Allocated);
        assert_eq!(queued.owner.vm_state, ForwardResourceState::Intent);
        assert!(queued.owner.vm_cleanup_identity.is_some());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn combined_tap_and_vm_transition_is_guarded_and_atomic() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-combined-runtime-transition-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 12,
                    identity: server,
                    revoked_epoch: None,
                };
                record.create_state = CreateState::InProgress;
                Ok(())
            })
            .unwrap();
        let prepare = handle
            .begin_runtime_intent(&RuntimeResourceOwner::intent(
                "/run/cubelet.sock".to_string(),
                "sandbox".to_string(),
                "lease".to_string(),
                1,
                "allocation".to_string(),
            ))
            .unwrap();
        prepare.mark_allocated().unwrap();
        drop(prepare);
        handle
            .update_record(|record| {
                record.create_state = CreateState::Succeeded;
                Ok(())
            })
            .unwrap();

        let start = handle.begin_start_operation().unwrap();
        assert!(start.mark_tap_allocated_and_vm_intent().is_err());
        let before = handle.runtime_owner().unwrap();
        assert_eq!(before.tap_state, ForwardResourceState::None);
        assert_eq!(before.vm_state, ForwardResourceState::None);
        assert!(before.vm_cleanup_identity.is_none());

        start
            .mark_tap_intent("provider-release=sandbox/lease")
            .unwrap();
        start.mark_tap_allocated_and_vm_intent().unwrap();
        let committed = handle.runtime_owner().unwrap();
        assert_eq!(committed.tap_state, ForwardResourceState::Allocated);
        assert_eq!(committed.vm_state, ForwardResourceState::Intent);
        assert!(committed.vm_cleanup_identity.is_some());

        assert!(start.mark_tap_allocated_and_vm_intent().is_err());
        let after_rejected_retry = handle.runtime_owner().unwrap();
        assert_eq!(after_rejected_retry, committed);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn combined_tap_and_vm_transition_survives_every_atomic_write_failure() {
        for (index, stage) in ["temp", "file-fsync", "rename", "parent-fsync"]
            .into_iter()
            .enumerate()
        {
            let root = std::env::temp_dir().join(format!(
                "cube-host-cgroup-combined-runtime-fail-{stage}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&root).unwrap();
            let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
            let server = process_identity(std::process::id() as i32).unwrap();
            handle
                .update_record(|record| {
                    record.operation_owner = OperationOwner {
                        kind: OwnerKind::Server,
                        epoch: 20 + index as u64,
                        identity: server,
                        revoked_epoch: None,
                    };
                    record.create_state = CreateState::InProgress;
                    Ok(())
                })
                .unwrap();
            let prepare = handle
                .begin_runtime_intent(&RuntimeResourceOwner::intent(
                    "/run/cubelet.sock".to_string(),
                    "sandbox".to_string(),
                    "lease".to_string(),
                    1,
                    "allocation".to_string(),
                ))
                .unwrap();
            prepare.mark_allocated().unwrap();
            drop(prepare);
            handle
                .update_record(|record| {
                    record.create_state = CreateState::Succeeded;
                    Ok(())
                })
                .unwrap();

            let start = handle.begin_start_operation().unwrap();
            start
                .mark_tap_intent("provider-release=sandbox/lease")
                .unwrap();
            File::create(atomic_write_failpoint_path(
                &handle.directory.join(RUNTIME_OWNER_FILE),
                stage,
            ))
            .unwrap();
            assert!(start.mark_tap_allocated_and_vm_intent().is_err());

            let owner = handle.runtime_owner().unwrap();
            assert_eq!(
                (owner.tap_state, owner.vm_state),
                if stage == "parent-fsync" {
                    (
                        ForwardResourceState::Allocated,
                        ForwardResourceState::Intent,
                    )
                } else {
                    (ForwardResourceState::Intent, ForwardResourceState::None)
                },
                "stage={stage}"
            );
            assert_eq!(
                owner.tap_cleanup_identity.as_deref(),
                Some("provider-release=sandbox/lease"),
                "stage={stage}"
            );
            assert_eq!(
                owner.vm_cleanup_identity.is_some(),
                stage == "parent-fsync",
                "stage={stage}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn host_reconcile_failure_does_not_park_runtime_cleanup_queue() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-reconcile-independent-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        let handle = lifecycle_fixture(&root, LifecyclePhase::CleanupRequired);
        handle
            .update_record(|record| {
                record.target = HostTarget::Cgroupfs {
                    oci_path: "/fixture.slice:cri:fixture".to_string(),
                    cgroup: "/fixture.slice/cri-fixture.scope".to_string(),
                    parent_identity: file_identity(&root).unwrap(),
                    leaf_identity: None,
                };
                Ok(())
            })
            .unwrap();
        let mut owner: HostCgroupOwner =
            read_json(&handle.directory.join(HOST_OWNER_FILE)).unwrap();
        owner.state = HostOwnerState::Intent;
        atomic_write_json(&handle.directory.join(HOST_OWNER_FILE), &owner).unwrap();
        // Leave the Host owner at its original target to force a
        // reconciliation error while keeping both canonical owner files valid.
        let error = converge_cleanup(&handle, &queue).await.unwrap_err();
        assert!(error.contains("Host target identity reconciliation"));
        let record = handle.read_record().unwrap();
        assert_eq!(record.phase, LifecyclePhase::ServerStopped);
        let runtime: RuntimeCleanupJob = read_json(&cleanup_queue_path(
            &queue,
            RUNTIME_QUEUE_DIRECTORY,
            &record.generation,
        ))
        .unwrap();
        assert!(runtime.ready_for_cleanup);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_does_not_enable_runtime_consumer_before_operation_barrier() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-operation-barrier-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 19,
                    identity: server,
                    revoked_epoch: None,
                };
                record.create_state = CreateState::Succeeded;
                Ok(())
            })
            .unwrap();
        let operation = handle.begin_start_operation().unwrap();
        handle.request_cleanup("operation barrier fixture").unwrap();

        let worker_handle = handle.clone();
        let worker_queue = queue.clone();
        let worker = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(converge_cleanup(&worker_handle, &worker_queue))
        });
        let runtime_path =
            cleanup_queue_path(&queue, RUNTIME_QUEUE_DIRECTORY, "fixture-generation");
        for _ in 0..100 {
            if runtime_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let queued: RuntimeCleanupJob = read_json(&runtime_path).unwrap();
        assert!(!queued.ready_for_cleanup);
        drop(operation);
        worker.join().unwrap().unwrap();
        let queued: RuntimeCleanupJob = read_json(&runtime_path).unwrap();
        assert!(queued.ready_for_cleanup);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn create_readback_rejects_cleanup_revoked_between_inspect_and_return() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-create-readback-revoke-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 23,
                    identity: server,
                    revoked_epoch: None,
                };
                record.create_state = CreateState::Succeeded;
                Ok(())
            })
            .unwrap();

        let readback = handle.begin_create_readback_operation().unwrap();
        readback.verify().unwrap(); // exact provider Inspect returns here
        handle
            .request_cleanup("revoke after provider Inspect")
            .unwrap();

        let worker_handle = handle.clone();
        let worker_queue = queue.clone();
        let worker = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(converge_cleanup(&worker_handle, &worker_queue))
        });
        let runtime_path =
            cleanup_queue_path(&queue, RUNTIME_QUEUE_DIRECTORY, "fixture-generation");
        for _ in 0..100 {
            if runtime_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let queued: RuntimeCleanupJob = read_json(&runtime_path).unwrap();
        assert!(!queued.ready_for_cleanup);
        assert!(readback.verify().unwrap_err().contains("revoked"));
        drop(readback);
        worker.join().unwrap().unwrap();
        let queued: RuntimeCleanupJob = read_json(&runtime_path).unwrap();
        assert!(queued.ready_for_cleanup);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn create_readback_success_linearizes_before_later_cleanup() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-create-readback-success-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let queue = root.join("queue");
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 29,
                    identity: server,
                    revoked_epoch: None,
                };
                record.create_state = CreateState::Succeeded;
                Ok(())
            })
            .unwrap();

        let readback = handle.begin_create_readback_operation().unwrap();
        readback.verify().unwrap(); // before provider Inspect
        readback.verify().unwrap(); // post-Inspect Create success point
        handle
            .request_cleanup("cleanup overlaps Create response delivery")
            .unwrap();

        let worker_handle = handle.clone();
        let worker_queue = queue.clone();
        let worker = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(converge_cleanup(&worker_handle, &worker_queue))
        });
        let runtime_path =
            cleanup_queue_path(&queue, RUNTIME_QUEUE_DIRECTORY, "fixture-generation");
        for _ in 0..100 {
            if runtime_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let queued: RuntimeCleanupJob = read_json(&runtime_path).unwrap();
        assert!(!queued.ready_for_cleanup);
        drop(readback); // Create response may now return; cleanup can proceed.
        worker.join().unwrap().unwrap();
        let queued: RuntimeCleanupJob = read_json(&runtime_path).unwrap();
        assert!(queued.ready_for_cleanup);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn containment_drift_cannot_commit_runtime_intent() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-containment-intent-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let server = process_identity(std::process::id() as i32).unwrap();
        handle
            .update_record(|record| {
                record.target = HostTarget::Legacy {
                    cgroup: "/forged-cgroup".to_string(),
                };
                record.operation_owner = OperationOwner {
                    kind: OwnerKind::Server,
                    epoch: 9,
                    identity: server,
                    revoked_epoch: None,
                };
                Ok(())
            })
            .unwrap();
        let intent = RuntimeResourceOwner::intent(
            "/run/cubelet.sock".to_string(),
            "sandbox".to_string(),
            "lease".to_string(),
            1,
            "allocation".to_string(),
        );
        assert!(handle.begin_runtime_intent(&intent).is_err());
        assert_eq!(
            handle.runtime_owner().unwrap().state(),
            RuntimeOwnerState::Empty
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_containment_observation_is_durable_with_filesystem_identity() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-containment-audit-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::ContainerdCommitted);
        let observed = current_process_cgroup(std::process::id() as i32).unwrap();
        handle
            .request_containment_cleanup(&observed, "fixture breach")
            .unwrap();
        let record = handle.read_record().unwrap();
        let breach = record.containment_breach.unwrap();
        assert_eq!(breach.cgroup, observed);
        assert!(breach.device.is_some());
        assert!(breach.inode.is_some());
        assert_eq!(record.phase, LifecyclePhase::CleanupRequired);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn old_socket_identity_never_unlinks_new_generation_socket() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-socket-generation-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::SocketReady);
        let socket = root.join("shim.sock");
        let old_listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                // The local agent sandbox forbids AF_UNIX creation. The same
                // test is mandatory in the privileged cloud validation.
                fs::remove_dir_all(root).unwrap();
                return;
            }
            Err(error) => panic!("bind old socket generation: {error}"),
        };
        let old_metadata = fs::symlink_metadata(&socket).unwrap();
        handle
            .update_record(|record| {
                record.socket.device = Some(old_metadata.dev());
                record.socket.inode = Some(old_metadata.ino());
                Ok(())
            })
            .unwrap();
        let old_record = handle.read_record().unwrap();
        // Keep the old socket object alive while replacing its path. If it is
        // closed first, the filesystem may immediately reuse its inode for
        // the new generation and make this identity-fencing test flaky.
        fs::remove_file(&socket).unwrap();
        let new_listener = UnixListener::bind(&socket).unwrap();
        let new_metadata = fs::symlink_metadata(&socket).unwrap();
        assert_ne!(old_metadata.ino(), new_metadata.ino());
        drop(old_listener);

        assert!(cleanup_socket_identity(
            &old_record.socket,
            old_record.created_at_ms,
            &old_record.generation,
            &root,
        )
        .is_err());
        assert_eq!(
            fs::symlink_metadata(&socket).unwrap().ino(),
            new_metadata.ino()
        );
        drop(new_listener);
        fs::remove_file(&socket).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn second_prepared_lifecycle_cannot_reserve_same_socket_before_bind() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-socket-reservation-{}",
            uuid::Uuid::new_v4()
        ));
        let lifecycle_root = root.join("lifecycles");
        let socket_root = root.join("sockets");
        let first_bundle = root.join("bundle-a");
        let second_bundle = root.join("bundle-b");
        for directory in [&lifecycle_root, &socket_root, &first_bundle, &second_bundle] {
            fs::create_dir_all(directory).unwrap();
        }
        let socket = socket_root.join("shim.sock");
        let address = format!("unix://{}", socket.display());
        let identity = process_identity(std::process::id() as i32).unwrap();
        let target = HostTarget::Legacy {
            cgroup: identity.cgroup,
        };
        let executable = std::env::current_exe().unwrap();
        let first = LifecycleHandle::create(
            &lifecycle_root,
            &params("k8s.io", "same-sandbox"),
            &first_bundle,
            Classification::LegacyTask,
            target.clone(),
            &address,
            b"first-nonce",
            &executable,
            false,
        )
        .unwrap();
        assert!(!socket.exists());

        let error = LifecycleHandle::create(
            &lifecycle_root,
            &params("k8s.io", "same-sandbox"),
            &second_bundle,
            Classification::LegacyTask,
            target,
            &address,
            b"second-nonce",
            &executable,
            false,
        )
        .unwrap_err();
        assert!(error.contains("already reserved"));
        assert_eq!(
            fs::read_dir(&lifecycle_root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.path().join(RECORD_FILE).is_file())
                .count(),
            1
        );
        drop(first);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lexical_and_symlink_socket_aliases_cannot_acquire_a_second_path_lock() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-socket-alias-{}",
            uuid::Uuid::new_v4()
        ));
        let lock_root = root.join("lifecycles");
        let socket_root = root.join("sockets");
        let child = socket_root.join("child");
        fs::create_dir_all(&lock_root).unwrap();
        fs::create_dir_all(&child).unwrap();
        let canonical = socket_root.join("shim.sock");
        let _guard = acquire_socket_path_lock(&lock_root, &canonical).unwrap();

        let lexical_alias = child.join("..").join("shim.sock");
        assert!(acquire_socket_path_lock(&lock_root, &lexical_alias)
            .err()
            .unwrap()
            .contains("canonical parent"));

        let symlink_parent = root.join("socket-link");
        symlink(&socket_root, &symlink_parent).unwrap();
        let symlink_alias = symlink_parent.join("shim.sock");
        assert!(acquire_socket_path_lock(&lock_root, &symlink_alias)
            .err()
            .unwrap()
            .contains("canonical parent"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn socket_reservation_matches_parent_inode_across_bind_mount_spellings() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-socket-bind-alias-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::Prepared);
        handle
            .update_record(|record| {
                // Model a second bind-mount spelling of the same parent. The
                // stored parent device/inode remains the kernel identity.
                record.socket.path = "/different-bind-mount/shim.sock".to_string();
                Ok(())
            })
            .unwrap();

        assert!(another_record_owns_socket(&root, None, &root.join("shim.sock")).unwrap());
        assert!(!another_record_owns_socket(&root, None, &root.join("different.sock")).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn socket_path_lock_fences_final_check_from_next_generation_bind() {
        let root = std::env::temp_dir().join(format!(
            "cube-host-cgroup-socket-lock-race-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("shim.sock");
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(root).unwrap();
                return;
            }
            Err(error) => panic!("bind stale socket generation: {error}"),
        };
        drop(listener);
        let identity = SocketIdentity {
            path: socket.display().to_string(),
            parent: file_identity(&root).unwrap(),
            device: None,
            inode: None,
            absent_at_prepare: true,
        };
        let (at_unlink_tx, at_unlink_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let cleanup_root = root.clone();
        let cleanup = std::thread::spawn(move || {
            cleanup_socket_identity_with_hook(
                &identity,
                unix_time_ms().unwrap().saturating_sub(1_000),
                "old-generation",
                &cleanup_root,
                || {
                    at_unlink_tx.send(()).unwrap();
                    continue_rx.recv().unwrap();
                },
            )
        });
        at_unlink_rx.recv().unwrap();

        let (lock_acquired_tx, lock_acquired_rx) = std::sync::mpsc::channel();
        let bind_root = root.clone();
        let bind_socket = socket.clone();
        let next_generation = std::thread::spawn(move || {
            let _guard = acquire_socket_path_lock(&bind_root, &bind_socket).unwrap();
            lock_acquired_tx.send(()).unwrap();
            UnixListener::bind(&bind_socket).unwrap()
        });
        assert!(lock_acquired_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err());
        continue_tx.send(()).unwrap();
        cleanup.join().unwrap().unwrap();
        lock_acquired_rx.recv().unwrap();
        let new_listener = next_generation.join().unwrap();
        assert!(fs::symlink_metadata(&socket)
            .unwrap()
            .file_type()
            .is_socket());
        drop(new_listener);
        fs::remove_file(&socket).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scanner_adopts_only_full_nonce_executable_argv_bundle_match() {
        let root =
            std::env::temp_dir().join(format!("cube-host-cgroup-adopt-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let handle = lifecycle_fixture(&root, LifecyclePhase::Prepared);
        let nonce = vec![7_u8; 32];
        let mut child = ProcessCommand::new("sleep")
            .arg("30")
            .current_dir(&root)
            .env(LAUNCH_NONCE_ENV, bytes_hex(&nonce))
            .spawn()
            .unwrap();
        let identity = (0..100)
            .find_map(|_| {
                let identity = server_process_identity(child.id() as i32).ok();
                if identity.is_none() {
                    std::thread::sleep(Duration::from_millis(10));
                }
                identity
            })
            .expect("capture child nonce from /proc environment");
        handle
            .update_record(|record| {
                record.launch_nonce_sha256 = sha256_hex(&nonce);
                record.expected_server_path = fs::read_link(format!("/proc/{}/exe", child.id()))
                    .unwrap()
                    .display()
                    .to_string();
                record.expected_server_executable = identity.executable.clone();
                record.expected_server_command_sha256 = identity.command_sha256.clone();
                record.expected_server_argv = vec!["sleep".to_string(), "30".to_string()];
                record.bundle = root.display().to_string();
                record.bundle_identity = file_identity(&root).unwrap();
                record.target = HostTarget::Legacy {
                    cgroup: identity.cgroup.clone(),
                };
                Ok(())
            })
            .unwrap();

        let record = handle.read_record().unwrap();
        assert!(adopt_unregistered_server(&handle, &record).unwrap());
        let adopted = handle.read_record().unwrap().server.unwrap();
        assert_eq!(adopted.pid, child.id() as i32);
        assert!(immutable_identity_matches(&adopted, &identity));
        child.kill().unwrap();
        child.wait().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
