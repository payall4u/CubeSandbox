// Copyright (c) 2024 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use containerd_shim::asynchronous::ExitSignal;
use containerd_shim::protos::protobuf::{
    well_known_types::{any::Any, timestamp::Timestamp},
    MessageField,
};
use containerd_shim::protos::ttrpc::{r#async::TtrpcContext, Code, Error as TtrpcError};
use containerd_shim::protos::types::platform::Platform;
use containerd_shim::protos::{sandbox_api as api, sandbox_async::Sandbox};
use containerd_shim::TtrpcResult;
use oci_spec::runtime::Spec;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Notify};
use tokio::time::{sleep, Duration};

use crate::common::utils::Utils;
use crate::container::resources::RESOURCE_V2_CAPABILITY;
use crate::sandbox::sb;
use crate::service::host_cgroup::{
    lifecycle_from_env, BeginCreateError, CreateAdmission, CreatePublisherGuard, LifecycleHandle,
    PersistedCreateResult, RuntimeOwnerState,
};
use crate::service::runtime_resource::{self, RuntimeLease};
use crate::service::task_srv::TaskService;

const READY: &str = "SANDBOX_READY";
const NOT_READY: &str = "SANDBOX_NOTREADY";
const REQUIRED_SANDBOX_CAPABILITY: &str = "io.cubesandbox.agent.sandbox.lifecycle";
const OCI_SPEC_TYPE_URL: &str = "types.containerd.io/opencontainers/runtime-spec/1/Spec";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Unmanaged,
    Creating,
    Created,
    Starting,
    Ready,
    Stopping,
    Stopped,
    ReleasePending,
    Failed,
    ShuttingDown,
    Shutdown,
}

#[derive(Debug)]
struct LifecycleState {
    phase: Phase,
    create_request: Option<Vec<u8>>,
    sandbox_spec: Option<Any>,
    runtime: Option<RuntimeLease>,
    created_at: Option<Timestamp>,
    exited_at: Option<Timestamp>,
    exit_status: u32,
    last_error: Option<String>,
}

impl Default for LifecycleState {
    fn default() -> Self {
        Self {
            phase: Phase::Unmanaged,
            create_request: None,
            sandbox_spec: None,
            runtime: None,
            created_at: None,
            exited_at: None,
            exit_status: 0,
            last_error: None,
        }
    }
}

pub(crate) struct SandboxLifecycle {
    state: Mutex<LifecycleState>,
    task_creates: StdMutex<HashSet<String>>,
    changed: Notify,
}

impl Default for SandboxLifecycle {
    fn default() -> Self {
        Self {
            state: Mutex::new(LifecycleState::default()),
            task_creates: StdMutex::new(HashSet::new()),
            changed: Notify::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TaskMode {
    Legacy,
    ManagedReady { shared_root: PathBuf },
}

pub(crate) struct TaskCreateReservation {
    lifecycle: Arc<SandboxLifecycle>,
    task_id: String,
    mode: TaskMode,
}

impl TaskCreateReservation {
    pub(crate) fn mode(&self) -> &TaskMode {
        &self.mode
    }
}

impl Drop for TaskCreateReservation {
    fn drop(&mut self) {
        self.lifecycle
            .task_creates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.task_id);
        self.lifecycle.changed.notify_waiters();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownAction {
    AlreadyComplete,
    WaitForExisting,
    Run { force_abort: bool },
}

impl SandboxLifecycle {
    pub(crate) async fn managed_task_mode(&self) -> Result<TaskMode, String> {
        let state = self.state.lock().await;
        if state.phase != Phase::Ready {
            return Err(format!(
                "managed Sandbox is not ready (phase {:?})",
                state.phase
            ));
        }
        let runtime = state
            .runtime
            .as_ref()
            .ok_or_else(|| "ready sandbox has no RuntimeResource lease".to_string())?;
        Ok(TaskMode::ManagedReady {
            shared_root: runtime.shared_root()?,
        })
    }

    pub(crate) async fn task_mode(&self) -> Result<TaskMode, String> {
        let state = self.state.lock().await;
        match state.phase {
            Phase::Unmanaged => Ok(TaskMode::Legacy),
            Phase::Ready => {
                let runtime = state
                    .runtime
                    .as_ref()
                    .ok_or_else(|| "ready sandbox has no RuntimeResource lease".to_string())?;
                Ok(TaskMode::ManagedReady {
                    shared_root: runtime.shared_root()?,
                })
            }
            phase => Err(format!(
                "sandbox is managed by Sandbox Service but is not ready (phase {phase:?})"
            )),
        }
    }

    async fn begin_shutdown(&self) -> ShutdownAction {
        loop {
            let notified = self.changed.notified();
            let mut state = self.state.lock().await;
            if self.has_task_creates() {
                drop(state);
                notified.await;
                continue;
            }
            match state.phase {
                Phase::Creating | Phase::Starting | Phase::Stopping => {
                    drop(state);
                    notified.await;
                }
                Phase::Shutdown => return ShutdownAction::AlreadyComplete,
                Phase::ShuttingDown => return ShutdownAction::WaitForExisting,
                Phase::Stopped | Phase::ReleasePending => {
                    state.phase = Phase::ShuttingDown;
                    return ShutdownAction::Run { force_abort: false };
                }
                _ => {
                    state.phase = Phase::ShuttingDown;
                    return ShutdownAction::Run { force_abort: true };
                }
            }
        }
    }

    pub(crate) async fn reserve_task_create(
        self: &Arc<Self>,
        task_id: &str,
    ) -> Result<TaskCreateReservation, String> {
        let mode = self.task_mode().await?;
        let inserted = self
            .task_creates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(task_id.to_string());
        if !inserted {
            return Err(format!("task {task_id} Create is already in progress"));
        }
        Ok(TaskCreateReservation {
            lifecycle: self.clone(),
            task_id: task_id.to_string(),
            mode,
        })
    }

    pub(crate) async fn is_managed(&self) -> bool {
        self.state.lock().await.phase != Phase::Unmanaged
    }

    fn has_task_creates(&self) -> bool {
        !self
            .task_creates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    }
}

#[derive(Clone)]
pub struct SandboxService {
    id: String,
    sandbox: Arc<Mutex<sb::SandBox>>,
    lifecycle: Arc<SandboxLifecycle>,
    exit: Arc<ExitSignal>,
}

impl SandboxService {
    pub fn new(task: &TaskService) -> Self {
        Self {
            id: task.sandbox_id().to_string(),
            sandbox: task.sandbox(),
            lifecycle: task.sandbox_lifecycle(),
            exit: task.exit_signal(),
        }
    }

    fn validate_id(&self, id: &str) -> TtrpcResult<()> {
        if id.is_empty() {
            return Err(rpc_error(Code::INVALID_ARGUMENT, "sandbox_id is empty"));
        }
        if id != self.id {
            return Err(rpc_error(
                Code::NOT_FOUND,
                format!("sandbox_id {id} does not match shim {}", self.id),
            ));
        }
        Ok(())
    }

    async fn run_create(
        self,
        mut spec: Spec,
        netns_path: String,
        config: runtime_resource::CriPodSandboxConfig,
        plan: runtime_resource::RuntimePreparePlan,
        publisher: CreatePublisherGuard,
    ) {
        let total_started = Instant::now();
        let phase_started = Instant::now();
        let prepared =
            runtime_resource::prepare(&self.id, &netns_path, &config, &plan, &mut spec).await;
        crate::cube_perf!(
            "cube_perf component=shim operation=create phase=runtime-resource sandbox_id={} ts_mono_us={} duration_us={} success={}",
            self.id,
            Utils::monotonic_time_micros(),
            phase_started.elapsed().as_micros(),
            prepared.is_ok()
        );
        let phase_started = Instant::now();
        let result = match prepared {
            Ok(lease) => match self.sandbox.lock().await.init(spec) {
                Ok(()) => Ok(lease),
                Err(error) => match lease.release().await {
                    Ok(()) => Err((format!("initialize Cube sandbox: {error}"), None)),
                    Err(release_error) => Err((format!("initialize Cube sandbox: {error}; release RuntimeResource: {release_error}"), Some(lease))),
                },
            },
            Err(error) => Err((format!("prepare RuntimeResource: {error}"), None)),
        };
        let succeeded = result.is_ok();
        crate::cube_perf!(
            "cube_perf component=shim operation=create phase=sandbox-init sandbox_id={} ts_mono_us={} duration_us={} success={}",
            self.id,
            Utils::monotonic_time_micros(),
            phase_started.elapsed().as_micros(),
            succeeded
        );
        let phase_started = Instant::now();
        let mut state = self.lifecycle.state.lock().await;
        match result {
            Ok(lease) => {
                state.phase = Phase::Created;
                state.runtime = Some(lease);
                state.last_error = None;
                drop(state);
                publisher.success_until_durable().await;
            }
            Err((error, lease)) => {
                state.phase = Phase::Failed;
                state.runtime = lease;
                state.exit_status = 1;
                state.exited_at = Some(now_timestamp());
                state.last_error = Some(error.clone());
                drop(state);
                publisher
                    .failure_until_durable("FAILED_PRECONDITION", &error)
                    .await;
            }
        }
        self.lifecycle.changed.notify_waiters();
        crate::cube_perf!(
            "cube_perf component=shim operation=create phase=publish sandbox_id={} ts_mono_us={} duration_us={} total_us={} success={}",
            self.id,
            Utils::monotonic_time_micros(),
            phase_started.elapsed().as_micros(),
            total_started.elapsed().as_micros(),
            succeeded
        );
    }

    async fn validate_durable_create_success(
        &self,
        lifecycle: &LifecycleHandle,
        fingerprint: &[u8],
    ) -> Result<(), String> {
        let validation = async {
            // Linearize the non-allocating provider readback against cleanup.
            // Cleanup may durably revoke the epoch without this lock, but it
            // cannot release the provider lease until the operation barrier is
            // dropped. The post-Inspect verify therefore either observes that
            // revoke and rejects success, or establishes a success point before
            // cleanup is allowed to pass the barrier.
            let readback = lifecycle.begin_create_readback_operation()?;
            readback.verify_host_controllers()?;
            let runtime = {
                let state = self.lifecycle.state.lock().await;
                if !matches!(state.phase, Phase::Created | Phase::Starting | Phase::Ready) {
                    return Err(format!(
                        "durable CreateSandbox success has local phase {:?}",
                        state.phase
                    ));
                }
                if state.create_request.as_deref() != Some(fingerprint) {
                    return Err(
                        "durable CreateSandbox success has a different local request".to_string(),
                    );
                }
                if state.sandbox_spec.is_none() {
                    return Err("durable CreateSandbox success has no local OCI spec".to_string());
                }
                state
                    .runtime
                    .as_ref()
                    .ok_or_else(|| {
                        "durable CreateSandbox success has no RuntimeResource lease".to_string()
                    })?
                    .clone()
            };
            if !self.sandbox.lock().await.inited() {
                return Err(
                    "durable CreateSandbox success has no initialized Cube sandbox".to_string(),
                );
            }
            let runtime_identity = runtime.durable_identity();
            let owner = lifecycle.runtime_owner()?;
            if owner.state() != RuntimeOwnerState::Allocated
                || owner.release_identity()
                    != Some((
                        runtime_identity.0,
                        runtime_identity.1,
                        runtime_identity.2,
                        runtime_identity.3,
                    ))
            {
                return Err(
                    "durable CreateSandbox success does not match the RuntimeResource owner"
                        .to_string(),
                );
            }
            readback.verify()?;
            // This is non-allocating. A durable SUCCEEDED retry may never
            // replay PrepareSandbox; it must prove that the provider still has
            // exactly the committed lease and handles.
            runtime.inspect_exact().await?;
            lifecycle.wait_test_failpoint("after-create-inspect").await;
            readback.verify()?;
            Ok(())
        }
        .await;
        if let Err(error) = validation {
            let reason = format!("durable CreateSandbox success exact readback failed: {error}");
            lifecycle
                .request_degraded_cleanup(&reason)
                .map_err(|persist_error| {
                    format!("{reason}; persist terminal DEGRADED cleanup: {persist_error}")
                })?;
            return Err(reason);
        }
        Ok(())
    }

    async fn run_start(self) {
        let started = Instant::now();
        let lease = self.lifecycle.state.lock().await.runtime.clone();
        let result = if let Some(lease) = lease {
            self.run_start_with_lease(&lease).await
        } else {
            Err(StartFailure {
                error: "sandbox has no RuntimeResource lease".to_string(),
                cleanup: StartCleanup::Released,
            })
        };
        crate::cube_perf!(
            "cube_perf component=shim operation=start phase=managed-start sandbox_id={} ts_mono_us={} duration_us={} success={}",
            self.id,
            Utils::monotonic_time_micros(),
            started.elapsed().as_micros(),
            result.is_ok()
        );
        self.finish_start(result).await;
    }

    async fn run_start_with_lease(&self, lease: &RuntimeLease) -> Result<(), StartFailure> {
        let phase_started = Instant::now();
        let lifecycle = match lifecycle_from_env() {
            Ok(Some(lifecycle)) => lifecycle,
            Ok(None) => {
                return Err(release_after_start_failure(
                    lease,
                    "managed StartSandbox has no durable Host lifecycle".to_string(),
                )
                .await)
            }
            Err(error) => {
                return Err(release_after_start_failure(
                    lease,
                    format!("load durable Host lifecycle for StartSandbox: {error}"),
                )
                .await)
            }
        };
        let operation = match lifecycle.begin_start_operation() {
            Ok(operation) => operation,
            Err(error) => {
                return Err(release_after_start_failure(
                    lease,
                    format!("begin fenced StartSandbox operation: {error}"),
                )
                .await)
            }
        };
        if let Err(error) = operation.verify_host_controllers() {
            drop(operation);
            return Err(release_after_start_failure(
                lease,
                format!("Host controller readback before StartSandbox: {error}"),
            )
            .await);
        }
        crate::cube_perf!(
            "cube_perf component=shim operation=start phase=host-readback sandbox_id={} ts_mono_us={} duration_us={}",
            self.id,
            Utils::monotonic_time_micros(),
            phase_started.elapsed().as_micros()
        );

        let phase_started = Instant::now();
        let tap_cleanup_identity = match lease.tap_cleanup_identity() {
            Ok(identity) => identity,
            Err(error) => {
                drop(operation);
                return Err(release_after_start_failure(lease, error).await);
            }
        };
        if let Err(error) = operation.mark_tap_intent(&tap_cleanup_identity) {
            drop(operation);
            return Err(release_after_start_failure(
                lease,
                format!("persist TAP allocation INTENT: {error}"),
            )
            .await);
        }
        lifecycle.wait_test_failpoint("pre-start-tap").await;
        if let Err(error) = operation.verify() {
            drop(operation);
            return Err(release_after_start_failure(
                lease,
                format!("TAP allocation owner was revoked: {error}"),
            )
            .await);
        }
        crate::cube_perf!(
            "cube_perf component=shim operation=start phase=tap-intent sandbox_id={} ts_mono_us={} duration_us={}",
            self.id,
            Utils::monotonic_time_micros(),
            phase_started.elapsed().as_micros()
        );
        let phase_started = Instant::now();
        let tap = match lease.acquire_tap().await {
            Ok(tap) => tap,
            Err(error) => {
                drop(operation);
                return Err(release_after_start_failure(
                    lease,
                    format!("acquire RuntimeResource TAP: {error}"),
                )
                .await);
            }
        };
        crate::cube_perf!(
            "cube_perf component=shim operation=start phase=tap-handoff sandbox_id={} ts_mono_us={} duration_us={}",
            self.id,
            Utils::monotonic_time_micros(),
            phase_started.elapsed().as_micros()
        );
        let phase_started = Instant::now();
        if let Err(error) = operation.mark_tap_allocated_and_vm_intent() {
            drop(tap);
            drop(operation);
            return Err(release_after_start_failure(
                lease,
                format!("commit TAP allocation and VM INTENT: {error}"),
            )
            .await);
        }
        lifecycle.wait_test_failpoint("pre-start-vm").await;
        if let Err(error) = operation.verify() {
            drop(tap);
            drop(operation);
            return Err(release_after_start_failure(
                lease,
                format!("VM allocation owner was revoked: {error}"),
            )
            .await);
        }
        crate::cube_perf!(
            "cube_perf component=shim operation=start phase=vm-intent sandbox_id={} ts_mono_us={} duration_us={}",
            self.id,
            Utils::monotonic_time_micros(),
            phase_started.elapsed().as_micros()
        );

        let mut sandbox = self.sandbox.lock().await;
        sandbox.set_runtime_tap(tap);
        let phase_started = Instant::now();
        let started = async {
            Utils::record_pid().map_err(|error| format!("record shim pid: {error}"))?;
            operation
                .verify()
                .map_err(|error| format!("VM allocation owner was revoked: {error}"))?;
            sandbox.create_sandbox(Some(&operation)).await?;
            operation
                .mark_vm_allocated()
                .map_err(|error| format!("commit VM allocation identity: {error}"))?;
            if !sandbox.agent_supports(REQUIRED_SANDBOX_CAPABILITY, 1) {
                return Err(format!(
                    "guest agent lacks required capability {REQUIRED_SANDBOX_CAPABILITY}>=1"
                ));
            }
            if !sandbox.agent_supports(RESOURCE_V2_CAPABILITY, 1) {
                return Err(format!(
                    "guest agent lacks required capability {RESOURCE_V2_CAPABILITY}>=1"
                ));
            }
            Ok::<(), String>(())
        }
        .await;
        crate::cube_perf!(
            "cube_perf component=shim operation=start phase=guest-start sandbox_id={} ts_mono_us={} duration_us={} success={}",
            self.id,
            Utils::monotonic_time_micros(),
            phase_started.elapsed().as_micros(),
            started.is_ok()
        );
        match started {
            Ok(()) => {
                drop(sandbox);
                drop(operation);
                Ok(())
            }
            Err(error) => {
                let rollback_error = sandbox.abort_sandbox().await.err();
                if let Some(rollback_error) = rollback_error {
                    drop(sandbox);
                    drop(operation);
                    Err(StartFailure {
                        error: format!(
                            "{error}; rollback VM: {rollback_error}; RuntimeResource release skipped until teardown is confirmed"
                        ),
                        cleanup: StartCleanup::TeardownUnconfirmed,
                    })
                } else {
                    sandbox.clear_runtime_tap();
                    drop(sandbox);
                    drop(operation);
                    Err(release_after_start_failure(lease, error).await)
                }
            }
        }
    }

    async fn finish_start(&self, result: Result<(), StartFailure>) {
        let terminal_failure = result.is_err();
        let mut state = self.lifecycle.state.lock().await;
        apply_start_result(&mut state, result);
        let ready = state.phase == Phase::Ready;
        drop(state);
        self.lifecycle.changed.notify_waiters();
        if ready {
            tokio::spawn(self.clone().monitor_vm_exit());
        } else if terminal_failure {
            request_external_cleanup_durable("sandbox start failed terminally").await;
        }
    }

    async fn monitor_vm_exit(self) {
        loop {
            sleep(Duration::from_millis(500)).await;
            if self.lifecycle.state.lock().await.phase != Phase::Ready {
                return;
            }
            if self.sandbox.lock().await.vm_exited().await {
                let mut state = self.lifecycle.state.lock().await;
                if state.phase == Phase::Ready {
                    state.phase = Phase::Failed;
                    state.exit_status = 1;
                    state.exited_at = Some(now_timestamp());
                    state.last_error = Some("Cube VM exited unexpectedly".to_string());
                }
                drop(state);
                self.lifecycle.changed.notify_waiters();
                request_external_cleanup_durable("Cube VM exited unexpectedly").await;
                return;
            }
        }
    }

    async fn wait_for_start(&self) -> TtrpcResult<api::StartSandboxResponse> {
        loop {
            let notified = self.lifecycle.changed.notified();
            let state = self.lifecycle.state.lock().await;
            match state.phase {
                Phase::Ready => {
                    return Ok(api::StartSandboxResponse {
                        pid: std::process::id(),
                        created_at: state.created_at.clone().into(),
                        spec: state.sandbox_spec.clone().into(),
                        ..Default::default()
                    })
                }
                Phase::Failed => {
                    return Err(rpc_error(
                        Code::FAILED_PRECONDITION,
                        state
                            .last_error
                            .clone()
                            .unwrap_or_else(|| "sandbox start failed".to_string()),
                    ))
                }
                Phase::Starting => {
                    drop(state);
                    notified.await;
                }
                phase => {
                    return Err(rpc_error(
                        Code::FAILED_PRECONDITION,
                        format!("sandbox cannot finish start from phase {phase:?}"),
                    ))
                }
            }
        }
    }

    async fn run_stop(self, previous: Phase) {
        if previous != Phase::ReleasePending && !self.sandbox.lock().await.is_empty().await {
            self.finish_stop_guard(previous, "sandbox still contains containers".to_string())
                .await;
            return;
        }
        let lease = self.lifecycle.state.lock().await.runtime.clone();
        let result = teardown_then_release(
            || async {
                let mut sandbox = self.sandbox.lock().await;
                match stop_teardown_action(previous) {
                    StopTeardownAction::ReleaseOnly => Ok(TeardownOutcome::normal()),
                    StopTeardownAction::Abort => match sandbox.abort_sandbox().await {
                        Ok(()) => {
                            sandbox.clear_runtime_tap();
                            Ok(TeardownOutcome::forced(None))
                        }
                        Err(error) => Err(format!("force stop sandbox: {error}")),
                    },
                    StopTeardownAction::Destroy => match sandbox.destroy_sandbox().await {
                        Ok(()) => {
                            sandbox.clear_runtime_tap();
                            Ok(TeardownOutcome::normal())
                        }
                        Err(error) => match sandbox.abort_sandbox().await {
                            Ok(()) => {
                                sandbox.clear_runtime_tap();
                                Ok(TeardownOutcome::forced(Some(format!(
                                    "destroy sandbox: {error}; forced rollback"
                                ))))
                            }
                            Err(rollback) => Err(format!(
                                "destroy sandbox: {error}; forced rollback: {rollback}"
                            )),
                        },
                    },
                }
            },
            || async {
                if let Some(lease) = lease {
                    lease.release().await
                } else {
                    Ok(())
                }
            },
        )
        .await;
        self.finish_stop(previous, result).await;
    }

    async fn finish_stop_guard(&self, previous: Phase, error: String) {
        let mut state = self.lifecycle.state.lock().await;
        state.phase = previous;
        state.last_error = Some(error);
        drop(state);
        self.lifecycle.changed.notify_waiters();
    }

    async fn finish_stop(&self, previous: Phase, result: CleanupOutcome) {
        let mut state = self.lifecycle.state.lock().await;
        match result {
            CleanupOutcome::Released(teardown) => {
                state.runtime = None;
                if previous != Phase::ReleasePending {
                    freeze_exit(&mut state, teardown.forced);
                }
                state.phase = Phase::Stopped;
                if let Some(warning) = teardown.warning {
                    state.last_error = Some(warning);
                } else {
                    state.last_error = None;
                }
            }
            CleanupOutcome::ReleaseFailed(teardown, error) => {
                if previous != Phase::ReleasePending {
                    freeze_exit(&mut state, teardown.forced);
                }
                state.phase = Phase::ReleasePending;
                state.last_error = Some(append_error(
                    format!("release RuntimeResource: {error}"),
                    "sandbox teardown warning",
                    teardown.warning,
                ));
            }
            CleanupOutcome::TeardownFailed(error) => {
                state.phase = Phase::Failed;
                freeze_exit(&mut state, true);
                state.last_error = Some(error);
            }
        }
        let terminal_failure = matches!(state.phase, Phase::Failed | Phase::ReleasePending);
        drop(state);
        self.lifecycle.changed.notify_waiters();
        if terminal_failure {
            request_external_cleanup_durable("sandbox stop failed terminally").await;
        }
    }

    async fn wait_for_stop(&self) -> TtrpcResult<()> {
        loop {
            let notified = self.lifecycle.changed.notified();
            let state = self.lifecycle.state.lock().await;
            match state.phase {
                Phase::Stopped if state.last_error.is_some() => {
                    return Err(rpc_error(
                        Code::FAILED_PRECONDITION,
                        state.last_error.clone().unwrap(),
                    ))
                }
                Phase::Stopped | Phase::Shutdown => return Ok(()),
                Phase::ReleasePending => {
                    return Err(rpc_error(
                        Code::FAILED_PRECONDITION,
                        state
                            .last_error
                            .clone()
                            .unwrap_or_else(|| "RuntimeResource release is pending".to_string()),
                    ))
                }
                Phase::Failed | Phase::Ready | Phase::Created if state.last_error.is_some() => {
                    return Err(rpc_error(
                        Code::FAILED_PRECONDITION,
                        state.last_error.clone().unwrap(),
                    ))
                }
                Phase::Stopping => {
                    drop(state);
                    notified.await;
                }
                phase => {
                    return Err(rpc_error(
                        Code::FAILED_PRECONDITION,
                        format!("sandbox cannot finish stop from phase {phase:?}"),
                    ))
                }
            }
        }
    }

    async fn run_shutdown(self, force_abort: bool) {
        let lease = self.lifecycle.state.lock().await.runtime.clone();
        let result = teardown_then_release(
            || async {
                if !force_abort {
                    return Ok(TeardownOutcome::normal());
                }
                let mut sandbox = self.sandbox.lock().await;
                match sandbox.abort_sandbox().await {
                    Ok(()) => {
                        sandbox.clear_runtime_tap();
                        Ok(TeardownOutcome::forced(None))
                    }
                    Err(error) => Err(format!("force shutdown sandbox: {error}")),
                }
            },
            || async {
                if let Some(lease) = lease {
                    lease.release().await
                } else {
                    Ok(())
                }
            },
        )
        .await;
        let mut state = self.lifecycle.state.lock().await;
        match result {
            CleanupOutcome::Released(teardown) => {
                state.runtime = None;
                if force_abort {
                    freeze_exit(&mut state, teardown.forced);
                } else if state.exited_at.is_none() {
                    freeze_exit(&mut state, false);
                }
                state.phase = Phase::Stopped;
                if let Some(warning) = teardown.warning {
                    state.phase = Phase::Failed;
                    state.last_error = Some(warning);
                } else {
                    state.phase = Phase::Shutdown;
                    state.last_error = None;
                }
            }
            CleanupOutcome::ReleaseFailed(teardown, error) => {
                if force_abort {
                    freeze_exit(&mut state, teardown.forced);
                } else if state.exited_at.is_none() {
                    freeze_exit(&mut state, false);
                }
                state.phase = Phase::ReleasePending;
                state.last_error = Some(append_error(
                    format!("release RuntimeResource: {error}"),
                    "sandbox teardown warning",
                    teardown.warning,
                ));
            }
            CleanupOutcome::TeardownFailed(error) => {
                state.phase = Phase::Failed;
                freeze_exit(&mut state, true);
                state.last_error = Some(error);
            }
        }
        let shutdown = state.phase == Phase::Shutdown;
        let terminal_failure = matches!(state.phase, Phase::Failed | Phase::ReleasePending);
        drop(state);
        self.lifecycle.changed.notify_waiters();
        if shutdown {
            self.exit.signal();
        } else if terminal_failure {
            request_external_cleanup_durable("sandbox shutdown failed terminally").await;
        }
    }

    async fn wait_for_shutdown(&self) -> TtrpcResult<api::ShutdownSandboxResponse> {
        loop {
            let notified = self.lifecycle.changed.notified();
            let state = self.lifecycle.state.lock().await;
            match state.phase {
                Phase::Shutdown => return Ok(api::ShutdownSandboxResponse::new()),
                Phase::Failed | Phase::ReleasePending => {
                    return Err(rpc_error(
                        Code::INTERNAL,
                        state
                            .last_error
                            .clone()
                            .unwrap_or_else(|| "sandbox shutdown failed".to_string()),
                    ))
                }
                Phase::ShuttingDown => {
                    drop(state);
                    notified.await;
                }
                phase => {
                    return Err(rpc_error(
                        Code::FAILED_PRECONDITION,
                        format!("sandbox cannot finish shutdown from phase {phase:?}"),
                    ))
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartCleanup {
    Released,
    ReleasePending,
    TeardownUnconfirmed,
}

#[derive(Debug, Eq, PartialEq)]
struct StartFailure {
    error: String,
    cleanup: StartCleanup,
}

async fn release_after_start_failure(lease: &RuntimeLease, error: String) -> StartFailure {
    match lease.release().await {
        Ok(()) => StartFailure {
            error,
            cleanup: StartCleanup::Released,
        },
        Err(release_error) => StartFailure {
            error: format!("{error}; release RuntimeResource: {release_error}"),
            cleanup: StartCleanup::ReleasePending,
        },
    }
}

fn apply_start_result(state: &mut LifecycleState, result: Result<(), StartFailure>) {
    match result {
        Ok(()) => {
            state.phase = Phase::Ready;
            state.created_at = Some(now_timestamp());
            state.last_error = None;
        }
        Err(failure) => {
            state.phase = if failure.cleanup == StartCleanup::ReleasePending {
                Phase::ReleasePending
            } else {
                Phase::Failed
            };
            if failure.cleanup == StartCleanup::Released {
                state.runtime = None;
            }
            freeze_exit(state, true);
            state.last_error = Some(failure.error);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopTeardownAction {
    ReleaseOnly,
    Abort,
    Destroy,
}

fn stop_teardown_action(previous: Phase) -> StopTeardownAction {
    match previous {
        Phase::ReleasePending => StopTeardownAction::ReleaseOnly,
        Phase::Failed => StopTeardownAction::Abort,
        _ => StopTeardownAction::Destroy,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct TeardownOutcome {
    forced: bool,
    warning: Option<String>,
}

impl TeardownOutcome {
    fn normal() -> Self {
        Self {
            forced: false,
            warning: None,
        }
    }

    fn forced(warning: Option<String>) -> Self {
        Self {
            forced: true,
            warning,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum CleanupOutcome {
    Released(TeardownOutcome),
    ReleaseFailed(TeardownOutcome, String),
    TeardownFailed(String),
}

async fn teardown_then_release<T, TeardownFuture, R, ReleaseFuture>(
    teardown: T,
    release: R,
) -> CleanupOutcome
where
    T: FnOnce() -> TeardownFuture,
    TeardownFuture: Future<Output = Result<TeardownOutcome, String>>,
    R: FnOnce() -> ReleaseFuture,
    ReleaseFuture: Future<Output = Result<(), String>>,
{
    let teardown = match teardown().await {
        Ok(teardown) => teardown,
        Err(error) => return CleanupOutcome::TeardownFailed(error),
    };
    match release().await {
        Ok(()) => CleanupOutcome::Released(teardown),
        Err(error) => CleanupOutcome::ReleaseFailed(teardown, error),
    }
}

fn freeze_exit(state: &mut LifecycleState, forced: bool) {
    if state.exited_at.is_none() {
        state.exit_status = u32::from(forced);
        state.exited_at = Some(now_timestamp());
    }
}

fn terminal_wait_response(state: &LifecycleState) -> Option<api::WaitSandboxResponse> {
    matches!(
        state.phase,
        Phase::Stopped | Phase::ReleasePending | Phase::Failed | Phase::Shutdown
    )
    .then(|| api::WaitSandboxResponse {
        exit_status: state.exit_status,
        exited_at: state.exited_at.clone().into(),
        ..Default::default()
    })
}

fn hash_create_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hash_create_field(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    hash_create_part(hasher, label);
    hash_create_part(hasher, value);
}

fn create_request_fingerprint(
    request: &api::CreateSandboxRequest,
    cri_fingerprint: &str,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hash_create_part(&mut hasher, b"create-sandbox-request-v2");
    hash_create_field(&mut hasher, b"sandbox-id", request.sandbox_id.as_bytes());
    hash_create_field(&mut hasher, b"bundle-path", request.bundle_path.as_bytes());
    hash_create_field(&mut hasher, b"netns-path", request.netns_path.as_bytes());
    hash_create_field(
        &mut hasher,
        b"cri-semantic-fingerprint",
        cri_fingerprint.as_bytes(),
    );
    hash_create_part(&mut hasher, b"rootfs");
    hash_create_part(&mut hasher, &(request.rootfs.len() as u64).to_be_bytes());
    for mount in &request.rootfs {
        hash_create_part(&mut hasher, b"mount");
        hash_create_field(&mut hasher, b"type", mount.type_.as_bytes());
        hash_create_field(&mut hasher, b"source", mount.source.as_bytes());
        hash_create_field(&mut hasher, b"target", mount.target.as_bytes());
        hash_create_part(&mut hasher, b"options");
        hash_create_part(&mut hasher, &(mount.options.len() as u64).to_be_bytes());
        for option in &mount.options {
            hash_create_part(&mut hasher, b"option");
            hash_create_part(&mut hasher, option.as_bytes());
        }
    }
    hash_create_part(&mut hasher, b"annotations");
    hash_create_part(
        &mut hasher,
        &(request.annotations.len() as u64).to_be_bytes(),
    );
    let mut annotations: Vec<_> = request.annotations.iter().collect();
    annotations.sort_by(|left, right| left.0.cmp(right.0));
    for (key, value) in annotations {
        hash_create_part(&mut hasher, b"entry");
        hash_create_part(&mut hasher, key.as_bytes());
        hash_create_part(&mut hasher, value.as_bytes());
    }
    hasher.finalize().to_vec()
}

fn encode_sandbox_spec(spec: &Spec) -> Result<Any, String> {
    let value = serde_json::to_vec(spec)
        .map_err(|error| format!("serialize OCI sandbox spec failed: {error}"))?;
    Ok(Any {
        type_url: OCI_SPEC_TYPE_URL.to_string(),
        value,
        ..Default::default()
    })
}

#[async_trait]
impl Sandbox for SandboxService {
    async fn create_sandbox(
        &self,
        _ctx: &TtrpcContext,
        req: api::CreateSandboxRequest,
    ) -> TtrpcResult<api::CreateSandboxResponse> {
        let total_started = Instant::now();
        self.validate_id(&req.sandbox_id)?;
        if req.bundle_path.is_empty() || !Path::new(&req.bundle_path).is_absolute() {
            return Err(rpc_error(
                Code::INVALID_ARGUMENT,
                "bundle_path must be absolute",
            ));
        }
        let options = req.options.as_ref().ok_or_else(|| {
            rpc_error(
                Code::INVALID_ARGUMENT,
                "sandbox options must contain CRI v1 PodSandboxConfig",
            )
        })?;
        let config = runtime_resource::decode_cri_config(&options.type_url, &options.value)
            .map_err(|error| rpc_error(Code::INVALID_ARGUMENT, error))?;
        let fingerprint =
            create_request_fingerprint(&req, &runtime_resource::cri_semantic_fingerprint(&config));
        let host_lifecycle = lifecycle_from_env()
            .map_err(|error| rpc_error(Code::FAILED_PRECONDITION, error))?
            .ok_or_else(|| {
                rpc_error(
                    Code::FAILED_PRECONDITION,
                    "managed CreateSandbox has no external shim lifecycle",
                )
            })?;
        let admission = host_lifecycle
            .begin_managed_create(
                Path::new(&req.bundle_path),
                runtime_resource::cgroup_parent(&config),
                &fingerprint,
            )
            .map_err(|error| match error {
                BeginCreateError::Conflict(message) => rpc_error(Code::ALREADY_EXISTS, message),
                BeginCreateError::Invalid(message) => rpc_error(Code::FAILED_PRECONDITION, message),
            })?;
        let waiter = host_lifecycle.create_waiter_guard();

        if admission == CreateAdmission::First {
            let publisher = host_lifecycle.create_publisher_guard();
            let validate_semantics =
                || -> TtrpcResult<(Spec, Any, runtime_resource::RuntimePreparePlan)> {
                    runtime_resource::shared_pid_namespace(&config)
                        .map_err(|error| rpc_error(Code::INVALID_ARGUMENT, error))?;
                    if req.netns_path.is_empty() || !Path::new(&req.netns_path).is_absolute() {
                        return Err(rpc_error(
                            Code::INVALID_ARGUMENT,
                            "netns_path must be absolute; host-network sandboxes are not supported",
                        ));
                    }
                    host_lifecycle
                        .validate_cri_parent(runtime_resource::cgroup_parent(&config))
                        .map_err(|error| rpc_error(Code::INVALID_ARGUMENT, error))?;
                    let config_path = Path::new(&req.bundle_path).join("config.json");
                    let mut spec: Spec = if config_path.is_file() {
                        Utils::load_spec(&req.bundle_path).map_err(|error| {
                            rpc_error(
                                Code::INVALID_ARGUMENT,
                                format!("load sandbox bundle spec: {error}"),
                            )
                        })?
                    } else {
                        Spec::default()
                    };
                    runtime_resource::merge_cri_annotations(&mut spec, &config, &req.annotations)
                        .map_err(|error| rpc_error(Code::INVALID_ARGUMENT, error))?;
                    let plan = runtime_resource::runtime_prepare_plan(&config, &req.annotations)
                        .map_err(|error| rpc_error(Code::INVALID_ARGUMENT, error))?;
                    let sandbox_spec = encode_sandbox_spec(&spec)
                        .map_err(|error| rpc_error(Code::INVALID_ARGUMENT, error))?;
                    Ok((spec, sandbox_spec, plan))
                };
            let semantic = validate_semantics();
            let (spec, sandbox_spec, plan) = match semantic {
                Ok(values) => values,
                Err(error) => {
                    let (code, message) = rpc_failure_identity(&error);
                    tokio::spawn(async move {
                        publisher.failure_until_durable(&code, &message).await;
                    })
                    .await
                    .map_err(|join_error| {
                        rpc_error(
                            Code::INTERNAL,
                            format!("join rejected CreateSandbox publisher: {join_error}"),
                        )
                    })?;
                    if let Err(persist_error) = waiter.finish() {
                        return Err(rpc_error(
                            Code::INTERNAL,
                            format!("finish rejected CreateSandbox waiter: {persist_error}"),
                        ));
                    }
                    return Err(error);
                }
            };
            if let Err(error) = host_lifecycle.place_managed_server() {
                let message = format!("place CubeShim server in Host Pod cgroup: {error}");
                publisher.failure_until_durable("INTERNAL", &message).await;
                waiter.finish().map_err(|finish_error| {
                    rpc_error(
                        Code::INTERNAL,
                        format!("finish failed Host placement waiter: {finish_error}"),
                    )
                })?;
                return Err(rpc_error(Code::INTERNAL, message));
            }
            host_lifecycle
                .wait_test_failpoint("after-create-commit")
                .await;
            if let Err(error) = host_lifecycle.apply_host_resource_ceiling(plan.host_ceiling()) {
                let message = format!("apply Host Pod resource ceiling: {error}");
                publisher.failure_until_durable("INTERNAL", &message).await;
                waiter.finish().map_err(|finish_error| {
                    rpc_error(
                        Code::INTERNAL,
                        format!("finish failed Host controller waiter: {finish_error}"),
                    )
                })?;
                return Err(rpc_error(Code::INTERNAL, message));
            }

            let mut state = self.lifecycle.state.lock().await;
            match state.phase {
                Phase::Unmanaged => {
                    state.phase = Phase::Creating;
                    state.create_request = Some(fingerprint.clone());
                    state.sandbox_spec = Some(sandbox_spec);
                    tokio::spawn(self.clone().run_create(
                        spec,
                        req.netns_path,
                        config,
                        plan,
                        publisher,
                    ));
                }
                phase => {
                    let error = rpc_error(
                        Code::INTERNAL,
                        format!("first durable Create found local phase {phase:?}"),
                    );
                    drop(state);
                    let (code, message) = rpc_failure_identity(&error);
                    tokio::spawn(async move {
                        publisher.failure_until_durable(&code, &message).await;
                    })
                    .await
                    .map_err(|join_error| {
                        rpc_error(
                            Code::INTERNAL,
                            format!("join failed CreateSandbox publisher: {join_error}"),
                        )
                    })?;
                    let _ = waiter.finish();
                    return Err(error);
                }
            }
        }

        let result = match host_lifecycle
            .wait_create_result(Duration::from_secs(45))
            .await
        {
            Ok(PersistedCreateResult::Succeeded) => self
                .validate_durable_create_success(&host_lifecycle, &fingerprint)
                .await
                .map(|_| api::CreateSandboxResponse::new())
                .map_err(|error| rpc_error(Code::INTERNAL, error)),
            Ok(PersistedCreateResult::Failed { code, message }) => {
                Err(rpc_error(rpc_code_from_name(&code), message))
            }
            Err(error) => Err(rpc_error(Code::INTERNAL, error)),
        };
        if let Err(error) = waiter.finish() {
            return Err(rpc_error(
                Code::INTERNAL,
                format!("finish CreateSandbox waiter: {error}"),
            ));
        }
        crate::cube_perf!(
            "cube_perf component=shim operation=create phase=ttrpc-total sandbox_id={} ts_mono_us={} duration_us={} success={}",
            self.id,
            Utils::monotonic_time_micros(),
            total_started.elapsed().as_micros(),
            result.is_ok()
        );
        result
    }

    async fn start_sandbox(
        &self,
        _ctx: &TtrpcContext,
        req: api::StartSandboxRequest,
    ) -> TtrpcResult<api::StartSandboxResponse> {
        let total_started = Instant::now();
        self.validate_id(&req.sandbox_id)?;
        let should_start = {
            let mut state = self.lifecycle.state.lock().await;
            match state.phase {
                Phase::Created => {
                    state.phase = Phase::Starting;
                    true
                }
                Phase::Starting | Phase::Ready => false,
                phase => {
                    return Err(rpc_error(
                        Code::FAILED_PRECONDITION,
                        format!("sandbox cannot start from phase {phase:?}"),
                    ))
                }
            }
        };
        if should_start {
            tokio::spawn(self.clone().run_start());
        }
        let result = self.wait_for_start().await;
        crate::cube_perf!(
            "cube_perf component=shim operation=start phase=ttrpc-total sandbox_id={} ts_mono_us={} duration_us={} success={}",
            self.id,
            Utils::monotonic_time_micros(),
            total_started.elapsed().as_micros(),
            result.is_ok()
        );
        result
    }

    async fn platform(
        &self,
        _ctx: &TtrpcContext,
        req: api::PlatformRequest,
    ) -> TtrpcResult<api::PlatformResponse> {
        self.validate_id(&req.sandbox_id)?;
        Ok(api::PlatformResponse {
            platform: MessageField::some(Platform {
                os: "linux".to_string(),
                architecture: "amd64".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    async fn stop_sandbox(
        &self,
        _ctx: &TtrpcContext,
        req: api::StopSandboxRequest,
    ) -> TtrpcResult<api::StopSandboxResponse> {
        self.validate_id(&req.sandbox_id)?;
        let (should_stop, previous) = loop {
            let notified = self.lifecycle.changed.notified();
            let mut state = self.lifecycle.state.lock().await;
            if self.lifecycle.has_task_creates() {
                drop(state);
                notified.await;
                continue;
            }
            match state.phase {
                Phase::Creating | Phase::Starting => {
                    drop(state);
                    notified.await;
                }
                Phase::Created | Phase::Ready | Phase::Failed | Phase::ReleasePending => {
                    let previous = state.phase;
                    state.phase = Phase::Stopping;
                    break (true, previous);
                }
                Phase::Stopping => break (false, Phase::Stopping),
                Phase::Stopped | Phase::Shutdown => return Ok(api::StopSandboxResponse::new()),
                phase => {
                    return Err(rpc_error(
                        Code::FAILED_PRECONDITION,
                        format!("sandbox cannot stop from phase {phase:?}"),
                    ))
                }
            }
        };
        if should_stop {
            tokio::spawn(self.clone().run_stop(previous));
        }
        self.wait_for_stop().await?;
        Ok(api::StopSandboxResponse::new())
    }

    async fn wait_sandbox(
        &self,
        _ctx: &TtrpcContext,
        req: api::WaitSandboxRequest,
    ) -> TtrpcResult<api::WaitSandboxResponse> {
        self.validate_id(&req.sandbox_id)?;
        loop {
            let notified = self.lifecycle.changed.notified();
            let state = self.lifecycle.state.lock().await;
            if let Some(response) = terminal_wait_response(&state) {
                return Ok(response);
            }
            drop(state);
            notified.await;
        }
    }

    async fn sandbox_status(
        &self,
        _ctx: &TtrpcContext,
        req: api::SandboxStatusRequest,
    ) -> TtrpcResult<api::SandboxStatusResponse> {
        self.validate_id(&req.sandbox_id)?;
        let state = self.lifecycle.state.lock().await;
        let mut info = std::collections::HashMap::new();
        if req.verbose {
            info.insert("phase".to_string(), format!("{:?}", state.phase));
            if let Some(error) = state.last_error.as_ref() {
                info.insert("last_error".to_string(), error.clone());
            }
            if let Some(runtime) = state.runtime.as_ref() {
                info.insert(
                    "runtime_lease".to_string(),
                    runtime.sandbox.lease_id.clone(),
                );
                info.insert(
                    "runtime_generation".to_string(),
                    runtime.sandbox.generation.to_string(),
                );
            }
        }
        Ok(api::SandboxStatusResponse {
            sandbox_id: self.id.clone(),
            pid: std::process::id(),
            state: if state.phase == Phase::Ready {
                READY.to_string()
            } else {
                NOT_READY.to_string()
            },
            info,
            created_at: state.created_at.clone().into(),
            exited_at: state.exited_at.clone().into(),
            ..Default::default()
        })
    }

    async fn ping_sandbox(
        &self,
        _ctx: &TtrpcContext,
        req: api::PingRequest,
    ) -> TtrpcResult<api::PingResponse> {
        self.validate_id(&req.sandbox_id)?;
        if self.lifecycle.state.lock().await.phase == Phase::Shutdown {
            return Err(rpc_error(Code::UNAVAILABLE, "sandbox shim is shut down"));
        }
        Ok(api::PingResponse::new())
    }

    async fn shutdown_sandbox(
        &self,
        _ctx: &TtrpcContext,
        req: api::ShutdownSandboxRequest,
    ) -> TtrpcResult<api::ShutdownSandboxResponse> {
        self.validate_id(&req.sandbox_id)?;
        let force_abort = match self.lifecycle.begin_shutdown().await {
            ShutdownAction::AlreadyComplete => return Ok(api::ShutdownSandboxResponse::new()),
            ShutdownAction::WaitForExisting => None,
            ShutdownAction::Run { force_abort } => Some(force_abort),
        };
        if let Some(force_abort) = force_abort {
            tokio::spawn(self.clone().run_shutdown(force_abort));
        }
        self.wait_for_shutdown().await
    }

    async fn sandbox_metrics(
        &self,
        _ctx: &TtrpcContext,
        req: api::SandboxMetricsRequest,
    ) -> TtrpcResult<api::SandboxMetricsResponse> {
        self.validate_id(&req.sandbox_id)?;
        Ok(api::SandboxMetricsResponse::new())
    }
}

fn append_error(base: String, operation: &str, error: Option<String>) -> String {
    match error {
        Some(error) => format!("{base}; {operation}: {error}"),
        None => base,
    }
}

fn rpc_error(code: Code, message: impl Into<String>) -> TtrpcError {
    TtrpcError::RpcStatus(containerd_shim::protos::ttrpc::get_status(
        code,
        message.into(),
    ))
}

fn rpc_failure_identity(error: &TtrpcError) -> (String, String) {
    match error {
        TtrpcError::RpcStatus(status) => {
            (format!("{:?}", status.code()), status.message().to_string())
        }
        error => ("UNKNOWN".to_string(), error.to_string()),
    }
}

fn rpc_code_from_name(name: &str) -> Code {
    match name {
        "CANCELLED" => Code::CANCELLED,
        "INVALID_ARGUMENT" => Code::INVALID_ARGUMENT,
        "NOT_FOUND" => Code::NOT_FOUND,
        "ALREADY_EXISTS" => Code::ALREADY_EXISTS,
        "FAILED_PRECONDITION" => Code::FAILED_PRECONDITION,
        "UNAVAILABLE" => Code::UNAVAILABLE,
        "INTERNAL" => Code::INTERNAL,
        _ => Code::UNKNOWN,
    }
}

async fn request_external_cleanup_durable(reason: &str) {
    loop {
        match lifecycle_from_env() {
            Ok(Some(lifecycle)) => match lifecycle.request_cleanup(reason) {
                Ok(()) => return,
                Err(error) => {
                    eprintln!("request external CubeShim cleanup after {reason}: {error}")
                }
            },
            Ok(None) => return,
            Err(error) => eprintln!("load external CubeShim lifecycle after {reason}: {error}"),
        }
        // Terminal RPC completion is intentionally held until cleanup intent
        // is durable. If this process dies meanwhile, the independent
        // watchdog observes the server death and performs the same handoff.
        sleep(Duration::from_millis(100)).await;
    }
}

fn now_timestamp() -> Timestamp {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos() as i32,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unmanaged_task_mode_preserves_legacy_runtime() {
        let lifecycle = Arc::new(SandboxLifecycle::default());
        let reservation = lifecycle.reserve_task_create("legacy-task").await.unwrap();
        assert_eq!(reservation.mode(), &TaskMode::Legacy);
        assert!(!lifecycle.is_managed().await);
    }

    #[tokio::test]
    async fn managed_task_is_rejected_until_ready() {
        let lifecycle = Arc::new(SandboxLifecycle::default());
        lifecycle.state.lock().await.phase = Phase::Created;
        assert!(lifecycle
            .reserve_task_create("task-before-ready")
            .await
            .err()
            .unwrap()
            .contains("not ready"));
        let shared_root = PathBuf::from(format!(
            "/data/cubelet/s11/shared/sb-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&shared_root).unwrap();
        {
            let mut state = lifecycle.state.lock().await;
            state.phase = Phase::Ready;
            state.runtime = Some(RuntimeLease::test_with_shared_root(
                shared_root.to_str().unwrap(),
            ));
        }
        let reservation = lifecycle.reserve_task_create("task-ready").await.unwrap();
        assert_eq!(
            reservation.mode(),
            &TaskMode::ManagedReady {
                shared_root: shared_root.clone()
            }
        );
        drop(reservation);
        std::fs::remove_dir_all(&shared_root).unwrap();
    }

    #[tokio::test]
    async fn task_create_reservation_rejects_duplicate_and_blocks_shutdown() {
        let lifecycle = Arc::new(SandboxLifecycle::default());
        let shared_root = PathBuf::from(format!(
            "/data/cubelet/s11/shared/sb-reservation-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&shared_root).unwrap();
        {
            let mut state = lifecycle.state.lock().await;
            state.phase = Phase::Ready;
            state.runtime = Some(RuntimeLease::test_with_shared_root(
                shared_root.to_str().unwrap(),
            ));
        }

        let reservation = lifecycle.reserve_task_create("same-task").await.unwrap();
        assert!(lifecycle
            .reserve_task_create("same-task")
            .await
            .err()
            .unwrap()
            .contains("already in progress"));
        let shutdown = {
            let lifecycle = lifecycle.clone();
            tokio::spawn(async move { lifecycle.begin_shutdown().await })
        };
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());

        drop(reservation);
        assert_eq!(
            shutdown.await.unwrap(),
            ShutdownAction::Run { force_abort: true }
        );
        std::fs::remove_dir_all(&shared_root).unwrap();
    }

    #[tokio::test]
    async fn managed_sandbox_allows_distinct_task_creates_and_waits_for_all() {
        let lifecycle = Arc::new(SandboxLifecycle::default());
        let shared_root = PathBuf::from(format!(
            "/data/cubelet/s11/shared/sb-multitask-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&shared_root).unwrap();
        {
            let mut state = lifecycle.state.lock().await;
            state.phase = Phase::Ready;
            state.runtime = Some(RuntimeLease::test_with_shared_root(
                shared_root.to_str().unwrap(),
            ));
        }

        let alpha = lifecycle.reserve_task_create("alpha").await.unwrap();
        let beta = lifecycle.reserve_task_create("beta").await.unwrap();
        assert_eq!(
            alpha.mode(),
            &TaskMode::ManagedReady {
                shared_root: shared_root.clone()
            }
        );
        assert_eq!(alpha.mode(), beta.mode());

        let shutdown = {
            let lifecycle = lifecycle.clone();
            tokio::spawn(async move { lifecycle.begin_shutdown().await })
        };
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());
        drop(alpha);
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());
        drop(beta);
        assert_eq!(
            shutdown.await.unwrap(),
            ShutdownAction::Run { force_abort: true }
        );

        std::fs::remove_dir_all(&shared_root).unwrap();
    }

    #[tokio::test]
    async fn shutdown_waits_for_detached_operation_before_transitioning() {
        let lifecycle = Arc::new(SandboxLifecycle::default());
        lifecycle.state.lock().await.phase = Phase::Creating;
        let waiter = {
            let lifecycle = lifecycle.clone();
            tokio::spawn(async move { lifecycle.begin_shutdown().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        lifecycle.state.lock().await.phase = Phase::Created;
        lifecycle.changed.notify_waiters();
        assert_eq!(
            waiter.await.unwrap(),
            ShutdownAction::Run { force_abort: true }
        );
        assert_eq!(lifecycle.state.lock().await.phase, Phase::ShuttingDown);
        assert_eq!(
            lifecycle.begin_shutdown().await,
            ShutdownAction::WaitForExisting
        );
    }

    #[tokio::test]
    async fn shutdown_after_stop_skips_redundant_force_abort() {
        let lifecycle = SandboxLifecycle::default();
        lifecycle.state.lock().await.phase = Phase::Stopped;
        assert_eq!(
            lifecycle.begin_shutdown().await,
            ShutdownAction::Run { force_abort: false }
        );
        assert_eq!(lifecycle.state.lock().await.phase, Phase::ShuttingDown);
    }

    #[tokio::test]
    async fn shutdown_with_pending_release_retries_only_release() {
        let lifecycle = SandboxLifecycle::default();
        lifecycle.state.lock().await.phase = Phase::ReleasePending;
        assert_eq!(
            lifecycle.begin_shutdown().await,
            ShutdownAction::Run { force_abort: false }
        );
        assert_eq!(lifecycle.state.lock().await.phase, Phase::ShuttingDown);
    }

    #[test]
    fn start_rollback_release_failure_enters_retry_only_phase() {
        let mut state = LifecycleState {
            phase: Phase::Starting,
            runtime: Some(RuntimeLease::test_with_shared_root(
                "/data/cubelet/start-release-pending-test",
            )),
            ..Default::default()
        };
        apply_start_result(
            &mut state,
            Err(StartFailure {
                error: "start failed; release RuntimeResource: unavailable".to_string(),
                cleanup: StartCleanup::ReleasePending,
            }),
        );

        assert_eq!(state.phase, Phase::ReleasePending);
        assert!(state.runtime.is_some());
        assert_eq!(state.exit_status, 1);
        assert!(state.exited_at.is_some());
        assert_eq!(
            stop_teardown_action(state.phase),
            StopTeardownAction::ReleaseOnly
        );
    }

    #[test]
    fn start_rollback_failure_retains_lease_and_requires_abort() {
        let mut state = LifecycleState {
            phase: Phase::Starting,
            runtime: Some(RuntimeLease::test_with_shared_root(
                "/data/cubelet/start-teardown-failed-test",
            )),
            ..Default::default()
        };
        apply_start_result(
            &mut state,
            Err(StartFailure {
                error: "start failed; rollback VM failed".to_string(),
                cleanup: StartCleanup::TeardownUnconfirmed,
            }),
        );

        assert_eq!(state.phase, Phase::Failed);
        assert!(state.runtime.is_some());
        assert_eq!(stop_teardown_action(state.phase), StopTeardownAction::Abort);
    }

    #[tokio::test]
    async fn teardown_is_confirmed_before_release_and_failure_retains_lease() {
        let events = Arc::new(StdMutex::new(Vec::new()));
        let teardown_events = events.clone();
        let release_events = events.clone();
        let result = teardown_then_release(
            move || async move {
                teardown_events.lock().unwrap().push("teardown");
                Ok(TeardownOutcome::normal())
            },
            move || async move {
                release_events.lock().unwrap().push("release");
                Ok(())
            },
        )
        .await;
        assert_eq!(result, CleanupOutcome::Released(TeardownOutcome::normal()));
        assert_eq!(*events.lock().unwrap(), vec!["teardown", "release"]);

        events.lock().unwrap().clear();
        let teardown_events = events.clone();
        let release_events = events.clone();
        let result = teardown_then_release(
            move || async move {
                teardown_events.lock().unwrap().push("teardown");
                Err("VM still active".to_string())
            },
            move || async move {
                release_events.lock().unwrap().push("release");
                Ok(())
            },
        )
        .await;
        assert_eq!(
            result,
            CleanupOutcome::TeardownFailed("VM still active".to_string())
        );
        assert_eq!(*events.lock().unwrap(), vec!["teardown"]);
    }

    #[test]
    fn pending_release_is_terminal_and_retry_does_not_change_wait_result() {
        let exited_at = Timestamp {
            seconds: 1_725_000_000,
            nanos: 123_456_789,
            ..Default::default()
        };
        let mut state = LifecycleState {
            phase: Phase::ReleasePending,
            exited_at: Some(exited_at.clone()),
            exit_status: 0,
            last_error: Some("release RuntimeResource: unavailable".to_string()),
            ..Default::default()
        };
        let before = terminal_wait_response(&state).unwrap();

        freeze_exit(&mut state, true);
        state.phase = Phase::Stopped;
        state.last_error = None;
        let after = terminal_wait_response(&state).unwrap();

        assert_eq!(before.exit_status, after.exit_status);
        assert_eq!(before.exited_at, after.exited_at);
        assert_eq!(after.exit_status, 0);
        assert_eq!(after.exited_at.as_ref(), Some(&exited_at));
    }

    #[test]
    fn create_retry_fingerprint_ignores_annotation_map_iteration_order() {
        let mut first = api::CreateSandboxRequest {
            sandbox_id: "sandbox-a".to_string(),
            bundle_path: "/run/containerd/bundle".to_string(),
            netns_path: "/run/netns/pod-a".to_string(),
            ..Default::default()
        };
        first
            .annotations
            .insert("z.example/key".to_string(), "z".to_string());
        first
            .annotations
            .insert("a.example/key".to_string(), "a".to_string());
        let mut second = api::CreateSandboxRequest {
            sandbox_id: first.sandbox_id.clone(),
            bundle_path: first.bundle_path.clone(),
            netns_path: first.netns_path.clone(),
            ..Default::default()
        };
        second
            .annotations
            .insert("a.example/key".to_string(), "a".to_string());
        second
            .annotations
            .insert("z.example/key".to_string(), "z".to_string());
        assert_eq!(
            create_request_fingerprint(&first, "cri-fingerprint"),
            create_request_fingerprint(&second, "cri-fingerprint")
        );
        second
            .annotations
            .insert("z.example/key".to_string(), "changed".to_string());
        assert_ne!(
            create_request_fingerprint(&first, "cri-fingerprint"),
            create_request_fingerprint(&second, "cri-fingerprint")
        );
    }

    #[test]
    fn sandbox_spec_uses_containerd_oci_type_url_and_json_encoding() {
        let mut spec = Spec::default();
        spec.set_hostname(Some("cube-sandbox".to_string()));

        let encoded = encode_sandbox_spec(&spec).unwrap();

        assert_eq!(encoded.type_url, OCI_SPEC_TYPE_URL);
        let decoded: serde_json::Value = serde_json::from_slice(&encoded.value).unwrap();
        assert_eq!(decoded["hostname"], "cube-sandbox");
        assert!(decoded.get("ociVersion").is_some());
    }

    #[test]
    fn timestamps_include_nanoseconds() {
        let timestamp = now_timestamp();
        assert!(timestamp.seconds > 0);
        assert!((0..1_000_000_000).contains(&timestamp.nanos));
    }
}
