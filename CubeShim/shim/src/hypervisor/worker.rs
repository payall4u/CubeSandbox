// Copyright (c) 2024 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::common::utils::Utils;
use crate::common::CResult;
use cube_hypervisor::config::RestoreConfig;
use cube_hypervisor::vm_config::{DeviceConfig, FsConfig, VmConfig};
use cube_hypervisor::{
    ApiRequest, ApiResponsePayload, NotifyEvent, SnapshotConfig, SnapshotType, VmRemoveDeviceData,
};
use nix::sys::socket::{
    getsockopt, sendmsg, socketpair, sockopt, AddressFamily, ControlMessage, MsgFlags, SockFlag,
    SockType,
};
use serde::{Deserialize, Serialize};
use std::env;
use std::io::IoSlice;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

const PROTOCOL_MAGIC: &str = "cube-vmm-worker";
pub(crate) const PROTOCOL_VERSION: u16 = 1;
const MAX_PACKET_SIZE: usize = 2 * 1024 * 1024;
const MAX_HANDOFF_FDS: usize = 64;
const CONTROL_FD_ENV: &str = "CUBE_VMM_WORKER_CONTROL_FD";
const EVENT_FD_ENV: &str = "CUBE_VMM_WORKER_EVENT_FD";
const WORKER_PATH_ENV: &str = "CUBE_VMM_WORKER_PATH";
const BACKEND_ENV: &str = "CUBE_VMM_BACKEND";
const NONCE_ENV: &str = "CUBE_VMM_WORKER_NONCE";
const PARENT_PID_ENV: &str = "CUBE_VMM_WORKER_PARENT_PID";
const HELLO_TIMEOUT_SECS: i64 = 2;
const COMMAND_TIMEOUT_SECS: i64 = 10;
const PLACEMENT_DEADLINE: Duration = Duration::from_secs(2);

pub trait WorkerPlacement: Sync {
    fn prepare_vmm_worker_spawn(
        &self,
        executable: &Path,
        nonce: &str,
        protocol_version: u16,
    ) -> CResult<()>;

    fn place_vmm_worker(&self, pid: u32) -> CResult<()>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct HelloConfig {
    nonce: String,
    parent_pid: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct LaunchConfig {
    sandbox_id: String,
    log_level: u8,
    http_path: Option<String>,
}

impl LaunchConfig {
    pub(crate) fn new(
        sandbox_id: String,
        log_level: log::LevelFilter,
        http_path: Option<String>,
    ) -> Self {
        Self {
            sandbox_id,
            log_level: level_to_wire(log_level),
            http_path,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", content = "payload")]
pub(crate) enum WorkerCommand {
    Hello(HelloConfig),
    Launch(LaunchConfig),
    Ping,
    CreateVm(VmConfig),
    BootVm,
    JoinVmm,
    SnapshotVm {
        path: String,
        snapshot_type: SnapshotType,
    },
    PauseVm,
    ResumeVm,
    RestoreVm(RestoreConfig),
    SetFs(FsConfig),
    AddDevice(DeviceConfig),
    RemoveDevice(VmRemoveDeviceData),
    DeleteVm,
    PauseToSnapshot(SnapshotConfig),
    ResumeFromSnapshot(RestoreConfig),
    ShutdownWorker,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) enum WorkerReply {
    Empty,
    ActionPayload(Option<Vec<u8>>),
}

#[derive(Debug, Deserialize, Serialize)]
struct WorkerRequest {
    magic: String,
    version: u16,
    request_id: u64,
    command: WorkerCommand,
}

#[derive(Debug, Deserialize, Serialize)]
struct WorkerResponse {
    magic: String,
    version: u16,
    request_id: u64,
    result: Result<WorkerReply, String>,
}

struct RequestFailure {
    message: String,
    channel_failed: bool,
}

impl RequestFailure {
    fn local(message: String) -> Self {
        Self {
            message,
            channel_failed: false,
        }
    }

    fn channel(message: String) -> Self {
        Self {
            message,
            channel_failed: true,
        }
    }

    fn application(message: String) -> Self {
        Self::local(message)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum WorkerEvent {
    VmShutdown,
    VsockServerReady,
    RestoreReady,
    SysStart,
    MigrationComplete,
    MigrationFail,
    ProtocolError(String),
}

struct WorkerClientInner {
    control: Mutex<OwnedFd>,
    child: Mutex<Child>,
    next_request_id: AtomicU64,
    poisoned: AtomicBool,
    reaped: AtomicBool,
}

impl Drop for WorkerClientInner {
    fn drop(&mut self) {
        if let Ok(child) = self.child.get_mut() {
            let _ = terminate_child(child);
        }
    }
}

#[derive(Clone)]
pub(crate) struct WorkerClient {
    inner: Arc<WorkerClientInner>,
}

impl WorkerClient {
    pub(crate) fn spawn(
        config: LaunchConfig,
        placement: Option<&dyn WorkerPlacement>,
    ) -> CResult<(Self, Receiver<NotifyEvent>)> {
        Self::spawn_inner(config, placement, true)
    }

    #[doc(hidden)]
    fn spawn_gated_for_process_test(sandbox_id: String) -> CResult<(Self, Receiver<NotifyEvent>)> {
        Self::spawn_inner(
            LaunchConfig::new(sandbox_id, log::LevelFilter::Off, None),
            None,
            false,
        )
    }

    fn spawn_inner(
        config: LaunchConfig,
        placement: Option<&dyn WorkerPlacement>,
        launch_vmm: bool,
    ) -> CResult<(Self, Receiver<NotifyEvent>)> {
        let lifecycle_started = Instant::now();
        let sandbox_id = config.sandbox_id.clone();
        let (control_parent, control_child) = seqpacket_pair()?;
        let (event_parent, event_child) = seqpacket_pair()?;

        let worker_path = worker_path()?;
        let nonce = uuid::Uuid::new_v4().to_string();
        let parent_pid = std::process::id();
        if let Some(placement) = placement {
            let phase_started = Instant::now();
            placement.prepare_vmm_worker_spawn(&worker_path, &nonce, PROTOCOL_VERSION)?;
            crate::cube_perf!(
                "cube_perf component=vmm-worker operation=start phase=prepare-intent sandbox_id={} ts_mono_us={} duration_us={}",
                sandbox_id,
                Utils::monotonic_time_micros(),
                phase_started.elapsed().as_micros()
            );
        }
        let mut command = Command::new(&worker_path);
        let control_child_fd = control_child.as_raw_fd();
        let event_child_fd = event_child.as_raw_fd();
        command
            .arg("--vmm-worker")
            .env(CONTROL_FD_ENV, control_child_fd.to_string())
            .env(EVENT_FD_ENV, event_child_fd.to_string())
            .env(NONCE_ENV, &nonce)
            .env(PARENT_PID_ENV, parent_pid.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        unsafe {
            command.pre_exec(move || {
                configure_worker_child_before_exec(control_child_fd, event_child_fd, parent_pid)
            });
        }
        let phase_started = Instant::now();
        let child = command
            .spawn()
            .map_err(|error| format!("spawn cube-vmm-worker {}: {error}", worker_path.display()))?;
        drop(control_child);
        drop(event_child);

        let pid = child.id();
        crate::cube_perf!(
            "cube_perf component=vmm-worker operation=start phase=fork-exec sandbox_id={} operation_id={} worker_pid={} ts_mono_us={} duration_us={}",
            sandbox_id,
            sandbox_id,
            pid,
            Utils::monotonic_time_micros(),
            phase_started.elapsed().as_micros()
        );
        let client = Self {
            inner: Arc::new(WorkerClientInner {
                control: Mutex::new(control_parent),
                child: Mutex::new(child),
                next_request_id: AtomicU64::new(1),
                poisoned: AtomicBool::new(false),
                reaped: AtomicBool::new(false),
            }),
        };
        let (event_sender, event_receiver) = channel();
        let event_sandbox_id = sandbox_id.clone();
        let event_client = Arc::downgrade(&client.inner);
        if let Err(error) = std::thread::Builder::new()
            .name(format!("cube-vmm-events-{pid}"))
            .spawn(move || {
                loop {
                    let packet = match recv_packet(event_parent.as_raw_fd()) {
                        Ok(Some((packet, descriptors))) => {
                            if !descriptors.is_empty() {
                                log::error!(
                                    "cube-vmm-worker event carried descriptors sandbox={} pid={}",
                                    event_sandbox_id,
                                    pid
                                );
                                break;
                            }
                            packet
                        }
                        Ok(None) => break,
                        Err(error) => {
                            log::error!(
                                "cube-vmm-worker event receive failed sandbox={} pid={}: {}",
                                event_sandbox_id,
                                pid,
                                error
                            );
                            break;
                        }
                    };
                    let event: WorkerEvent = match serde_json::from_slice(&packet) {
                        Ok(event) => event,
                        Err(error) => {
                            log::error!(
                                "cube-vmm-worker event decode failed sandbox={} pid={}: {}",
                                event_sandbox_id,
                                pid,
                                error
                            );
                            break;
                        }
                    };
                    if let WorkerEvent::ProtocolError(message) = &event {
                        log::error!(
                            "cube-vmm-worker protocol failure sandbox={} pid={}: {}",
                            event_sandbox_id,
                            pid,
                            message
                        );
                        break;
                    }
                    if event_sender.send(event.into()).is_err() {
                        break;
                    }
                }
                poison_worker(&event_client);
                // A dead worker is equivalent to a dead VM from the sandbox's
                // point of view. Wake the existing monitor immediately instead
                // of waiting for the next guest-agent health probe.
                let _ = event_sender.send(NotifyEvent::VmShutdown);
            })
        {
            let _ = client.terminate();
            return Err(format!("spawn cube-vmm-worker event reader: {error}"));
        }
        if let Err(error) = set_socket_timeout(
            client.inner.control.lock().unwrap().as_raw_fd(),
            HELLO_TIMEOUT_SECS,
        ) {
            return Err(client.terminate_after_error(error));
        }
        let phase_started = Instant::now();
        if let Err(error) =
            client.request(WorkerCommand::Hello(HelloConfig { nonce, parent_pid }), &[])
        {
            return Err(client.terminate_after_error(error));
        }
        crate::cube_perf!(
            "cube_perf component=vmm-worker operation=start phase=hello sandbox_id={} operation_id={} worker_pid={} ts_mono_us={} duration_us={}",
            sandbox_id,
            sandbox_id,
            pid,
            Utils::monotonic_time_micros(),
            phase_started.elapsed().as_micros()
        );
        if let Err(error) = set_socket_timeout(
            client.inner.control.lock().unwrap().as_raw_fd(),
            COMMAND_TIMEOUT_SECS,
        ) {
            return Err(client.terminate_after_error(error));
        }
        let phase_started = Instant::now();
        if let Err(error) = verify_worker_fd_allowlist(pid, control_child_fd, event_child_fd) {
            return Err(client.terminate_after_error(error));
        }
        crate::cube_perf!(
            "cube_perf component=vmm-worker operation=start phase=fd-gate sandbox_id={} operation_id={} worker_pid={} ts_mono_us={} duration_us={}",
            sandbox_id,
            sandbox_id,
            pid,
            Utils::monotonic_time_micros(),
            phase_started.elapsed().as_micros()
        );
        if let Some(placement) = placement {
            let phase_started = Instant::now();
            if let Err(error) = placement.place_vmm_worker(pid) {
                return Err(
                    client.terminate_after_error(format!("place cube-vmm-worker {pid}: {error}"))
                );
            }
            let placement_elapsed = phase_started.elapsed();
            if placement_elapsed > PLACEMENT_DEADLINE {
                return Err(client.terminate_after_error(format!(
                    "place cube-vmm-worker {pid} exceeded {:?}: {:?}",
                    PLACEMENT_DEADLINE, placement_elapsed
                )));
            }
            crate::cube_perf!(
                "cube_perf component=vmm-worker operation=start phase=placement sandbox_id={} operation_id={} worker_pid={} ts_mono_us={} duration_us={}",
                sandbox_id,
                sandbox_id,
                pid,
                Utils::monotonic_time_micros(),
                placement_elapsed.as_micros()
            );
        }
        if launch_vmm {
            let phase_started = Instant::now();
            if let Err(error) = client.request(WorkerCommand::Launch(config), &[]) {
                return Err(client.terminate_after_error(error));
            }
            crate::cube_perf!(
                "cube_perf component=vmm-worker operation=start phase=launch sandbox_id={} operation_id={} worker_pid={} ts_mono_us={} duration_us={} total_us={}",
                sandbox_id,
                sandbox_id,
                pid,
                Utils::monotonic_time_micros(),
                phase_started.elapsed().as_micros(),
                lifecycle_started.elapsed().as_micros()
            );
        }
        Ok((client, event_receiver))
    }

    pub(crate) fn request(&self, command: WorkerCommand, fds: &[RawFd]) -> CResult<WorkerReply> {
        let poison_on_error = !matches!(&command, WorkerCommand::Hello(_) | WorkerCommand::Ping);
        let control = match self.inner.control.lock() {
            Ok(control) => control,
            Err(_) => {
                self.inner.poisoned.store(true, Ordering::Release);
                return Err(
                    self.terminate_after_error("cube-vmm-worker control lock poisoned".to_string())
                );
            }
        };
        if self.inner.poisoned.load(Ordering::Acquire) {
            return Err("cube-vmm-worker is poisoned".to_string());
        }
        let result = self.request_once(&control, command, fds);
        let terminate = result
            .as_ref()
            .err()
            .is_some_and(|error| error.channel_failed || poison_on_error);
        let terminate_error = if terminate {
            self.inner.poisoned.store(true, Ordering::Release);
            drop(control);
            self.terminate().err()
        } else {
            None
        };
        result.map_err(|error| match terminate_error {
            Some(terminate_error) => format!(
                "{}; exact worker termination failed: {terminate_error}",
                error.message
            ),
            None => error.message,
        })
    }

    fn request_once(
        &self,
        control: &OwnedFd,
        command: WorkerCommand,
        fds: &[RawFd],
    ) -> Result<WorkerReply, RequestFailure> {
        if fds.len() > MAX_HANDOFF_FDS {
            return Err(RequestFailure::local(format!(
                "cube-vmm-worker FD handoff has {} descriptors, maximum is {MAX_HANDOFF_FDS}",
                fds.len()
            )));
        }
        let expects_action_payload = matches!(&command, WorkerCommand::AddDevice(_));
        let request_id = self.inner.next_request_id.fetch_add(1, Ordering::Relaxed);
        let request = WorkerRequest {
            magic: PROTOCOL_MAGIC.to_string(),
            version: PROTOCOL_VERSION,
            request_id,
            command,
        };
        let payload = serde_json::to_vec(&request).map_err(|error| {
            RequestFailure::local(format!("encode cube-vmm-worker request: {error}"))
        })?;
        send_packet(control.as_raw_fd(), &payload, fds).map_err(RequestFailure::channel)?;
        let (payload, descriptors) = recv_packet(control.as_raw_fd())
            .map_err(RequestFailure::channel)?
            .ok_or_else(|| {
                RequestFailure::channel("cube-vmm-worker closed the control channel".to_string())
            })?;
        if !descriptors.is_empty() {
            return Err(RequestFailure::channel(
                "cube-vmm-worker response unexpectedly carried descriptors".to_string(),
            ));
        }
        let response: WorkerResponse = serde_json::from_slice(&payload).map_err(|error| {
            RequestFailure::channel(format!("decode cube-vmm-worker response: {error}"))
        })?;
        if response.magic != PROTOCOL_MAGIC
            || response.version != PROTOCOL_VERSION
            || response.request_id != request_id
        {
            return Err(RequestFailure::channel(format!(
                "cube-vmm-worker response identity mismatch: magic={:?} version={} request_id={} expected={request_id}",
                response.magic, response.version, response.request_id
            )));
        }
        let reply = response.result.map_err(RequestFailure::application)?;
        if (expects_action_payload && !matches!(reply, WorkerReply::ActionPayload(_)))
            || (!expects_action_payload && !matches!(reply, WorkerReply::Empty))
        {
            return Err(RequestFailure::channel(
                "cube-vmm-worker response payload does not match request opcode".to_string(),
            ));
        }
        Ok(reply)
    }

    pub(crate) fn shutdown(&self) -> CResult<()> {
        if self.inner.reaped.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Err(error) = self.request(WorkerCommand::ShutdownWorker, &[]) {
            return self.terminate().map_err(|terminate_error| {
                format!(
                    "shutdown cube-vmm-worker failed: {error}; exact termination failed: {terminate_error}"
                )
            });
        }
        let status = self.reap()?;
        if !status.success() {
            log::warn!("cube-vmm-worker exited after shutdown with {status}");
        }
        Ok(())
    }

    fn process_id(&self) -> u32 {
        self.inner.child.lock().unwrap().id()
    }

    fn is_poisoned(&self) -> bool {
        self.inner.poisoned.load(Ordering::Acquire)
    }

    fn is_reaped(&self) -> bool {
        self.inner.reaped.load(Ordering::Acquire)
    }

    pub(crate) fn join(&self) -> CResult<()> {
        if self.inner.reaped.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Err(error) = self.request(WorkerCommand::JoinVmm, &[]) {
            return self.terminate().map_err(|terminate_error| {
                format!(
                    "join cube-vmm-worker failed: {error}; exact termination failed: {terminate_error}"
                )
            });
        }
        let status = self.reap()?;
        if !status.success() {
            log::warn!("cube-vmm-worker exited after join with {status}");
        }
        Ok(())
    }

    fn reap(&self) -> CResult<ExitStatus> {
        let mut child = self
            .inner
            .child
            .lock()
            .map_err(|_| "cube-vmm-worker child lock poisoned".to_string())?;
        let status = wait_child(&mut child, Duration::from_secs(2))?;
        self.inner.reaped.store(true, Ordering::Release);
        Ok(status)
    }

    fn terminate(&self) -> CResult<()> {
        if self.inner.reaped.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut child = self
            .inner
            .child
            .lock()
            .map_err(|_| "cube-vmm-worker child lock poisoned".to_string())?;
        terminate_child(&mut child)?;
        self.inner.reaped.store(true, Ordering::Release);
        Ok(())
    }

    fn terminate_after_error(&self, error: String) -> String {
        match self.terminate() {
            Ok(()) => error,
            Err(terminate_error) => {
                format!("{error}; exact worker termination failed: {terminate_error}")
            }
        }
    }
}

/// Narrow subprocess adapter used by the external worker contract test.
#[doc(hidden)]
pub struct WorkerProcessProbe {
    client: WorkerClient,
    events: Receiver<NotifyEvent>,
}

#[doc(hidden)]
impl WorkerProcessProbe {
    pub fn spawn(sandbox_id: String) -> CResult<Self> {
        let (client, events) = WorkerClient::spawn_gated_for_process_test(sandbox_id)?;
        Ok(Self { client, events })
    }

    pub fn process_id(&self) -> u32 {
        self.client.process_id()
    }

    pub fn recv_event_timeout(&self, timeout: Duration) -> CResult<NotifyEvent> {
        self.events
            .recv_timeout(timeout)
            .map_err(|error| format!("receive worker probe event: {error}"))
    }

    pub fn is_poisoned_and_reaped(&self) -> bool {
        self.client.is_poisoned() && self.client.is_reaped()
    }

    pub fn shutdown(&self) -> CResult<()> {
        self.client.shutdown()
    }
}

fn poison_worker(inner: &Weak<WorkerClientInner>) {
    let Some(inner) = inner.upgrade() else {
        return;
    };
    inner.poisoned.store(true, Ordering::Release);
    if let Ok(mut child) = inner.child.lock() {
        match terminate_child(&mut child) {
            Ok(()) => inner.reaped.store(true, Ordering::Release),
            Err(error) => log::error!("terminate failed cube-vmm-worker: {error}"),
        }
    };
}

pub(crate) fn worker_backend_enabled() -> CResult<bool> {
    match env::var(BACKEND_ENV).as_deref() {
        Ok("embedded") => Ok(false),
        Ok("worker") | Err(env::VarError::NotPresent) => Ok(true),
        Ok(value) => Err(format!(
            "unsupported {BACKEND_ENV}={value:?}; expected worker or embedded"
        )),
        Err(error) => Err(format!("read {BACKEND_ENV}: {error}")),
    }
}

pub fn run_from_env() -> CResult<()> {
    let (control, event) = inherited_fds()?;
    set_cloexec(control.as_raw_fd())?;
    set_cloexec(event.as_raw_fd())?;
    set_socket_timeout(control.as_raw_fd(), HELLO_TIMEOUT_SECS)?;
    let expected_nonce =
        env::var(NONCE_ENV).map_err(|error| format!("read {NONCE_ENV}: {error}"))?;
    let expected_parent_pid = env::var(PARENT_PID_ENV)
        .map_err(|error| format!("read {PARENT_PID_ENV}: {error}"))?
        .parse::<u32>()
        .map_err(|error| format!("parse {PARENT_PID_ENV}: {error}"))?;
    if unsafe { libc::getppid() } != expected_parent_pid as libc::pid_t {
        return Err("CubeShim parent identity changed before worker gate".to_string());
    }
    let peer = getsockopt(&control, sockopt::PeerCredentials)
        .map_err(|error| format!("read cube-vmm-worker peer credentials: {error}"))?;
    if peer.pid() != expected_parent_pid as libc::pid_t {
        return Err(format!(
            "cube-vmm-worker control peer pid {} does not match CubeShim {expected_parent_pid}",
            peer.pid()
        ));
    }
    run_worker(control, event, expected_nonce, expected_parent_pid)
}

fn run_worker(
    control: OwnedFd,
    event: OwnedFd,
    expected_nonce: String,
    expected_parent_pid: u32,
) -> CResult<()> {
    let mut vmm: Option<cube_hypervisor::VmmInstance> = None;
    let mut pending_vm_fds = PendingVmFds::default();
    let mut hello_complete = false;
    let mut next_request_id = 1_u64;

    loop {
        let packet = match recv_packet(control.as_raw_fd()) {
            Ok(packet) => packet,
            Err(error) => {
                notify_protocol_error(&event, &error);
                return Err(error);
            }
        };
        let Some((payload, descriptors)) = packet else {
            break;
        };
        let request: WorkerRequest = match serde_json::from_slice(&payload) {
            Ok(request) => request,
            Err(error) => {
                close_descriptors(descriptors);
                let error = format!("decode worker request: {error}");
                notify_protocol_error(&event, &error);
                return Err(error);
            }
        };
        if request.magic != PROTOCOL_MAGIC || request.version != PROTOCOL_VERSION {
            close_descriptors(descriptors);
            let error = format!(
                "unsupported worker protocol magic={:?} version={}",
                request.magic, request.version
            );
            notify_protocol_error(&event, &error);
            return Err(error);
        }
        if request.request_id != next_request_id {
            close_descriptors(descriptors);
            let error = format!(
                "worker request_id {} is not the expected {next_request_id}",
                request.request_id
            );
            notify_protocol_error(&event, &error);
            return Err(error);
        }
        next_request_id = next_request_id
            .checked_add(1)
            .ok_or_else(|| "worker request_id overflow".to_string())?;
        match &request.command {
            WorkerCommand::Hello(hello)
                if !hello_complete
                    && hello.nonce == expected_nonce
                    && hello.parent_pid == expected_parent_pid => {}
            WorkerCommand::Hello(_) => {
                close_descriptors(descriptors);
                let error = "invalid or duplicate cube-vmm-worker Hello".to_string();
                notify_protocol_error(&event, &error);
                return Err(error);
            }
            _ if !hello_complete => {
                close_descriptors(descriptors);
                let error = "cube-vmm-worker command arrived before Hello".to_string();
                notify_protocol_error(&event, &error);
                return Err(error);
            }
            _ => {}
        }
        if !matches!(&request.command, WorkerCommand::CreateVm(_)) && !descriptors.is_empty() {
            let error = "descriptors are only valid with CreateVm".to_string();
            close_descriptors(descriptors);
            notify_protocol_error(&event, &error);
            return Err(error);
        }
        let shutdown = matches!(
            request.command,
            WorkerCommand::JoinVmm | WorkerCommand::ShutdownWorker
        );
        let poison_on_error = !matches!(
            request.command,
            WorkerCommand::Hello(_) | WorkerCommand::Ping
        );
        let result = execute_command(
            &mut vmm,
            &mut pending_vm_fds,
            request.command,
            descriptors,
            &event,
        );
        if result.is_ok() && !hello_complete {
            hello_complete = true;
            // PR_SET_PDEATHSIG tracks the specific thread that called fork,
            // not the parent thread group. CubeShim launches workers from a
            // Tokio worker; block_in_place may later retire that otherwise
            // healthy runtime thread and would spuriously SIGKILL the VMM.
            // Once the authenticated Hello proves the control peer, the
            // seqpacket EOF is the process-lifetime fence and the durable
            // lifecycle scanner remains the exact stuck-worker fallback.
            clear_parent_death_signal()?;
            // The worker is a long-lived server and an idle control channel is
            // healthy.  Keep writes bounded in case the still-live parent
            // stops reading, but never treat the absence of a new request as
            // a protocol failure.  The client endpoint retains its bounded
            // request/response timeout.
            set_socket_receive_timeout(control.as_raw_fd(), 0)?;
            set_socket_send_timeout(control.as_raw_fd(), COMMAND_TIMEOUT_SECS)?;
        }
        let poisoned = poison_on_error && result.is_err();
        let response = WorkerResponse {
            magic: PROTOCOL_MAGIC.to_string(),
            version: PROTOCOL_VERSION,
            request_id: request.request_id,
            result,
        };
        let payload = serde_json::to_vec(&response)
            .map_err(|error| format!("encode worker response: {error}"))?;
        send_packet(control.as_raw_fd(), &payload, &[])?;
        if shutdown && response.result.is_ok() {
            break;
        }
        if poisoned {
            if let Err(error) = &response.result {
                notify_protocol_error(&event, error);
            }
            break;
        }
    }
    drop(vmm);
    Ok(())
}

fn clear_parent_death_signal() -> CResult<()> {
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) } < 0 {
        return Err(format!(
            "clear cube-vmm-worker parent-death signal: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn execute_command(
    vmm: &mut Option<cube_hypervisor::VmmInstance>,
    pending_vm_fds: &mut PendingVmFds,
    command: WorkerCommand,
    descriptors: Vec<OwnedFd>,
    event_fd: &OwnedFd,
) -> CResult<WorkerReply> {
    match command {
        WorkerCommand::Hello(_) => {
            if vmm.is_some() {
                return Err("Hello arrived after VMM launch".to_string());
            }
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::Launch(config) => {
            if vmm.is_some() {
                return Err("cube-vmm-worker is already launched".to_string());
            }
            env::remove_var(NONCE_ENV);
            env::remove_var(PARENT_PID_ENV);
            cube_hypervisor::set_runtime_seccomp_rules(
                super::cube_hypervisor::runtime_seccomp_syscalls()
                    .into_iter()
                    .map(|syscall| (syscall, vec![]))
                    .collect(),
            );
            let (sender, receiver) = channel::<NotifyEvent>();
            let event_socket = event_fd
                .try_clone()
                .map_err(|error| format!("clone worker event socket: {error}"))?;
            std::thread::Builder::new()
                .name(format!("cube-vmm-notify-{}", config.sandbox_id))
                .spawn(move || {
                    while let Ok(event) = receiver.recv() {
                        let event: WorkerEvent = event.into();
                        let Ok(payload) = serde_json::to_vec(&event) else {
                            break;
                        };
                        if send_packet(event_socket.as_raw_fd(), &payload, &[]).is_err() {
                            break;
                        }
                    }
                })
                .map_err(|error| format!("spawn VMM event forwarder: {error}"))?;
            let mut config_out = cube_hypervisor::vmm_config::VmmConfig {
                sandbox_id: config.sandbox_id,
                log_level: level_from_wire(config.log_level)?,
                http_path: config.http_path,
                ..Default::default()
            };
            config_out.event_notifier =
                Some(cube_hypervisor::vmm_config::EventNotifyConfig { notifier: sender });
            *vmm = Some(
                cube_hypervisor::VmmInstance::new(config_out)
                    .map_err(|error| format!("launch worker VMM: {error}"))?,
            );
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::Ping => {
            send_vmm(vmm, ApiRequest::VmmPing, "ping VMM")?;
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::CreateVm(mut config) => {
            pending_vm_fds.install(&mut config, descriptors)?;
            if let Err(error) = send_vmm(vmm, ApiRequest::VmCreate(Box::new(config)), "create VM") {
                pending_vm_fds.abort();
                return Err(error);
            }
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::BootVm => {
            send_vmm(vmm, ApiRequest::VmBoot, "boot VM")?;
            // Net::from_tap_fds() duplicates each donated descriptor while
            // handling VmBoot. Keep the SCM_RIGHTS-owned originals alive
            // until that synchronous response proves the duplication is done.
            pending_vm_fds.complete_boot();
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::JoinVmm => {
            let mut instance = vmm
                .take()
                .ok_or_else(|| "cube-vmm-worker is not launched".to_string())?;
            instance
                .join()
                .map_err(|error| format!("join worker VMM: {error}"))?;
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::SnapshotVm {
            path,
            snapshot_type,
        } => {
            send_vmm(
                vmm,
                ApiRequest::VmSnapshot(Arc::new(SnapshotConfig {
                    destination_url: path,
                    snapshot_type,
                    ..Default::default()
                })),
                "snapshot VM",
            )?;
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::PauseVm => {
            send_vmm(vmm, ApiRequest::VmPause, "pause VM")?;
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::ResumeVm => {
            send_vmm(vmm, ApiRequest::VmResume, "resume VM")?;
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::RestoreVm(config) => {
            send_vmm(vmm, ApiRequest::VmRestore(Arc::new(config)), "restore VM")?;
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::SetFs(config) => {
            send_vmm(vmm, ApiRequest::VmSetFs(Arc::new(config)), "set VM fs")?;
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::AddDevice(config) => {
            let response = send_vmm(
                vmm,
                ApiRequest::VmAddDevice(Arc::new(config)),
                "add VM device",
            )?;
            match response {
                ApiResponsePayload::VmAction(payload) => Ok(WorkerReply::ActionPayload(payload)),
                _ => Ok(WorkerReply::ActionPayload(None)),
            }
        }
        WorkerCommand::RemoveDevice(config) => {
            send_vmm(
                vmm,
                ApiRequest::VmRemoveDevice(Arc::new(config)),
                "remove VM device",
            )?;
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::DeleteVm => {
            send_vmm(vmm, ApiRequest::VmDelete, "delete VM")?;
            pending_vm_fds.abort();
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::PauseToSnapshot(config) => {
            send_vmm(
                vmm,
                ApiRequest::VmPauseToSnapshot(Arc::new(config)),
                "pause VM to snapshot",
            )?;
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::ResumeFromSnapshot(config) => {
            send_vmm(
                vmm,
                ApiRequest::VmResumeFromSnapshot(Arc::new(config)),
                "resume VM from snapshot",
            )?;
            Ok(WorkerReply::Empty)
        }
        WorkerCommand::ShutdownWorker => {
            let mut instance = vmm
                .take()
                .ok_or_else(|| "cube-vmm-worker is not launched".to_string())?;
            instance
                .send_request(ApiRequest::VmmShutdown)
                .map_err(|error| format!("shutdown worker VMM request: {error}"))?
                .map_err(|error| format!("shutdown worker VMM response: {error}"))?;
            instance
                .join()
                .map_err(|error| format!("join worker VMM: {error}"))?;
            Ok(WorkerReply::Empty)
        }
    }
}

fn send_vmm(
    vmm: &Option<cube_hypervisor::VmmInstance>,
    request: ApiRequest,
    action: &str,
) -> CResult<ApiResponsePayload> {
    vmm.as_ref()
        .ok_or_else(|| "cube-vmm-worker is not launched".to_string())?
        .send_request(request)
        .map_err(|error| format!("{action} request: {error}"))?
        .map_err(|error| format!("{action} response: {error}"))
}

pub(crate) fn extract_vm_fds(config: &mut VmConfig) -> Vec<RawFd> {
    let mut descriptors = Vec::new();
    if let Some(networks) = config.net.as_mut() {
        for network in networks {
            if let Some(fds) = network.fds.as_mut() {
                for fd in fds {
                    descriptors.push(*fd);
                    *fd = (descriptors.len() - 1) as RawFd;
                }
            }
        }
    }
    descriptors
}

fn install_vm_fds(config: &mut VmConfig, descriptors: &[OwnedFd]) -> CResult<()> {
    let expected = config
        .net
        .as_ref()
        .into_iter()
        .flatten()
        .filter_map(|network| network.fds.as_ref())
        .map(Vec::len)
        .sum::<usize>();
    if expected != descriptors.len() {
        return Err(format!(
            "CreateVm expected {expected} descriptors but received {}",
            descriptors.len()
        ));
    }
    let mut used_slots = std::collections::BTreeSet::new();
    if let Some(networks) = config.net.as_mut() {
        for network in networks {
            if let Some(fds) = network.fds.as_mut() {
                for fd in fds {
                    let slot = usize::try_from(*fd)
                        .map_err(|_| format!("negative CreateVm FD slot {fd}"))?;
                    if !used_slots.insert(slot) {
                        return Err(format!("duplicate CreateVm FD slot {slot}"));
                    }
                    let descriptor = descriptors.get(slot).ok_or_else(|| {
                        format!(
                            "CreateVm FD slot {slot} exceeds {} rights",
                            descriptors.len()
                        )
                    })?;
                    *fd = descriptor.as_raw_fd();
                }
            }
        }
    }
    if used_slots.len() != descriptors.len() {
        return Err("CreateVm FD slots do not cover every received descriptor".to_string());
    }
    Ok(())
}

#[derive(Default)]
struct PendingVmFds {
    descriptors: Option<Vec<OwnedFd>>,
}

impl PendingVmFds {
    fn install(&mut self, config: &mut VmConfig, descriptors: Vec<OwnedFd>) -> CResult<()> {
        if self.descriptors.is_some() {
            return Err("CreateVm descriptors are already pending VmBoot".to_string());
        }
        install_vm_fds(config, &descriptors)?;
        self.descriptors = Some(descriptors);
        Ok(())
    }

    fn abort(&mut self) {
        self.descriptors = None;
    }

    fn complete_boot(&mut self) {
        self.descriptors = None;
    }
}

fn seqpacket_pair() -> CResult<(OwnedFd, OwnedFd)> {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(|error| format!("create cube-vmm-worker socketpair: {error}"))
}

fn clear_cloexec_io(fd: RawFd) -> std::io::Result<()> {
    let current = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if current < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, current & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Configure the worker side of the inherited IPC channels immediately before
/// `exec`. This is public only so the subprocess contract test can exercise the
/// exact production pre-exec gate.
///
/// # Safety
///
/// This function closes inheritance for every descriptor above stderr except
/// `control_fd` and `event_fd`; it must only run in a freshly forked child from
/// a `Command::pre_exec` callback.
#[doc(hidden)]
pub unsafe fn configure_worker_child_before_exec(
    control_fd: RawFd,
    event_fd: RawFd,
    parent_pid: u32,
) -> std::io::Result<()> {
    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if libc::getppid() != parent_pid as libc::pid_t {
        return Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "CubeShim parent exited before cube-vmm-worker exec",
        ));
    }
    let result = libc::syscall(
        libc::SYS_close_range,
        3_u32,
        u32::MAX,
        libc::CLOSE_RANGE_CLOEXEC,
    );
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    clear_cloexec_io(control_fd)?;
    clear_cloexec_io(event_fd)?;
    Ok(())
}

fn set_cloexec(fd: RawFd) -> CResult<()> {
    let current = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if current < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, current | libc::FD_CLOEXEC) } < 0 {
        return Err(format!(
            "set cube-vmm-worker FD_CLOEXEC: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn set_socket_timeout(fd: RawFd, seconds: i64) -> CResult<()> {
    set_socket_receive_timeout(fd, seconds)?;
    set_socket_send_timeout(fd, seconds)
}

fn set_socket_receive_timeout(fd: RawFd, seconds: i64) -> CResult<()> {
    set_socket_option_timeout(fd, libc::SO_RCVTIMEO, seconds)
}

fn set_socket_send_timeout(fd: RawFd, seconds: i64) -> CResult<()> {
    set_socket_option_timeout(fd, libc::SO_SNDTIMEO, seconds)
}

fn set_socket_option_timeout(fd: RawFd, option: libc::c_int, seconds: i64) -> CResult<()> {
    let timeout = libc::timeval {
        tv_sec: seconds,
        tv_usec: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(format!(
            "set cube-vmm-worker socket timeout: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn verify_worker_fd_allowlist(pid: u32, control_fd: RawFd, event_fd: RawFd) -> CResult<()> {
    let directory = PathBuf::from(format!("/proc/{pid}/fd"));
    let mut actual = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&directory)
        .map_err(|error| format!("read worker FD directory {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("read worker FD entry: {error}"))?;
        let fd = entry
            .file_name()
            .to_string_lossy()
            .parse::<RawFd>()
            .map_err(|error| format!("parse worker FD entry: {error}"))?;
        actual.insert(fd);
    }
    let expected = [0, 1, 2, control_fd, event_fd]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "cube-vmm-worker gate FD allowlist mismatch: actual={actual:?} expected={expected:?}"
        ));
    }
    Ok(())
}

fn inherited_fd_number(name: &str) -> CResult<RawFd> {
    env::var(name)
        .map_err(|error| format!("read {name}: {error}"))?
        .parse::<RawFd>()
        .map_err(|error| format!("parse {name}: {error}"))
}

fn validate_inherited_seqpacket(name: &str, raw: RawFd) -> CResult<()> {
    if raw <= libc::STDERR_FILENO {
        return Err(format!("{name} must be greater than stderr, got {raw}"));
    }
    if unsafe { libc::fcntl(raw, libc::F_GETFD) } < 0 {
        return Err(format!(
            "validate {name} descriptor {raw}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut socket_type: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(format!(
            "validate {name} socket type: {}",
            std::io::Error::last_os_error()
        ));
    }
    if length as usize != std::mem::size_of::<libc::c_int>() || socket_type != libc::SOCK_SEQPACKET
    {
        return Err(format!("{name} descriptor {raw} is not SOCK_SEQPACKET"));
    }
    Ok(())
}

fn inherited_fds() -> CResult<(OwnedFd, OwnedFd)> {
    let control_raw = inherited_fd_number(CONTROL_FD_ENV)?;
    let event_raw = inherited_fd_number(EVENT_FD_ENV)?;
    if control_raw == event_raw {
        return Err(format!(
            "{CONTROL_FD_ENV} and {EVENT_FD_ENV} must name distinct descriptors"
        ));
    }
    validate_inherited_seqpacket(CONTROL_FD_ENV, control_raw)?;
    validate_inherited_seqpacket(EVENT_FD_ENV, event_raw)?;
    env::remove_var(CONTROL_FD_ENV);
    env::remove_var(EVENT_FD_ENV);
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(control_raw),
            OwnedFd::from_raw_fd(event_raw),
        )
    })
}

fn send_packet(fd: RawFd, payload: &[u8], descriptors: &[RawFd]) -> CResult<()> {
    if payload.is_empty() || payload.len() > MAX_PACKET_SIZE {
        return Err(format!("invalid worker packet size {}", payload.len()));
    }
    let iov = [IoSlice::new(payload)];
    let sent = if descriptors.is_empty() {
        sendmsg::<()>(fd, &iov, &[], MsgFlags::MSG_NOSIGNAL, None)
    } else {
        sendmsg::<()>(
            fd,
            &iov,
            &[ControlMessage::ScmRights(descriptors)],
            MsgFlags::MSG_NOSIGNAL,
            None,
        )
    }
    .map_err(|error| format!("send worker packet: {error}"))?;
    if sent != payload.len() {
        return Err(format!(
            "short worker seqpacket send: {sent}/{}",
            payload.len()
        ));
    }
    Ok(())
}

fn notify_protocol_error(event_fd: &OwnedFd, message: &str) {
    if let Ok(payload) = serde_json::to_vec(&WorkerEvent::ProtocolError(message.to_string())) {
        let _ = send_packet(event_fd.as_raw_fd(), &payload, &[]);
    }
}

fn recv_packet(fd: RawFd) -> CResult<Option<(Vec<u8>, Vec<OwnedFd>)>> {
    let mut payload = vec![0_u8; MAX_PACKET_SIZE];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let control_len = unsafe {
        libc::CMSG_SPACE((MAX_HANDOFF_FDS * std::mem::size_of::<RawFd>()) as u32) as usize
    };
    let mut control = vec![0_u8; control_len];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let received = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(format!(
            "receive worker packet: {}",
            std::io::Error::last_os_error()
        ));
    }
    let descriptors = receive_descriptors(&message)?;
    let received = received as usize;
    if received == 0 {
        return Ok(None);
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err("truncated cube-vmm-worker packet".to_string());
    }
    payload.truncate(received);
    Ok(Some((payload, descriptors)))
}

fn receive_descriptors(message: &libc::msghdr) -> CResult<Vec<OwnedFd>> {
    let mut descriptors = Vec::new();
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let header_len = unsafe { (*header).cmsg_len as usize };
        let minimum_len = unsafe { libc::CMSG_LEN(0) as usize };
        if header_len < minimum_len {
            return Err("decode worker control message: invalid header length".to_string());
        }
        let level = unsafe { (*header).cmsg_level };
        let kind = unsafe { (*header).cmsg_type };
        if level != libc::SOL_SOCKET || kind != libc::SCM_RIGHTS {
            return Err(format!(
                "decode worker control message: unsupported level={level} type={kind}"
            ));
        }
        let data_len = header_len - minimum_len;
        if data_len == 0 || data_len % std::mem::size_of::<RawFd>() != 0 {
            return Err("decode worker SCM_RIGHTS: invalid descriptor bytes".to_string());
        }
        let count = data_len / std::mem::size_of::<RawFd>();
        if descriptors.len().saturating_add(count) > MAX_HANDOFF_FDS {
            return Err(format!(
                "worker packet has more than {MAX_HANDOFF_FDS} descriptors"
            ));
        }
        let rights = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
        for index in 0..count {
            let raw = unsafe { *rights.add(index) };
            if raw < 0 {
                return Err("decode worker SCM_RIGHTS: negative descriptor".to_string());
            }
            descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    Ok(descriptors)
}

fn close_descriptors(descriptors: Vec<OwnedFd>) {
    drop(descriptors);
}

fn worker_path() -> CResult<PathBuf> {
    if let Some(path) = env::var_os(WORKER_PATH_ENV) {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(format!(
                "{WORKER_PATH_ENV} must be absolute: {}",
                path.display()
            ));
        }
        return Ok(path);
    }
    let executable =
        env::current_exe().map_err(|error| format!("resolve CubeShim executable: {error}"))?;
    let sibling = executable.with_file_name("cube-vmm-worker");
    if sibling.is_file() {
        return Ok(sibling);
    }
    Ok(Path::new("/usr/local/bin/cube-vmm-worker").to_path_buf())
}

fn terminate_child(child: &mut Child) -> CResult<()> {
    if child
        .try_wait()
        .map_err(|error| format!("inspect cube-vmm-worker before termination: {error}"))?
        .is_some()
    {
        return Ok(());
    }
    if let Err(error) = child.kill() {
        if child
            .try_wait()
            .map_err(|wait_error| {
                format!(
                    "terminate cube-vmm-worker: {error}; inspect after kill failure: {wait_error}"
                )
            })?
            .is_none()
        {
            return Err(format!("terminate cube-vmm-worker: {error}"));
        }
        return Ok(());
    }
    wait_child(child, Duration::from_secs(2)).map(|_| ())
}

fn wait_child(child: &mut Child, timeout: Duration) -> CResult<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("wait for cube-vmm-worker: {error}"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting {:?} for cube-vmm-worker {}",
                timeout,
                child.id()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn level_to_wire(level: log::LevelFilter) -> u8 {
    match level {
        log::LevelFilter::Off => 0,
        log::LevelFilter::Error => 1,
        log::LevelFilter::Warn => 2,
        log::LevelFilter::Info => 3,
        log::LevelFilter::Debug => 4,
        log::LevelFilter::Trace => 5,
    }
}

fn level_from_wire(level: u8) -> CResult<log::LevelFilter> {
    match level {
        0 => Ok(log::LevelFilter::Off),
        1 => Ok(log::LevelFilter::Error),
        2 => Ok(log::LevelFilter::Warn),
        3 => Ok(log::LevelFilter::Info),
        4 => Ok(log::LevelFilter::Debug),
        5 => Ok(log::LevelFilter::Trace),
        _ => Err(format!("invalid cube-vmm-worker log level {level}")),
    }
}

impl From<NotifyEvent> for WorkerEvent {
    fn from(event: NotifyEvent) -> Self {
        match event {
            NotifyEvent::VmShutdown => Self::VmShutdown,
            NotifyEvent::VsockServerReady => Self::VsockServerReady,
            NotifyEvent::RestoreReady => Self::RestoreReady,
            NotifyEvent::SysStart => Self::SysStart,
            NotifyEvent::MigrationComplete => Self::MigrationComplete,
            NotifyEvent::MigrationFail => Self::MigrationFail,
        }
    }
}

impl From<WorkerEvent> for NotifyEvent {
    fn from(event: WorkerEvent) -> Self {
        match event {
            WorkerEvent::VmShutdown => Self::VmShutdown,
            WorkerEvent::VsockServerReady => Self::VsockServerReady,
            WorkerEvent::RestoreReady => Self::RestoreReady,
            WorkerEvent::SysStart => Self::SysStart,
            WorkerEvent::MigrationComplete => Self::MigrationComplete,
            WorkerEvent::MigrationFail => Self::MigrationFail,
            WorkerEvent::ProtocolError(_) => Self::VmShutdown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cube_hypervisor::vm_config::BalloonConfig;
    use std::fs::File;
    use std::sync::Mutex as StdMutex;

    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    #[test]
    fn create_vm_balloon_config_round_trips_over_worker_protocol() {
        for balloon in [
            Some(BalloonConfig {
                size: 0,
                deflate_on_oom: false,
                free_page_reporting: true,
            }),
            None,
        ] {
            let mut config = VmConfig::default();
            config.balloon = balloon.clone();
            let request = WorkerRequest {
                magic: PROTOCOL_MAGIC.to_string(),
                version: PROTOCOL_VERSION,
                request_id: 1,
                command: WorkerCommand::CreateVm(config),
            };

            let payload = serde_json::to_vec(&request).unwrap();
            let decoded: WorkerRequest = serde_json::from_slice(&payload).unwrap();
            let WorkerCommand::CreateVm(config) = decoded.command else {
                panic!("worker request changed command during serialization");
            };

            match (balloon, config.balloon) {
                (Some(expected), Some(actual)) => {
                    assert_eq!(actual.size, expected.size);
                    assert_eq!(actual.deflate_on_oom, expected.deflate_on_oom);
                    assert_eq!(actual.free_page_reporting, expected.free_page_reporting);
                }
                (None, None) => {}
                _ => panic!("worker protocol changed balloon presence"),
            }
        }
    }

    #[test]
    fn vm_fd_slots_round_trip_over_scm_rights() {
        let (sender, receiver) = seqpacket_pair().unwrap();
        let file = File::open("/dev/null").unwrap();
        let payload = b"fd-handoff";

        send_packet(sender.as_raw_fd(), payload, &[file.as_raw_fd()]).unwrap();
        let (actual, descriptors) = recv_packet(receiver.as_raw_fd()).unwrap().unwrap();

        assert_eq!(actual, payload);
        assert_eq!(descriptors.len(), 1);
        assert!(unsafe { libc::fcntl(descriptors[0].as_raw_fd(), libc::F_GETFD) } >= 0);
    }

    #[test]
    fn vm_fd_stays_open_until_boot_completes() {
        let (sender, receiver) = seqpacket_pair().unwrap();
        let file = File::open("/dev/null").unwrap();
        send_packet(sender.as_raw_fd(), b"tap", &[file.as_raw_fd()]).unwrap();
        let (_, descriptors) = recv_packet(receiver.as_raw_fd()).unwrap().unwrap();
        let received_fd = descriptors[0].as_raw_fd();

        let mut config = VmConfig::default();
        config.net = Some(vec![cube_hypervisor::vm_config::NetConfig {
            fds: Some(vec![0]),
            ..Default::default()
        }]);
        let mut pending = PendingVmFds::default();
        pending.install(&mut config, descriptors).unwrap();

        assert_eq!(config.net.unwrap()[0].fds.as_ref().unwrap(), &[received_fd]);
        assert!(unsafe { libc::fcntl(received_fd, libc::F_GETFD) } >= 0);
        assert!(pending
            .install(&mut VmConfig::default(), Vec::new())
            .unwrap_err()
            .contains("already pending"));

        pending.complete_boot();
        assert_eq!(unsafe { libc::fcntl(received_fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn vm_fd_delete_releases_pending_and_allows_create_again() {
        let first: OwnedFd = File::open("/dev/null").unwrap().into();
        let first_fd = first.as_raw_fd();
        let mut first_config = VmConfig::default();
        first_config.net = Some(vec![cube_hypervisor::vm_config::NetConfig {
            fds: Some(vec![0]),
            ..Default::default()
        }]);
        let mut pending = PendingVmFds::default();
        pending.install(&mut first_config, vec![first]).unwrap();

        pending.abort();
        assert_eq!(unsafe { libc::fcntl(first_fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );

        let second: OwnedFd = File::open("/dev/null").unwrap().into();
        let second_fd = second.as_raw_fd();
        let mut second_config = VmConfig::default();
        second_config.net = Some(vec![cube_hypervisor::vm_config::NetConfig {
            fds: Some(vec![0]),
            ..Default::default()
        }]);
        pending.install(&mut second_config, vec![second]).unwrap();
        assert_eq!(
            second_config.net.unwrap()[0].fds.as_ref().unwrap(),
            &[second_fd]
        );
        assert!(unsafe { libc::fcntl(second_fd, libc::F_GETFD) } >= 0);
    }

    #[test]
    fn vm_fd_slots_reject_missing_rights() {
        let mut config = VmConfig::default();
        config.net = Some(vec![cube_hypervisor::vm_config::NetConfig {
            fds: Some(vec![0]),
            ..Default::default()
        }]);

        assert!(install_vm_fds(&mut config, &[])
            .unwrap_err()
            .contains("expected 1 descriptors"));
    }

    #[test]
    fn vm_fd_slots_reject_duplicate_and_out_of_range_slots() {
        let first = File::open("/dev/null").unwrap();
        let second = File::open("/dev/null").unwrap();
        let descriptors = vec![
            OwnedFd::from(first.try_clone().unwrap()),
            OwnedFd::from(second.try_clone().unwrap()),
        ];

        let mut duplicate = VmConfig::default();
        duplicate.net = Some(vec![cube_hypervisor::vm_config::NetConfig {
            fds: Some(vec![0, 0]),
            ..Default::default()
        }]);
        assert!(install_vm_fds(&mut duplicate, &descriptors)
            .unwrap_err()
            .contains("duplicate"));

        let mut out_of_range = VmConfig::default();
        out_of_range.net = Some(vec![cube_hypervisor::vm_config::NetConfig {
            fds: Some(vec![0, 2]),
            ..Default::default()
        }]);
        assert!(install_vm_fds(&mut out_of_range, &descriptors)
            .unwrap_err()
            .contains("exceeds 2 rights"));
    }

    #[test]
    fn recv_packet_rejects_truncated_scm_rights() {
        let (sender, receiver) = seqpacket_pair().unwrap();
        let path =
            std::env::temp_dir().join(format!("cube-vmm-worker-fd-leak-{}", uuid::Uuid::new_v4()));
        let file = File::create(&path).unwrap();
        let count_open = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    std::fs::read_link(entry.path()).ok().as_deref() == Some(path.as_path())
                })
                .count()
        };
        assert_eq!(count_open(), 1);
        let descriptors = vec![file.as_raw_fd(); MAX_HANDOFF_FDS + 1];
        send_packet(sender.as_raw_fd(), b"too-many-rights", &descriptors).unwrap();
        let error = recv_packet(receiver.as_raw_fd()).unwrap_err();
        assert!(
            error.contains("truncated") || error.contains("decode worker control message"),
            "unexpected receive error: {error}"
        );
        assert_eq!(count_open(), 1, "truncated SCM_RIGHTS leaked descriptors");
        std::fs::remove_file(path).unwrap();
    }

    fn assert_protocol_rejected(request: WorkerRequest, expected: &str) {
        let (control_parent, control_child) = seqpacket_pair().unwrap();
        let (event_parent, event_child) = seqpacket_pair().unwrap();
        set_socket_timeout(event_parent.as_raw_fd(), 1).unwrap();
        let worker = std::thread::spawn(move || {
            run_worker(
                control_child,
                event_child,
                "expected-nonce".to_string(),
                std::process::id(),
            )
        });
        let payload = serde_json::to_vec(&request).unwrap();
        send_packet(control_parent.as_raw_fd(), &payload, &[]).unwrap();
        let (payload, descriptors) = recv_packet(event_parent.as_raw_fd()).unwrap().unwrap();
        assert!(descriptors.is_empty());
        let WorkerEvent::ProtocolError(message) =
            serde_json::from_slice::<WorkerEvent>(&payload).unwrap()
        else {
            panic!("expected protocol error event");
        };
        assert!(message.contains(expected), "unexpected error: {message}");
        assert!(worker.join().unwrap().unwrap_err().contains(expected));
    }

    #[test]
    fn worker_rejects_unknown_version_and_out_of_order_request_id() {
        assert_protocol_rejected(
            WorkerRequest {
                magic: PROTOCOL_MAGIC.to_string(),
                version: PROTOCOL_VERSION + 1,
                request_id: 1,
                command: WorkerCommand::Hello(HelloConfig {
                    nonce: "expected-nonce".to_string(),
                    parent_pid: std::process::id(),
                }),
            },
            "unsupported worker protocol",
        );
        assert_protocol_rejected(
            WorkerRequest {
                magic: PROTOCOL_MAGIC.to_string(),
                version: PROTOCOL_VERSION,
                request_id: 2,
                command: WorkerCommand::Hello(HelloConfig {
                    nonce: "expected-nonce".to_string(),
                    parent_pid: std::process::id(),
                }),
            },
            "not the expected 1",
        );
    }

    #[test]
    fn worker_rejects_duplicate_hello() {
        let (control_parent, control_child) = seqpacket_pair().unwrap();
        let (event_parent, event_child) = seqpacket_pair().unwrap();
        set_socket_timeout(event_parent.as_raw_fd(), 1).unwrap();
        let worker = std::thread::spawn(move || {
            run_worker(
                control_child,
                event_child,
                "expected-nonce".to_string(),
                std::process::id(),
            )
        });
        for request_id in [1, 2] {
            let payload = serde_json::to_vec(&WorkerRequest {
                magic: PROTOCOL_MAGIC.to_string(),
                version: PROTOCOL_VERSION,
                request_id,
                command: WorkerCommand::Hello(HelloConfig {
                    nonce: "expected-nonce".to_string(),
                    parent_pid: std::process::id(),
                }),
            })
            .unwrap();
            send_packet(control_parent.as_raw_fd(), &payload, &[]).unwrap();
            if request_id == 1 {
                let (payload, descriptors) =
                    recv_packet(control_parent.as_raw_fd()).unwrap().unwrap();
                assert!(descriptors.is_empty());
                let response: WorkerResponse = serde_json::from_slice(&payload).unwrap();
                assert_eq!(response.request_id, 1);
                assert!(matches!(response.result, Ok(WorkerReply::Empty)));
            }
        }
        let (payload, _) = recv_packet(event_parent.as_raw_fd()).unwrap().unwrap();
        let WorkerEvent::ProtocolError(message) =
            serde_json::from_slice::<WorkerEvent>(&payload).unwrap()
        else {
            panic!("expected protocol error event");
        };
        assert!(message.contains("duplicate"));
        assert!(worker.join().unwrap().unwrap_err().contains("duplicate"));
    }

    #[test]
    fn worker_poisons_descriptor_bearing_non_create_command() {
        let (control_parent, control_child) = seqpacket_pair().unwrap();
        let (event_parent, event_child) = seqpacket_pair().unwrap();
        set_socket_timeout(event_parent.as_raw_fd(), 1).unwrap();
        let worker = std::thread::spawn(move || {
            run_worker(
                control_child,
                event_child,
                "expected-nonce".to_string(),
                std::process::id(),
            )
        });
        let hello = WorkerRequest {
            magic: PROTOCOL_MAGIC.to_string(),
            version: PROTOCOL_VERSION,
            request_id: 1,
            command: WorkerCommand::Hello(HelloConfig {
                nonce: "expected-nonce".to_string(),
                parent_pid: std::process::id(),
            }),
        };
        send_packet(
            control_parent.as_raw_fd(),
            &serde_json::to_vec(&hello).unwrap(),
            &[],
        )
        .unwrap();
        let (payload, _) = recv_packet(control_parent.as_raw_fd()).unwrap().unwrap();
        assert!(matches!(
            serde_json::from_slice::<WorkerResponse>(&payload)
                .unwrap()
                .result,
            Ok(WorkerReply::Empty)
        ));

        let ping = WorkerRequest {
            magic: PROTOCOL_MAGIC.to_string(),
            version: PROTOCOL_VERSION,
            request_id: 2,
            command: WorkerCommand::Ping,
        };
        let file = File::open("/dev/null").unwrap();
        send_packet(
            control_parent.as_raw_fd(),
            &serde_json::to_vec(&ping).unwrap(),
            &[file.as_raw_fd()],
        )
        .unwrap();
        let (payload, _) = recv_packet(event_parent.as_raw_fd()).unwrap().unwrap();
        let WorkerEvent::ProtocolError(message) =
            serde_json::from_slice::<WorkerEvent>(&payload).unwrap()
        else {
            panic!("expected protocol error event");
        };
        assert!(message.contains("descriptors are only valid with CreateVm"));
        assert!(worker
            .join()
            .unwrap()
            .unwrap_err()
            .contains("descriptors are only valid with CreateVm"));
    }

    #[test]
    fn worker_hello_timeout_is_bounded() {
        let (_control_parent, control_child) = seqpacket_pair().unwrap();
        let (event_parent, event_child) = seqpacket_pair().unwrap();
        set_socket_timeout(control_child.as_raw_fd(), 1).unwrap();
        set_socket_timeout(event_parent.as_raw_fd(), 2).unwrap();
        let worker = std::thread::spawn(move || {
            run_worker(
                control_child,
                event_child,
                "expected-nonce".to_string(),
                std::process::id(),
            )
        });
        let (payload, _) = recv_packet(event_parent.as_raw_fd()).unwrap().unwrap();
        assert!(matches!(
            serde_json::from_slice::<WorkerEvent>(&payload).unwrap(),
            WorkerEvent::ProtocolError(_)
        ));
        assert!(worker
            .join()
            .unwrap()
            .unwrap_err()
            .contains("receive worker packet"));
    }

    #[test]
    fn worker_clears_receive_timeout_after_hello() {
        let (control_parent, control_child) = seqpacket_pair().unwrap();
        let control_probe = control_child.try_clone().unwrap();
        let (_event_parent, event_child) = seqpacket_pair().unwrap();
        set_socket_receive_timeout(control_child.as_raw_fd(), HELLO_TIMEOUT_SECS).unwrap();
        let parent_pid = std::process::id();
        let worker = std::thread::spawn(move || {
            run_worker(
                control_child,
                event_child,
                "expected-nonce".to_string(),
                parent_pid,
            )
        });

        let request = WorkerRequest {
            magic: PROTOCOL_MAGIC.to_string(),
            version: PROTOCOL_VERSION,
            request_id: 1,
            command: WorkerCommand::Hello(HelloConfig {
                nonce: "expected-nonce".to_string(),
                parent_pid,
            }),
        };
        send_packet(
            control_parent.as_raw_fd(),
            &serde_json::to_vec(&request).unwrap(),
            &[],
        )
        .unwrap();
        let (payload, descriptors) = recv_packet(control_parent.as_raw_fd()).unwrap().unwrap();
        assert!(descriptors.is_empty());
        let response: WorkerResponse = serde_json::from_slice(&payload).unwrap();
        assert!(matches!(response.result, Ok(WorkerReply::Empty)));

        let mut timeout = libc::timeval {
            tv_sec: -1,
            tv_usec: -1,
        };
        let mut length = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    control_probe.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&mut timeout as *mut libc::timeval).cast(),
                    &mut length,
                )
            },
            0
        );
        assert_eq!(timeout.tv_sec, 0);
        assert_eq!(timeout.tv_usec, 0);

        drop(control_probe);
        drop(control_parent);
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn mutation_response_identity_mismatch_poisons_client() {
        let (control_client, control_server) = seqpacket_pair().unwrap();
        let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let client = WorkerClient {
            inner: Arc::new(WorkerClientInner {
                control: Mutex::new(control_client),
                child: Mutex::new(child),
                next_request_id: AtomicU64::new(1),
                poisoned: AtomicBool::new(false),
                reaped: AtomicBool::new(false),
            }),
        };
        let server = std::thread::spawn(move || {
            let (payload, descriptors) = recv_packet(control_server.as_raw_fd()).unwrap().unwrap();
            assert!(descriptors.is_empty());
            let request: WorkerRequest = serde_json::from_slice(&payload).unwrap();
            let response = WorkerResponse {
                magic: PROTOCOL_MAGIC.to_string(),
                version: PROTOCOL_VERSION,
                request_id: request.request_id + 1,
                result: Ok(WorkerReply::Empty),
            };
            send_packet(
                control_server.as_raw_fd(),
                &serde_json::to_vec(&response).unwrap(),
                &[],
            )
            .unwrap();
        });
        assert!(client
            .request(WorkerCommand::DeleteVm, &[])
            .unwrap_err()
            .contains("identity mismatch"));
        assert!(client.inner.poisoned.load(Ordering::Acquire));
        assert_eq!(
            client.request(WorkerCommand::DeleteVm, &[]).unwrap_err(),
            "cube-vmm-worker is poisoned"
        );
        server.join().unwrap();
    }

    #[test]
    fn cloned_clients_serialize_request_ids_and_responses() {
        let (control_client, control_server) = seqpacket_pair().unwrap();
        let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let client = WorkerClient {
            inner: Arc::new(WorkerClientInner {
                control: Mutex::new(control_client),
                child: Mutex::new(child),
                next_request_id: AtomicU64::new(1),
                poisoned: AtomicBool::new(false),
                reaped: AtomicBool::new(false),
            }),
        };
        let server = std::thread::spawn(move || {
            for expected_id in [1, 2] {
                let (payload, descriptors) =
                    recv_packet(control_server.as_raw_fd()).unwrap().unwrap();
                assert!(descriptors.is_empty());
                let request: WorkerRequest = serde_json::from_slice(&payload).unwrap();
                assert_eq!(request.request_id, expected_id);
                assert!(matches!(request.command, WorkerCommand::Ping));
                let response = WorkerResponse {
                    magic: PROTOCOL_MAGIC.to_string(),
                    version: PROTOCOL_VERSION,
                    request_id: request.request_id,
                    result: Ok(WorkerReply::Empty),
                };
                send_packet(
                    control_server.as_raw_fd(),
                    &serde_json::to_vec(&response).unwrap(),
                    &[],
                )
                .unwrap();
            }
        });
        let first = {
            let client = client.clone();
            std::thread::spawn(move || client.request(WorkerCommand::Ping, &[]))
        };
        let second = {
            let client = client.clone();
            std::thread::spawn(move || client.request(WorkerCommand::Ping, &[]))
        };
        assert!(matches!(first.join().unwrap(), Ok(WorkerReply::Empty)));
        assert!(matches!(second.join().unwrap(), Ok(WorkerReply::Empty)));
        server.join().unwrap();
        client.terminate().unwrap();
    }

    #[test]
    fn reply_payload_mismatch_poisons_channel() {
        let (control_client, control_server) = seqpacket_pair().unwrap();
        let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let client = WorkerClient {
            inner: Arc::new(WorkerClientInner {
                control: Mutex::new(control_client),
                child: Mutex::new(child),
                next_request_id: AtomicU64::new(1),
                poisoned: AtomicBool::new(false),
                reaped: AtomicBool::new(false),
            }),
        };
        let server = std::thread::spawn(move || {
            let (payload, _) = recv_packet(control_server.as_raw_fd()).unwrap().unwrap();
            let request: WorkerRequest = serde_json::from_slice(&payload).unwrap();
            let response = WorkerResponse {
                magic: PROTOCOL_MAGIC.to_string(),
                version: PROTOCOL_VERSION,
                request_id: request.request_id,
                result: Ok(WorkerReply::ActionPayload(None)),
            };
            send_packet(
                control_server.as_raw_fd(),
                &serde_json::to_vec(&response).unwrap(),
                &[],
            )
            .unwrap();
        });
        assert!(client
            .request(WorkerCommand::Ping, &[])
            .unwrap_err()
            .contains("does not match request opcode"));
        server.join().unwrap();
        assert!(client.inner.poisoned.load(Ordering::Acquire));
        assert!(client.inner.reaped.load(Ordering::Acquire));
    }

    #[test]
    fn backend_switch_is_fail_closed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = env::var_os(BACKEND_ENV);
        env::set_var(BACKEND_ENV, "invalid");
        assert!(worker_backend_enabled().is_err());
        match old {
            Some(value) => env::set_var(BACKEND_ENV, value),
            None => env::remove_var(BACKEND_ENV),
        }
    }
}
