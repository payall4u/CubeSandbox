// Copyright (c) 2024 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

package runtimeresource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/moby/sys/mountinfo"
	runtimev1 "github.com/tencentcloud/CubeSandbox/Cubelet/api/services/runtime/v1"
	"github.com/tencentcloud/CubeSandbox/Cubelet/internal/kmutex"
	"github.com/tencentcloud/CubeSandbox/Cubelet/internal/monotime"
	runtimeservice "github.com/tencentcloud/CubeSandbox/Cubelet/services/runtime"
	"github.com/tencentcloud/CubeSandbox/Cubelet/services/runtime/handoff"
	"github.com/tencentcloud/CubeSandbox/Cubelet/services/runtime/state"
	"golang.org/x/sys/unix"
)

type Assets struct {
	KernelPath     string
	AgentPath      string
	GuestImagePath string
	SharedRootBase string
}

type NetworkOps interface {
	Prepare(context.Context, string, string, string) (*runtimev1.NetworkAttachment, error)
	Release(context.Context, string, string, string) error
	Open(string, string) (*os.File, error)
}

type prepareStage string

type startupTraceIdentity struct {
	sandboxID   string
	podUID      string
	operationID string
}

type startupTraceIdentityKey struct{}

func withStartupTraceIdentity(ctx context.Context, request *runtimev1.PrepareSandboxRequest) context.Context {
	if request == nil {
		return ctx
	}
	return context.WithValue(ctx, startupTraceIdentityKey{}, startupTraceIdentity{
		sandboxID: request.GetSandboxId(), podUID: request.GetPod().GetUid(), operationID: request.GetSandboxId(),
	})
}

func startupTraceIdentityFromContext(ctx context.Context) startupTraceIdentity {
	identity, _ := ctx.Value(startupTraceIdentityKey{}).(startupTraceIdentity)
	return identity
}

const (
	stageIntent     prepareStage = "INTENT"
	stageSharedRoot prepareStage = "SHARED_ROOT"
	stagePrepared   prepareStage = "PREPARED"
)

type adapter struct {
	operations  kmutex.KeyedLocker
	tapMu       sync.Mutex
	stateDir    string
	assets      Assets
	network     NetworkOps
	persistHook func(prepareStage, *diskRecord) error
	tapFiles    map[string]*os.File
	closeTap    func(*os.File) error
	cleanup     sharedRootCleanupOps
}

type sharedRootCleanupOps struct {
	mountTargets func(string) ([]string, error)
	unmount      func(string, int) error
	removeAll    func(string) error
}

type diskRecord struct {
	Stage         prepareStage                 `json:"stage"`
	SandboxID     string                       `json:"sandbox_id"`
	Generation    uint64                       `json:"generation"`
	LeaseID       string                       `json:"lease_id"`
	NetworkHandle string                       `json:"network_handle"`
	NetNSPath     string                       `json:"netns_path"`
	InterfaceName string                       `json:"interface_name"`
	TapName       string                       `json:"tap_name"`
	PodUID        string                       `json:"pod_uid,omitempty"`
	OperationID   string                       `json:"operation_id,omitempty"`
	Assets        *runtimev1.RuntimeAssets     `json:"assets"`
	Network       *runtimev1.NetworkAttachment `json:"network"`
}

var _ runtimeservice.Adapter = (*adapter)(nil)

// NewNodeAdapter builds the production Linux RuntimeResource adapter used by
// Cubelet and by privileged end-to-end validation. The returned interface keeps
// the implementation details private while allowing a standalone service to
// exercise the exact asset, network, TAP, and cleanup path.
func NewNodeAdapter(stateDir string, assets Assets) (runtimeservice.Adapter, error) {
	network, err := newNodeNetwork()
	if err != nil {
		return nil, err
	}
	return newAdapter(stateDir, assets, network)
}

func newAdapter(stateDir string, assets Assets, network NetworkOps) (*adapter, error) {
	if stateDir == "" || network == nil {
		return nil, errors.New("runtime resource adapter state/network is empty")
	}
	for name, path := range map[string]string{"kernel": assets.KernelPath, "agent": assets.AgentPath, "guest image": assets.GuestImagePath} {
		if path == "" {
			return nil, fmt.Errorf("runtime resource %s path is empty", name)
		}
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("runtime resource %s %q: %w", name, path, err)
		}
	}
	if assets.SharedRootBase == "" {
		return nil, errors.New("runtime resource shared root is empty")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(assets.SharedRootBase, 0o711); err != nil {
		return nil, err
	}
	sharedRootBase, err := filepath.EvalSymlinks(assets.SharedRootBase)
	if err != nil {
		return nil, fmt.Errorf("resolve runtime resource shared root %q: %w", assets.SharedRootBase, err)
	}
	if !filepath.IsAbs(sharedRootBase) {
		return nil, fmt.Errorf("runtime resource shared root must resolve absolute: %q", sharedRootBase)
	}
	assets.SharedRootBase = filepath.Clean(sharedRootBase)
	return &adapter{
		operations: kmutex.New(), stateDir: stateDir, assets: assets, network: network, tapFiles: make(map[string]*os.File),
		closeTap: func(file *os.File) error { return file.Close() }, cleanup: defaultSharedRootCleanupOps(),
	}, nil
}

func (a *adapter) Prepare(ctx context.Context, request *runtimev1.PrepareSandboxRequest, lease state.Lease) (prepared *runtimev1.PreparedSandbox, err error) {
	totalStart := time.Now()
	lockStart := totalStart
	ctx = withStartupTraceIdentity(ctx, request)
	trace := monotime.TraceBufferFromContext(ctx)
	if err := a.operations.Lock(ctx, request.GetSandboxId()); err != nil {
		return nil, err
	}
	defer a.operations.Unlock(request.GetSandboxId())
	lockWait := time.Since(lockStart)
	defer func() {
		if !trace.Enabled() {
			return
		}
		trace.Addf(
			"cube_perf component=cubelet operation=create phase=adapter-prepare sandbox_id=%s pod_uid=%s operation_id=%s generation=%d ts_mono_us=%d duration_us=%d success=%t lock_wait_us=%d",
			request.GetSandboxId(), request.GetPod().GetUid(), request.GetSandboxId(), request.GetGeneration(), monotime.Micros(), time.Since(totalStart).Microseconds(),
			err == nil, lockWait.Microseconds(),
		)
	}()

	if record, err := a.load(request.GetSandboxId()); err == nil {
		if record.Generation != request.GetGeneration() || record.LeaseID != lease.LeaseID {
			return nil, errors.New("sandbox already has a different runtime resource lease")
		}
		return a.resumePrepare(ctx, record)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	tapName := nameFor("cb", request.GetSandboxId(), request.GetGeneration())
	sharedRoot := filepath.Join(a.assets.SharedRootBase, nameFor("sb-", request.GetSandboxId(), request.GetGeneration()))
	handle := nameFor("net-", request.GetSandboxId()+lease.LeaseID, request.GetGeneration())
	record := &diskRecord{
		Stage: stageIntent, SandboxID: request.GetSandboxId(), Generation: request.GetGeneration(), LeaseID: lease.LeaseID,
		NetworkHandle: handle, NetNSPath: request.GetNetwork().GetNetnsPath(), InterfaceName: request.GetNetwork().GetInterfaceName(), TapName: tapName,
		PodUID: request.GetPod().GetUid(), OperationID: request.GetSandboxId(),
		Assets:  &runtimev1.RuntimeAssets{KernelPath: a.assets.KernelPath, AgentPath: a.assets.AgentPath, GuestImagePath: a.assets.GuestImagePath, SharedRoot: sharedRoot},
		Network: &runtimev1.NetworkAttachment{NetworkHandle: handle, TapName: tapName, GuestInterfaceName: "eth0"},
	}
	if err := a.persistStage(record, stageIntent, trace); err != nil {
		return nil, err
	}
	return a.resumePrepare(ctx, record)
}

func (a *adapter) resumePrepare(ctx context.Context, record *diskRecord) (prepared *runtimev1.PreparedSandbox, err error) {
	totalStart := time.Now()
	stageStart := totalStart
	initialStage := record.Stage
	var validateRoot, persistShared, networkPrepare, persistPrepared time.Duration
	trace := monotime.TraceBufferFromContext(ctx)
	defer func() {
		if !trace.Enabled() {
			return
		}
		trace.Addf(
			"cube_perf component=cubelet operation=create phase=adapter-resume sandbox_id=%s pod_uid=%s operation_id=%s generation=%d initial_stage=%s final_stage=%s ts_mono_us=%d duration_us=%d success=%t validate_root_us=%d persist_shared_us=%d network_us=%d persist_prepared_us=%d",
			record.SandboxID, record.PodUID, record.OperationID, record.Generation, initialStage, record.Stage, monotime.Micros(),
			time.Since(totalStart).Microseconds(), err == nil, validateRoot.Microseconds(), persistShared.Microseconds(),
			networkPrepare.Microseconds(), persistPrepared.Microseconds(),
		)
	}()
	switch record.Stage {
	case stageIntent:
		root := record.Assets.GetSharedRoot()
		if err := os.Mkdir(root, 0o711); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, a.discardIntent(record, fmt.Errorf("create runtime resource shared root %q: %w", root, err))
		}
		validated, err := a.validateSharedRoot(root)
		if err != nil {
			return nil, a.discardIntent(record, err)
		}
		record.Assets.SharedRoot = validated
		validateRoot += time.Since(stageStart)
		// The durable INTENT already contains the exact shared-root and network
		// targets. If the process exits after mkdir, replaying INTENT observes
		// and validates the same directory before idempotently preparing the
		// network. Keep accepting the historical SHARED_ROOT stage below, but
		// do not add an otherwise redundant file+directory fsync to new Pods.
		fallthrough
	case stageSharedRoot:
		stageStart = time.Now()
		validated, err := a.validateSharedRoot(record.Assets.GetSharedRoot())
		if err != nil {
			return nil, err
		}
		record.Assets.SharedRoot = validated
		validateRoot += time.Since(stageStart)
		stageStart = time.Now()
		network, err := a.network.Prepare(ctx, record.NetNSPath, record.InterfaceName, record.TapName)
		if err != nil {
			if rollbackErr := a.rollbackPreparing(ctx, record); rollbackErr != nil {
				return nil, fmt.Errorf("prepare network: %v; rollback: %v", err, rollbackErr)
			}
			return nil, err
		}
		networkPrepare += time.Since(stageStart)
		if network == nil {
			err := errors.New("network adapter returned no attachment")
			if rollbackErr := a.rollbackPreparing(ctx, record); rollbackErr != nil {
				return nil, fmt.Errorf("%v; rollback: %v", err, rollbackErr)
			}
			return nil, err
		}
		network.NetworkHandle = record.NetworkHandle
		network.TapName = record.TapName
		if network.GuestInterfaceName == "" {
			network.GuestInterfaceName = "eth0"
		}
		record.Network = network
		stageStart = time.Now()
		if err := a.persistStage(record, stagePrepared, trace); err != nil {
			return nil, err
		}
		persistPrepared += time.Since(stageStart)
	case stagePrepared:
		stageStart = time.Now()
		validated, err := a.validateSharedRoot(record.Assets.GetSharedRoot())
		if err != nil {
			return nil, err
		}
		record.Assets.SharedRoot = validated
		validateRoot += time.Since(stageStart)
	default:
		return nil, fmt.Errorf("unsupported runtime resource prepare stage %q", record.Stage)
	}
	prepared = preparedFromRecord(record)
	return prepared, nil
}

func (a *adapter) discardIntent(record *diskRecord, cause error) error {
	if err := os.Remove(a.path(record.SandboxID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%v; discard runtime resource intent: %w", cause, err)
	}
	if err := syncDir(a.stateDir); err != nil {
		return fmt.Errorf("%v; sync discarded runtime resource intent: %w", cause, err)
	}
	return cause
}

func (a *adapter) validateSharedRoot(root string) (string, error) {
	root = filepath.Clean(root)
	if filepath.Dir(root) != a.assets.SharedRootBase || root == a.assets.SharedRootBase {
		return "", fmt.Errorf("runtime resource shared root %q is not a direct child of %q", root, a.assets.SharedRootBase)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("stat runtime resource shared root %q: %w", root, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("runtime resource shared root %q is not a real directory", root)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve runtime resource shared root %q: %w", root, err)
	}
	canonical = filepath.Clean(canonical)
	if canonical != root || filepath.Dir(canonical) != a.assets.SharedRootBase {
		return "", fmt.Errorf("runtime resource shared root %q escaped canonical base %q", root, a.assets.SharedRootBase)
	}
	return canonical, nil
}

func (a *adapter) rollbackPreparing(ctx context.Context, record *diskRecord) error {
	if file := a.getTap(record.SandboxID); file != nil {
		if err := a.closeTapFile(file); err != nil {
			return err
		}
		a.removeTap(record.SandboxID, file)
	}
	if err := a.cleanupSharedRoot(record.Assets.GetSharedRoot()); err != nil {
		return err
	}
	if err := a.network.Release(ctx, record.NetNSPath, record.InterfaceName, record.TapName); err != nil {
		return err
	}
	if err := os.Remove(a.path(record.SandboxID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(a.stateDir)
}

func (a *adapter) persistStage(record *diskRecord, stage prepareStage, trace *monotime.TraceBuffer) error {
	record.Stage = stage
	if a.persistHook != nil {
		if err := a.persistHook(stage, record); err != nil {
			return err
		}
	}
	return a.persist(record, trace)
}

func (a *adapter) Release(ctx context.Context, request state.ReleaseRequest, networkHandle string) error {
	if err := a.operations.Lock(ctx, request.SandboxID); err != nil {
		return err
	}
	defer a.operations.Unlock(request.SandboxID)
	record, err := a.load(request.SandboxID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if record.Generation != request.Generation || record.LeaseID != request.LeaseID {
		return errors.New("release does not match runtime resource record")
	}
	if networkHandle != "" && record.NetworkHandle != networkHandle {
		return errors.New("release network handle does not match runtime resource record")
	}
	if file := a.getTap(record.SandboxID); file != nil {
		if err := a.closeTapFile(file); err != nil {
			return err
		}
		a.removeTap(record.SandboxID, file)
	}
	if record.Assets != nil {
		if err := a.cleanupSharedRoot(record.Assets.GetSharedRoot()); err != nil {
			return err
		}
	}
	if err := a.network.Release(ctx, record.NetNSPath, record.InterfaceName, record.TapName); err != nil {
		return err
	}
	if err := os.Remove(a.path(request.SandboxID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(a.stateDir)
}

func defaultSharedRootCleanupOps() sharedRootCleanupOps {
	return sharedRootCleanupOps{
		mountTargets: mountedTargetsUnder,
		unmount:      unix.Unmount,
		removeAll:    os.RemoveAll,
	}
}

func (a *adapter) cleanupSharedRoot(root string) error {
	if root == "" {
		return nil
	}
	root = filepath.Clean(root)
	if filepath.Dir(root) != a.assets.SharedRootBase || root == a.assets.SharedRootBase {
		return fmt.Errorf("runtime resource shared root %q is not a direct child of %q", root, a.assets.SharedRootBase)
	}
	_, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		// A previous exact-lease Release may have removed the filesystem tree and
		// then failed while releasing the network. Continue the staged retry.
		return nil
	}
	if err == nil {
		if _, err := a.validateSharedRoot(root); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("stat runtime resource shared root %q: %w", root, err)
	}
	ops := a.cleanup
	defaults := defaultSharedRootCleanupOps()
	if ops.mountTargets == nil {
		ops.mountTargets = defaults.mountTargets
	}
	if ops.unmount == nil {
		ops.unmount = defaults.unmount
	}
	if ops.removeAll == nil {
		ops.removeAll = defaults.removeAll
	}
	targets, err := ops.mountTargets(root)
	if err != nil {
		return fmt.Errorf("list mounts under runtime resource shared root %q: %w", root, err)
	}
	for _, target := range deepestMountTargets(targets) {
		if err := ops.unmount(target, 0); err == nil || ignorableUnmountError(err) {
			continue
		}
		if err := ops.unmount(target, unix.MNT_DETACH); err != nil && !ignorableUnmountError(err) {
			return fmt.Errorf("detach mount %q below runtime resource shared root: %w", target, err)
		}
	}
	remaining, err := ops.mountTargets(root)
	if err != nil {
		return fmt.Errorf("verify mounts under runtime resource shared root %q: %w", root, err)
	}
	if len(remaining) != 0 {
		return fmt.Errorf("refuse to remove runtime resource shared root %q with %d active mounts", root, len(remaining))
	}
	if err := ops.removeAll(root); err != nil {
		return fmt.Errorf("remove runtime resource shared root %q: %w", root, err)
	}
	return nil
}

func mountedTargetsUnder(root string) ([]string, error) {
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		return nil, err
	}
	targets := make([]string, 0)
	for _, mount := range mounts {
		if pathWithin(root, mount.Mountpoint) {
			targets = append(targets, filepath.Clean(mount.Mountpoint))
		}
	}
	return deepestMountTargets(targets), nil
}

func pathWithin(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	relative, err := filepath.Rel(root, target)
	return err == nil && !filepath.IsAbs(relative) && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func deepestMountTargets(targets []string) []string {
	unique := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target != "" {
			unique[filepath.Clean(target)] = struct{}{}
		}
	}
	targets = targets[:0]
	for target := range unique {
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool {
		leftDepth := strings.Count(targets[i], string(os.PathSeparator))
		rightDepth := strings.Count(targets[j], string(os.PathSeparator))
		if leftDepth == rightDepth {
			return targets[i] > targets[j]
		}
		return leftDepth > rightDepth
	})
	return targets
}

func ignorableUnmountError(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT)
}

func (a *adapter) Inspect(ctx context.Context, sandboxID string, lease state.Lease) (*runtimev1.PreparedSandbox, error) {
	if err := a.operations.Lock(ctx, sandboxID); err != nil {
		return nil, err
	}
	defer a.operations.Unlock(sandboxID)
	record, err := a.load(sandboxID)
	if err != nil {
		return nil, err
	}
	if record.Generation != lease.Generation || record.LeaseID != lease.LeaseID {
		return nil, errors.New("runtime resource record does not match durable lease")
	}
	validated, err := a.validateSharedRoot(record.Assets.GetSharedRoot())
	if err != nil {
		return nil, err
	}
	record.Assets.SharedRoot = validated
	return preparedFromRecord(record), nil
}

func (a *adapter) OpenTap(binding handoff.Binding) (descriptorFile *os.File, err error) {
	totalStart := time.Now()
	stageStart := totalStart
	var lockWait, loadTime, openTime, duplicateTime time.Duration
	trace := monotime.NewTraceBuffer()
	defer trace.Flush()
	if err := a.operations.Lock(context.Background(), binding.SandboxID); err != nil {
		return nil, err
	}
	defer a.operations.Unlock(binding.SandboxID)
	lockWait = time.Since(stageStart)
	stageStart = time.Now()
	defer func() {
		if !trace.Enabled() {
			return
		}
		trace.Addf(
			"cube_perf component=cubelet operation=start phase=adapter-open-tap sandbox_id=%s operation_id=%s generation=%d ts_mono_us=%d duration_us=%d success=%t lock_wait_us=%d load_us=%d open_us=%d duplicate_us=%d",
			binding.SandboxID, binding.SandboxID, binding.Generation, monotime.Micros(), time.Since(totalStart).Microseconds(), err == nil,
			lockWait.Microseconds(), loadTime.Microseconds(), openTime.Microseconds(), duplicateTime.Microseconds(),
		)
	}()
	record, err := a.load(binding.SandboxID)
	if err != nil {
		return nil, err
	}
	if record.Stage != stagePrepared || record.Generation != binding.Generation || record.LeaseID != binding.LeaseID || record.NetworkHandle != binding.NetworkHandle {
		return nil, handoff.ErrStaleLease
	}
	loadTime = time.Since(stageStart)
	stageStart = time.Now()
	file := a.getTap(binding.SandboxID)
	if file == nil {
		file, err = a.network.Open(record.NetNSPath, record.TapName)
		if err != nil {
			return nil, err
		}
		a.setTap(binding.SandboxID, file)
	}
	openTime = time.Since(stageStart)
	stageStart = time.Now()
	descriptor, err := duplicateTapFD(file.Fd())
	if err != nil {
		if a.removeTap(binding.SandboxID, file) {
			_ = a.closeTapFile(file)
		}
		return nil, err
	}
	duplicateTime = time.Since(stageStart)
	descriptorFile = os.NewFile(uintptr(descriptor), file.Name())
	return descriptorFile, nil
}

var duplicateTapFD = func(fd uintptr) (int, error) {
	return unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
}

func (a *adapter) closeTapFile(file *os.File) error {
	if a.closeTap != nil {
		return a.closeTap(file)
	}
	return file.Close()
}

// TAP descriptors are owned by a sandbox operation lock. tapMu protects only
// the Go map so unrelated sandboxes never hold it across netns work, open(2),
// close(2), or descriptor duplication.
func (a *adapter) getTap(sandboxID string) *os.File {
	a.tapMu.Lock()
	defer a.tapMu.Unlock()
	return a.tapFiles[sandboxID]
}

func (a *adapter) setTap(sandboxID string, file *os.File) {
	a.tapMu.Lock()
	defer a.tapMu.Unlock()
	a.tapFiles[sandboxID] = file
}

func (a *adapter) removeTap(sandboxID string, file *os.File) bool {
	a.tapMu.Lock()
	defer a.tapMu.Unlock()
	if a.tapFiles[sandboxID] != file {
		return false
	}
	delete(a.tapFiles, sandboxID)
	return true
}

func (a *adapter) load(sandboxID string) (*diskRecord, error) {
	data, err := os.ReadFile(a.path(sandboxID))
	if err != nil {
		return nil, err
	}
	record := new(diskRecord)
	if err := json.Unmarshal(data, record); err != nil {
		return nil, err
	}
	if record.SandboxID != sandboxID || record.Assets == nil || record.Network == nil {
		return nil, errors.New("invalid runtime resource adapter record")
	}
	if record.Stage == "" {
		// Records created before staged WAL support were persisted only after all side effects.
		record.Stage = stagePrepared
	}
	return record, nil
}

func (a *adapter) persist(record *diskRecord, trace *monotime.TraceBuffer) (err error) {
	totalStart := time.Now()
	stageStart := totalStart
	var encodeTime, createTime, writeTime, fileSyncTime, renameTime, parentSyncTime time.Duration
	defer func() {
		if !trace.Enabled() {
			return
		}
		trace.Addf(
			"cube_perf component=cubelet operation=persist phase=adapter-store sandbox_id=%s pod_uid=%s operation_id=%s record_stage=%s ts_mono_us=%d duration_us=%d success=%t encode_us=%d create_us=%d write_us=%d file_fsync_us=%d rename_us=%d parent_fsync_us=%d fsync_count=2",
			record.SandboxID, record.PodUID, record.OperationID, record.Stage, monotime.Micros(), time.Since(totalStart).Microseconds(), err == nil,
			encodeTime.Microseconds(), createTime.Microseconds(), writeTime.Microseconds(), fileSyncTime.Microseconds(),
			renameTime.Microseconds(), parentSyncTime.Microseconds(),
		)
	}()
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	encodeTime = time.Since(stageStart)
	stageStart = time.Now()
	temp, err := os.CreateTemp(a.stateDir, ".runtime-resource-*")
	if err != nil {
		return err
	}
	createTime = time.Since(stageStart)
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	stageStart = time.Now()
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	writeTime = time.Since(stageStart)
	stageStart = time.Now()
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	fileSyncTime = time.Since(stageStart)
	if err := temp.Close(); err != nil {
		return err
	}
	stageStart = time.Now()
	if err := os.Rename(name, a.path(record.SandboxID)); err != nil {
		return err
	}
	renameTime = time.Since(stageStart)
	stageStart = time.Now()
	err = syncDir(a.stateDir)
	parentSyncTime = time.Since(stageStart)
	return err
}

func (a *adapter) path(sandboxID string) string {
	sum := sha256.Sum256([]byte(sandboxID))
	return filepath.Join(a.stateDir, hex.EncodeToString(sum[:])+".json")
}

func preparedFromRecord(record *diskRecord) *runtimev1.PreparedSandbox {
	return &runtimev1.PreparedSandbox{SandboxId: record.SandboxID, LeaseId: record.LeaseID, Generation: record.Generation, Assets: record.Assets, Network: record.Network}
}

func nameFor(prefix, identity string, generation uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", identity, generation)))
	return prefix + hex.EncodeToString(sum[:])[:11]
}

func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
