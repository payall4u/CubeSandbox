# CubeSandbox Kubernetes RuntimeClass PoC 开发计划

> 状态：执行中（S3.4 资源控制）
> 日期：2026-08-30  
> 总体设计：[CubeSandbox 对接 Kubernetes RuntimeClass 总体技术方案](./kubernetes-runtime-integration)  
> 活动交接：[Kubernetes RuntimeClass PoC Handoff](../../../docs/handoffs/kubernetes-runtime/README.md)

## 1. 开发目标

在不修改 Kubernetes/containerd 上游、不替换 CubeSandbox 现有产品链路的前提下，把现有 CubeShim 演进为可由 `RuntimeClass` 选择的 Pod VM runtime。PoC 最终需要证明：

- 一个 Pod 对应一个 Cube VM，init、app、sidecar 和 ephemeral container 可在 VM 内动态运行。
- 宿主机 containerd 负责标准 OCI image、snapshotter 和 CNI；CubeShim 消费标准 Sandbox/Task 输入。
- runc 与 Cube runtime 共存，现有 CubeMaster/CubeboxMgr 链路不回归。
- 网络、基础 PVC、常用安全字段、恢复、监控和升级路径能够被重复验证。
- Snapshot/Pause/Resume 的接口方向被记录，但实现放在二期。

## 2. 面向社区的实现原则

### 2.1 沿用现有组件边界

- **CubeShim** 是 containerd 适配层：承接 Sandbox/Task API，转换 OCI spec、rootfs、volume、stdio 和事件；不实现 Kubernetes controller。
- **Cubelet** 是节点资源层：准备/释放 KVM、Guest assets 和网络 attachment，并负责残留资源对账；不实现另一套 CRI。
- **cube-vmm-worker** 是 CubeShim 拉起的每 Pod VMM 数据面进程：只承载 VMM、vCPU、Guest memory、virtiofs 和设备，不理解 Kubernetes/containerd，也不直接调用 Cubelet。
- **Guest Agent** 是 VM 内容器执行层：管理 namespace、mount、cgroup 和进程；不理解 Pod、Deployment、RuntimeClass 等 Kubernetes API。
- **containerd/kubelet** 保持标准职责：镜像、snapshotter、CNI 和 Pod 状态机不复制到 CubeSandbox。
- **CubeMaster legacy 链路**继续可用，Kubernetes 功能通过独立入口和 feature gate 增量加入。

这能把 Kubernetes 特例限制在边缘适配层，核心 VM/容器能力仍可被其他 CubeSandbox 场景复用。

### 2.2 使用稳定契约而不是跨组件耦合

- 优先使用 containerd Sandbox API、Task API、OCI Runtime Spec 和 CNI 结果，不 fork 上游协议。
- CubeShim ↔ Cubelet、CubeShim ↔ Agent 的新增 RPC 必须版本化，并提供 `GetCapabilities`/feature negotiation。
- cube-vmm-worker 只接受 CubeShim 的版本化本地 IPC；CubeShim 从 Cubelet 获取节点资源，再通过继承 FD 或 `SCM_RIGHTS` 交付 worker，不建立 worker ↔ Cubelet 控制连接。
- 新 protobuf 字段保持 optional/backward-compatible；先让接收方识别，再让调用方启用。
- 不支持的字段明确报错，不静默丢弃安全或生命周期语义。
- 实验能力默认关闭，通过配置或 RuntimeClass handler 打开；失败时可以退回 runc 或 legacy Cube 链路。

### 2.3 按组件拆 PR

一个 stage 可以由多个 PR 完成，但一个 PR 尽量只改一个组件：

1. 接口/文档 PR：协议、状态机、错误语义和测试计划。
2. Agent PR：Guest 侧能力，默认不被旧 Shim 调用。
3. CubeShim PR：Sandbox/Task 适配，通过 capability negotiation 启用。
4. Cubelet PR：节点本地资源服务和网络 adapter。
5. deploy/test PR：RuntimeClass、containerd 配置、安装器和 E2E。

重构与行为改动分开；不要在 Kubernetes PR 中顺便改 runtime type、重命名现有模块或替换旧存储格式。跨组件必须一起验证时使用 stacked PR，但每个 PR仍应可构建并说明依赖关系。

## 3. 建议代码组织

尽量在现有目录中扩展，避免建立一套平行实现：

```text
CubeShim/shim/src/
├── bin/
│   └── cube-vmm-worker.rs     # 每 Pod VMM worker 入口，不包含 CRI/RuntimeResource client
├── worker/                    # Shim↔worker 版本化 IPC、启动 gate、重连与进程身份
├── service/
│   ├── srv.rs                 # Shim 进程入口
│   ├── sandbox_srv.rs         # 新增：containerd Sandbox Service adapter
│   └── task_srv.rs            # 现有 Task Service，改为多 Task/sandbox
├── sandbox/                   # Pod VM 状态机、VM 生命周期、网络 attachment
├── container/                 # 单容器生命周期、rootfs、exec、stdio
└── recovery/                  # S4 再增加：状态持久化和 reconcile

Cubelet/
├── api/services/runtime/      # 版本化 Runtime Resource RPC 定义
├── services/runtime/          # 直接 gRPC 注册、持久化 lease 状态机、FD handoff
└── plugins/cube/runtime/      # 通过显式接口注入的 KVM/网络/资产 adapter

agent/
├── protoc/protos/agent.proto  # 兼容扩展动态容器/namespace/mount RPC
└── cube/src/                  # Guest rootfs、namespace、cgroup 和进程实现

deploy/kubernetes/runtimeclass/
├── runtimeclass.yaml
├── containerd-config.toml
└── README.md

tests/e2e/kubernetes-runtime/
├── manifests/
├── lifecycle/
├── network/
├── storage/
├── security/
└── recovery/
```

目录名称在第一个接口 PR 中由维护者最终确认。必须保持的边界是：Kubernetes API 不进入 Agent/hypervisor；containerd/CNI 适配不进入 Guest；CubeMaster 不成为 Pod 创建的同步依赖。

## 4. Stage 总览

| Stage | 目标 | 主要产物 | 进入下一 Stage 的条件 |
|---|---|---|---|
| S0 | 消除四个架构风险 | 技术探针、调用 trace、接口草案 | Sandbox API、rootfs/virtiofs、CNI 和组件边界均有可行证据 |
| S1 | 单容器纵向链路 | RuntimeClass + 单容器 Cube Pod | 创建、运行、日志、exec、停止、删除可重复通过 |
| S2 | 完整多容器生命周期 | init/app/sidecar/ephemeral + namespace | 多容器顺序、重启、探针和退出状态正确 |
| S3 | 存储、安全和资源 | volume/PVC、安全字段、双层 cgroup | 支持矩阵主路径通过，不支持项明确拒绝 |
| S4 | 恢复和可观测性 | 重连、reconcile、stats、metrics | 组件故障注入后无错误状态和持久泄漏 |
| S5 | 可部署 PoC 验收 | 安装升级、VMM worker、普通冷启动性能、兼容性、Node E2E | 普通冷启动达到 S5.5 门禁，PoC 验收报告和已知限制完整 |
| S6 | 快照启动与最终快路径 | Runtime template、Snapshot/Restore API、Pause/Resume | 从快照创建新 Pod、一秒启动和一致性验证通过 |

### 4.1 执行状态规则

本文档同时是 Stage 进度的唯一权威来源；handoff 只引用当前 `Sx.x`，不复制整张进度表。

| 状态 | 含义 |
|---|---|
| `NOT_STARTED` | 尚未开始 |
| `IN_PROGRESS` | 正在实现，尚未进入完整验收 |
| `VALIDATING` | 实现已具备，正在执行该 Work Stage 的验收标准 |
| `DONE` | 全部验收标准通过，并已填写可复现证据 |
| `BLOCKED` | 存在阻塞，必须在“下一步”中写解除条件 |
| `DEFERRED` | 不阻塞当前 Milestone，已明确新的目标 Stage |

`Sx` 的状态由必需的 `Sx.x` 聚合：只有全部为 `DONE` 才能标记 Milestone 完成。代码合入但尚未通过验收时只能是 `VALIDATING`。

### 4.2 当前准备状态

| 项目 | 状态 | 已完成 | 证据 | 下一步 |
|---|---|---|---|---|
| 方案与开发准备 | `DONE` | 总体设计、S0～S6 开发计划、轻量 handoff 和未决问题表 | `95b3164a`、`3b564b76`；VitePress 构建通过 | 从 S0.1 开始技术探针 |

## 5. S0：架构技术探针
> Milestone 状态：`DONE`。S0.1～S0.4 均已通过独立审查。

| Work Stage | 状态 | Owner | 已完成 | 验收证据 | 下一步 |
|---|---|---|---|---|---|
| S0.1 Sandbox API | `DONE` | Codex | 双服务探针、独立配置、固定 CRI 输入和一键验收脚本已提交；真实正常链路及四类明确异常通过，10 类残留均为 0 | 实现 `f38622c2`、`6a53a52d`、`33dbf479`；TAT `inv-68246d0jt1`；[原始证据](../../handoffs/kubernetes-runtime/evidence/s0.1/README.md)；subagent `APPROVE` | S0.2 RootFS/virtiofs |
| S0.2 RootFS/virtiofs | `DONE` | Codex | 标准 OCI active snapshot 已在真实 Cube Guest 运行；动态 bind/rename/只读与卸载约束已验证；20 次创建删除无残留 | 实现 `c014d3c6`；TAT `inv-9827ikgt4f`；[原始证据](../../handoffs/kubernetes-runtime/evidence/s0.2/README.md)；subagent `APPROVE` | S0.3 CNI 网络 |
| S0.3 CNI 网络 | `DONE` | Codex | Cilium tcfilter/TAP 跨 netns FD 已接入；Pod IP/MAC/MTU、DNS、Service、跨节点和 NetworkPolicy 通过，成功/失败资源残留均为 0 | 实现 `e16411fd`、`80bacacb`、`168cd061`；完整验收 `inv-a82g9g0x1f`；[原始证据](../../handoffs/kubernetes-runtime/evidence/s0.3/README.md)；subagent `APPROVE` | S0.4 组件接口 |
| S0.4 组件接口 | `DONE` | Codex | RuntimeResource v1、持久化 lease 状态机、带 generation/lease/token 栅栏的 FD handoff、直接 gRPC 注册、Agent capability negotiation 已实现；四轮问题均已整改 | 实现 `40f4389a`、`30bf3365`、`eb7aed1a`、`2e2612a4`、整改 `ea192ecb`、`e3205220`、`aace4c4a`、`695fbada`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s0.4/README.md)；第五轮 subagent `APPROVE` | S1.1 Sandbox VM 生命周期 |

### S0.1 云上开发基线（2026-08-30）

| 项目 | 结果 |
|---|---|
| 节点 | 腾讯云香港二区 `ins-pl7mznaa`，`SA5.4XLARGE32`（16C32G），镜像 `img-qansmwme`，Ubuntu 24.04；带 `billing=blakezyli` 标签 |
| PVM/KVM | 内核 `6.12.33+`，`kvm_pvm` 已加载，`/dev/kvm` 可用；`KVM_GET_API_VERSION=12`、`KVM_CREATE_VM=ok` |
| containerd | 官方校验后的 `v2.3.4`，systemd 使用 `/usr/local/bin/containerd`；CRI images/runtime 插件均为 `ok`；Docker 29.2.1 正常接入同一 containerd |
| 存储 | 新 200GB 数据盘 `/dev/vdb` 以 XFS 挂载到 `/data/cubelet`，`reflink=1`，写入 `/etc/fstab` |
| 源码与构建 | 云节点从公开 `master` 检出精确基线 `09274501dd12e47dbed2dcc77d8eb67dd661d49c`；`make shim` 生成 `containerd-shim-cube-rs` 和 `cube-runtime` |
| 测试 | `make shim-test`：shim 61 个、cube-runtime 1 个测试通过，0 失败；构建 TAT `inv-38221eg40s`，测试 TAT `inv-6822eegkw4`，汇总 TAT `inv-3822g20r7i` |
| 网络/访问 | 复用账号内现有 `cubesandbox-cluster-subnet` 和共享安全组 `sg-k3absy6z`（均非本 PoC 创建）。TAT Agent 在线；公网 SSH 转发返回 `502 Server UnReachable`，当前以 TAT 执行命令，不阻塞自动化验证 |
| 集群 | S0.1 当时尚未创建专属 TKE；2026-09-02 已额外创建 `cls-1oqe2py4` / `cubesandbox-k8s-poc-extra-2n（勿删）`，Kubernetes 1.36.2、两个 8C16G 节点、containerd 2.2.5-tke.1，作为默认 runtime 多节点交互基线 |

上述基线当时只证明云上开发环境、KVM API 和现有 CubeShim 可构建/可测试；后续 Sandbox API trace 与清理结论见下一节。完整 Cube Guest 和 virtiofs 仍由 S0.2 验证。

### S0.1 Sandbox API 探针结果（2026-08-30）

探针位于 `CubeShim/sandbox-probe`，必须单独构建，不进入默认产物。它采用 containerd
2.3.4 的 bootstrap v3，在一个 ttrpc endpoint 同时注册 Sandbox Service 与官方
runc Task v3 Service。此处复用 runc 只用于隔离验证 containerd 契约；S1.1 必须把
这些契约移植到 Rust CubeShim，并替换为 Cube-backed Task，之后删除 Go 探针。

| 项目 | 结果 |
|---|---|
| 配置 | 独立 root/state/socket，不替换节点主 containerd；handler `cube-s0` 使用 `runtime_type = "io.containerd.cube-s0.v1"`、绝对 `runtime_path` 和 `sandboxer = "shim"` |
| 正常链路 | CNI ADD → bootstrap v3 → Sandbox Create/Start/Wait → Sandbox Status/Platform → Task v3 Create/Start/Wait/Kill/Delete → Sandbox Stop → CNI DEL → Sandbox Shutdown → shim delete |
| CRI 结果 | `SANDBOX_READY`，Pod IP `10.88.0.11`；BusyBox 标准 OCI snapshot 进程输出 `cube-s0-task-ok` 并准确返回 exit code 23 |
| 正常清理 | 删除后 CRI Pod/Container、mount、shim 进程/socket、sandbox metadata、state/root bundle、netns、host-local IP 分配 10 项均为 0 |
| 异常清理 | `CreateSandbox` 失败、`StartSandbox` 失败、Create 中 shim exit(86)、延迟 Create 后客户端取消均回到上述 10 项 0；每例均确认 failpoint 命中和 CNI ADD/DEL 成功 |
| 本地验证 | `go test -race ./...`、`go vet ./...`、`git diff --check` 通过 |
| 云端证据 | 仓库脚本完整重放 `inv-68246d0jt1`；原始 JSONL、失败输出和摘要位于 `docs/handoffs/kubernetes-runtime/evidence/s0.1/` |

实测确认以下非显然契约：

- Sandbox bundle 没有 pause 容器 `config.json`，不能直接复用 runc shim manager 的
  spec/grouping 启动逻辑；
- bootstrap 必须返回 `version=3, protocol=ttrpc`，Task 才会复用 Sandbox endpoint；
- `SandboxStatusResponse.state` 必须使用 CRI 枚举字符串
  `SANDBOX_READY/SANDBOX_NOTREADY`，自由文本 `ready/running` 会被映射为 NotReady；
- CNI ADD 在 Sandbox Create 前完成；Stop 时先清 Task 和 Sandbox，再执行 CNI DEL；
  Remove 阶段可能以空 netns 再调用一次 CNI DEL，因此 CNI DEL 必须幂等；
- Create/Start 失败由 shim controller 调用 Shutdown 并删除 shim/bundle；shim 已崩溃时
  Shutdown 可能失败，但 containerd 仍执行 shim delete；客户端取消由 CRI 回滚 CNI，
  最终同样不能残留 metadata、mount、socket 或进程。
- 首轮 crash 探针暴露出 delete helper 未删除死 shim socket；提交 `6a53a52d` 改为从
  `bootstrap.json` 读取精确地址并传播清理错误。新矩阵开始前只删除两个已验证不可连接
  的旧 socket，之后 normal、fail-create、fail-start、crash-create、cancel-create 每例
  均断言 socket=0。

S0.1 尚未证明 Cube Guest、virtiofs 或 Cube-backed Task；这些属于 S0.2，不能用本
探针中的 runc 成功结果代替。

### S0.2 RootFS/virtiofs 探针结果（2026-08-30）

探针位于 `CubeShim/s0-rootfs-probe`，由
`io.containerd.cube.s0.standard-rootfs=true` 显式开启。当前 Agent 仍消费 legacy
`cube.rootfs.info`，因此 CubeShim 在内部把标准 `CreateTaskRequest.rootfs` 转成该
注解；上游 containerd/CRI 不需要生成 Cube 私有 rootfs 输入。S1 把转换并入 Sandbox
生命周期后应删除或演进此 S0 开关。

| 项目 | 结果 |
|---|---|
| 云上环境 | 香港二区 `ins-pl7mznaa`；官方匹配 PVM Host/Guest 6.6.69；containerd 2.3.4；XFS `/data/cubelet` |
| 标准 rootfs | BusyBox 1.36.1 的 overlayfs active snapshot 经标准 Task rootfs 进入 Guest，输出 `STANDARD_OCI_ROOTFS_OK`，准确返回 exit code 23 |
| 转换方式 | 不导出 Host merged overlay；按 containerd 顺序 bind active upper + image lowers，Guest Agent 在其上建立临时 writable overlay |
| virtiofs 参数 | `cache=never`、`read_only=true`、`announce_submounts=false`；开启 submount 通告的负向对照在 Guest overlay 返回 `EINVAL` |
| 在线变化 | VM 启动后新增 bind、Host rename、切只读均由 Guest console 确认；写只读 bind 返回 `Read-only file system` |
| 在线卸载约束 | Guest lookup 后普通 Host unmount 返回 `EBUSY`；`MNT_DETACH` 使 Host mount 立即归零，旧 inode 可能保留到 Task/VM 删除。后续 volume detach 必须 Guest-first、generation 路径不复用 |
| 清理 | 动态用例和 20/20 创建删除完成后，mount、share、Task、Container、Shim 每项均为 0 |
| 测试/构建 | `make shim-test`：CubeShim 68 个、cube-runtime 1 个测试通过；release 构建通过，TAT `inv-9827fk0njh` |
| 最终验收 | 仓库脚本直接重放成功，TAT `inv-9827ikgt4f`；环境证据 TAT `inv-0827k8gnsw` |

由负向对照确认两个非显然边界：

- Host merged overlay 不能直接作为 Guest overlay lower，否则形成
  overlay-on-virtiofs-on-overlay 并返回 `EINVAL`；
- layer bind 必须关闭 `announce_submounts`，否则 Guest 把 lower 识别为 FUSE
  submount，同样返回 `EINVAL`。

Guest writable upper 当前不回写 containerd active upper。S0/S1 的运行、退出码与删除
语义已成立；持久化 writable layer、容器重启对账和 snapshotter 协同留到 S3。


### S0.3 CNI 网络探针结果（2026-08-31）

探针位于 `CubeShim/s0-cni-probe`。S0 使用 anchor Pod 保存 CNI netns，在其中创建 TAP 和双向 tcfilter；CubeShim 从该 netns 打开 TAP 并把 FD 交给嵌入式 VMM。S1 必须把 netns/attachment 来源改为 Sandbox Service 与 Cubelet network adapter，并删除 anchor 与 S0 annotation。

| 项目 | 结果 |
|---|---|
| 云上环境 | 香港二区 3 节点 Kubernetes 1.36.4、containerd 2.3.4、Cilium 1.20.0；隔离验收节点为 `ins-4dyul5ag`，匹配 PVM Host/Guest 6.6.69 |
| Pod 网络身份 | Guest 使用 CNI 分配的 Pod IP、MAC、MTU、/32 路由和网关；MAC/MTU 从目标 netns 的 netlink 读取，避免误读宿主机 sysfs |
| 数据面 | TAP 与 Pod eth0 使用双向 tc ingress redirect；跨 netns TAP FD 显式禁用 name-based ioctl 与 offload |
| Kubernetes 网络 | 跨节点 PodIP、Cluster DNS、Service ClusterIP 和 Cilium egress NetworkPolicy 全部通过 |
| OCI/DNS | 沿用 S0.2 标准 OCI rootfs；Pod DNS 同时进入 sandbox，并通过现有 custom-file 机制注入容器 `/etc/resolv.conf` |
| 异常与清理 | 相对 netns 路径在创建前明确失败；成功/失败后 Task、Container、Shim、TAP、tc filter、rootfs mount/dir 均为 0，测试 namespace 已删除 |
| 构建/测试 | 云端 release 构建与 74 项测试通过，TAT `inv-982ekw0q2u`；本地 `make shim-test` 通过 CubeShim 74 项和 cube-runtime 1 项测试；binary SHA-256 `4414ee5da24871978b65a34a04a2999430169b91e0f18f1163b90e14d6d43a10` |
| 最终验收 | anchor 对照 `inv-b82g3a0mda`；无网络对照 `inv-b82fadg4xe`；Cube 完整 CNI `inv-a82g9g0x1f`；最终集群状态 `inv-682gcjgsnu`；[原始证据](../../handoffs/kubernetes-runtime/evidence/s0.3/README.md) |

诊断同时确认 Host 6.12/Guest 6.6 的 reset 失败与网络无关；匹配 Host/Guest 6.6.69 后无网络与完整 CNI 用例均成功。S0 只冻结 Cilium tcfilter 作为首选 PoC 路径，VPC-CNI/Global Router 留给后续 adapter 兼容验证。

### S0.4 组件接口结果（2026-08-31）

S0.4 将 Kubernetes 新链路分为三层：host containerd 维护 CRI、OCI image/snapshot、Sandbox/Task 与 CNI 状态；Cubelet `runtime.v1.RuntimeResource` 只做节点资源 Prepare/Release/Inspect/report-only Reconcile；Guest Agent 只做 VM 内容器执行。Cubelet 的新 service 不得调用内嵌 containerd 的 CRI、Task、Sandbox、Image 或 Snapshot 服务。

| 项目 | 结果 |
|---|---|
| CubeShim ↔ Cubelet | v1 方法集、持久化 generation/lease/tombstone 和精确 gRPC 结果已冻结；Kubernetes 专用 FD handoff 以 generation + lease + network handle + token 栅栏后通过 `SCM_RIGHTS` 交付 |
| CubeShim ↔ Agent | 兼容扩展 `Health.Version` field 3/4；Agent protocol 1 声明版本化能力；legacy protocol 0 仍兼容旧 Cubebox，S1 Kubernetes handler 必须显式校验 capability |
| 递归防线 | RuntimeResource 直接注册到 `grpc.ServiceRegistrar`；测试解析真实 `go list -deps`，禁止依赖 containerd 与 legacy Cubelet services |
| 测试 | 契约探针输出 `S0_4_INTERFACE_CONTRACT_OK`；CubeShim 76 项、cube-runtime 1 项、Agent 114 项通过 |
| 云端范围 | 本 PoC control 节点与 builder image 经 TAT 确认在线；平台在执行前拒绝本地分支归档上传，因此本纯编译契约未在云端重放且云端未被修改。S1 真实 VM 生命周期仍在云节点验收 |

详细调用图、兼容规则和演进约束见 [S0.4 接口边界](./kubernetes-runtime-integration-s0.4-interface.md)，原始摘要见 [S0.4 验收证据](../../handoffs/kubernetes-runtime/evidence/s0.4/README.md)。

### 目标

只回答“主架构是否可行”，避免在调用顺序、rootfs、virtiofs 或网络尚未验证时展开完整实现。

### 工作项

- **S0-1 Sandbox API**：在 containerd 2.3 基线上记录 `RunPodSandbox`、Sandbox Service、Task Service、CNI 和清理的真实调用顺序；验证 `sandboxer = "shim"` 的最小配置。
- **S0-2 RootFS/virtiofs**：让 containerd overlayfs active snapshot 通过标准 `CreateTaskRequest.rootfs` 在 Guest 中运行；验证 VM 启动后新增 bind、rename、只读 mount 和 unmount。
- **S0-3 网络**：用一个候选 CNI 把 Pod netns/IP 接入 VM，验证 Pod-to-Pod、DNS、Service 和最小 NetworkPolicy。
- **S0-4 接口边界**：冻结 CubeShim ↔ Cubelet 最小 RPC 与 CubeShim ↔ Agent capability negotiation 草案，确认不会递归调用 Cubelet 内置 containerd。

### 验收标准

- 一份可复现的 containerd 配置和调用 trace，能指出每个失败阶段由谁清理。
- 一个标准 OCI rootfs 在 Cube VM 内运行，退出码返回 containerd；创建/删除 20 次无残留 mount。
- VM 启动后新增的 rootfs bind 在 Guest 可见，删除后引用被释放。
- 一个 Pod IP 对应一个 VM，基础 DNS/Service/跨节点路径至少在所选 PoC CNI 上跑通。
- `K8S-OQ-001`～`K8S-OQ-004` 更新为 `DECIDED`，或有证据表明需要修改总体架构。
- 不要求生产代码质量；探针代码若合入必须 feature-gated，并附删除或演进说明。

## 6. S1：单容器纵向 PoC
> Milestone 状态：`DONE`。S1.1～S1.4 均已完成并通过同一 reviewer 门禁。

| Work Stage | 状态 | Owner | 已完成 | 验收证据 | 下一步 |
|---|---|---|---|---|---|
| S1.1 Sandbox VM 生命周期 | `DONE` | Codex | 生命周期、持久 lease、FD handoff、失败回滚、dead-shim recovery 和 durable fence 已实现；真实 Cilium TAP/PVM Cube VM 的 Create→Created Status→Platform→Start→Ready Status→Stop→Stopped Status→Wait→Shutdown、异常回滚及宿主零残留终验通过 | `47522929`～`22716267`；云端严格构建 `inv-b831vp0wan`；终验 `inv-38324c05ra`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s1.1/README.md)；最终 subagent `APPROVE` | S1.2 OCI Task |
| S1.2 OCI Task | `DONE` | Codex | 标准 OCI overlayfs rootfs 已进入真实 Guest；Task API v3、共享 root/generation fence、稳定 rootfs 父 inode 和 Agent `128+signal` 退出码已实现；同一 Cube 内自然退出与 SIGKILL Task 均完成并全量清理 | `9c679855`、`cf07e446`、`781cd8f8`、`32a49105`、`d47af8c2`；Shim 115 项、Agent/workspace 203 项通过；真实终验 `inv-9837xq0wnq`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s1.2/README.md)；最终 subagent `APPROVE` | S1.3 CRI 基础交互 |
| S1.3 CRI 基础交互 | `DONE` | Codex | Kubernetes OCI host bind mount 已经由 Pod 固定 virtio-fs shared root 导入 Guest；标准 PATH shim 选择已加制品一致性门禁；真实 `RuntimeClass/cube` Pod 的 logs、非 TTY/非 stdin exec、stdout/stderr、进程/客户端退出码 19、3 秒 grace 后 137 和删除全量基线均通过；unmount 失败时保留 export，避免目录 bind 下误删宿主数据 | `14354f09`；最终严格构建 `inv-683bb60cjf`；最终部署 `inv-883besgxts`；真实终验 `inv-383bfj082n`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s1.3/README.md)；最终同一 subagent `APPROVE` | S1.4 清理与共存 |
| S1.4 清理与共存 | `DONE` | Codex | Sandbox Spec 已返回 containerd 标准 OCI Any；默认 runc、Job/Deployment、正常/强制/创建中取消、100 Pod 循环、legacy Cubebox race tests 和 unmanaged shim 20 次循环均通过；全部 owned runtime resource 及 `/run/vc/vm` 恢复基线，legacy 安全清理和固定 Git tree 输入门禁通过 | 实现 `517c62b3`；最终构建 `inv-a83cu30ran`；部署 `inv-a83cxjgftm`；Spec `inv-983d0j0cbd`；smoke `inv-083ehrgqpm`；100 循环 `inv-883ep9gvt6`；Cubebox `inv-b83ejs0618`；legacy shim `inv-683f0pg8ge`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s1.4/README.md)；最终同一 reviewer `APPROVE` | S2.1 动态多容器 |


### 目标

让用户通过 `runtimeClassName: cube` 运行一个标准单容器 Pod，并完成完整创建和删除闭环。

### 工作项

- CubeShim 实现最小 Sandbox Create/Start/Stop/Shutdown/Status。
- Task Service 使用标准 rootfs 创建一个 Guest 容器，支持 Start/Wait/Kill/Delete。
- Cubelet 提供最小 Prepare/Release/Inspect，返回 VM 资产和网络 attachment。
- 支持 CRI 日志、非 TTY `exec`、grace period 和准确 exit code。
- 提供 RuntimeClass、containerd 配置和专用节点 label/taint。

### 验收标准

- `Pod`、`Job`、单副本 `Deployment` 能创建并达到预期状态。
- `kubectl logs` 和非 TTY `kubectl exec` 正常；失败进程返回准确 exit code。
- 正常删除、强制删除和创建中取消都能最终释放 VM、tap、virtiofs、mount 和 socket。
- 连续创建/删除 100 个单容器 Pod，无持续增长的残留资源。
- runc 仍为默认 runtime；不指定 `runtimeClassName` 的 Pod 行为不变。
- legacy Cubebox 创建/删除 smoke test 通过。

## 7. S2：多容器与 Pod 生命周期
> Milestone 状态：`DONE`。S2.1～S2.4 均已完成并通过同一 reviewer 门禁。

| Work Stage | 状态 | Owner | 已完成 | 验收证据 | 下一步 |
|---|---|---|---|---|---|
| S2.1 动态多容器 | `DONE` | Codex | 双普通容器已在同一 Sandbox/VM/Pod IP 内以独立 Task/rootfs 运行；分别 logs/exec 成功；CRI 删除 alpha 后旧 Task/rootfs 清理，beta 与 VM/IP 不变，kubelet 仅重建 alpha 并恢复 Pod Ready；整 Pod 删除恢复全量基线 | 实现 `ce3afe4c`；严格构建 `inv-083fdrgb3k`；完整加固终验 `inv-083g3u0npg`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s2.1/README.md)；最终同一 reviewer `APPROVE` | S2.2 Init 与重启 |
| S2.2 Init 与重启 | `DONE` | Codex | 双 init 严格串行、失败 init 新 Task 重试且 app 不启动、alpha exit 23 后仅定向重建 alpha 均通过；每例旧 Task/rootfs 清理，survivor/Pod UID/IP/VM/shim PID 不变并恢复全量基线 | 验收 `9467e4a0`；诊断 `inv-983ggb0u6k`；reviewer 加固后终验 `inv-a83gx50k5f`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s2.2/README.md)；最终同一 reviewer `APPROVE` | S2.3 Namespace |
| S2.3 Namespace | `DONE` | Codex | CRI namespace/hostname 已映射；默认 net/IPC/UTS 共享而 PID/mount 隔离；共享 PID 使用加固的专用 PID 1，容器替换后 holder 与 survivor 稳定；hostNetwork/hostPID/hostIPC 在资源分配前拒绝；逐例恢复全量基线 | 实现 `e1bc2b7a`、holder 加固 `72beea45`、打包修复 `9b0c14fa`、验收 `a50425d3`；严格构建 `inv-v83iix062d`；终验 `inv-a83j9u0q12`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s2.3/README.md)；最终同一 reviewer `APPROVE` | S2.4 Sidecar 与 Pod 生命周期 |
| S2.4 Sidecar 与 Pod 生命周期 | `DONE` | Codex | 两个原生 sidecar、动态 ephemeral container、startup/readiness/liveness probe、PostStart/幂等 PreStop、优雅 exit 0 与 grace 后 SIGKILL 137 均在同一 Cube VM 内通过；单容器加入/重建未影响 survivor、Pod UID/IP、Sandbox、shim 或 VM；修复 Cilium TAP 12-byte vnet header | 网络修复 `df548000`、验收脚本 `495ac4ca`；D1 `inv-383kh2g6w4`、D2 `inv-983kt80r3f`、D3 `inv-683nbagv5s`、D4 `inv-383nsc0was`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s2.4/README.md)；最终同一 reviewer `APPROVE` | S3.1 基础 Volume；TARGET PID 缺口归 `K8S-OQ-012` / S5.3 |


### 目标

把一个 Cube VM 从“单容器沙箱”升级为符合 Kubernetes Pod 语义的动态多容器 sandbox。

### 工作项

- 支持 init container、普通容器、原生 sidecar 和 ephemeral container 动态增删。
- net/IPC/UTS 在 Pod 内共享；PID 默认隔离，支持 `shareProcessNamespace`。
- 每容器独立 mount namespace、rootfs、cgroup、stdio、日志和退出状态。
- 支持 startup/readiness/liveness probe、lifecycle hook、restart policy 和 graceful termination。
- 单容器重启不得重启 VM 或影响其他容器。

### 验收标准

- init 顺序、sidecar 启停顺序和 app 并发行为符合 Kubernetes 预期。
- 一个容器 crash 后只重建该容器；其他容器和 Pod IP 保持不变。
- 多容器日志可分别读取，exec 定位到正确容器。
- `shareProcessNamespace` 开关两种模式均有 E2E；hostPID/hostIPC/hostNetwork 明确拒绝。
- ephemeral container 能在运行中的 sandbox 动态加入并退出。
- 终止宽限期、SIGTERM/SIGKILL 和 TaskExit 事件时序有自动化测试。

## 8. S3：存储、安全与资源
> Milestone 状态：`DONE`。S3.1～S3.4 已完成并通过各子阶段同一 reviewer 验收。

| Work Stage | 状态 | Owner | 已完成 | 验收证据 | 下一步 |
|---|---|---|---|---|---|
| S3.1 基础 Volume | `DONE` | Codex | 输入、独立 Pod Volume share、可写卷/失败回滚、四类投射卷动态更新、subPath 固定语义和最终支持矩阵均已关闭 | 实现 `5b504b58`；S3.1d 回归 `aafdef40` / `inv-a83u0wgvxv`；审计 `inv-v83u490xa8`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s3.1/README.md)；同一 reviewer 确认 S3.1 `DONE` | S3.2 filesystem PVC |
| S3.2 PVC | `DONE` | Codex | S3.2a～S3.2d 已完成输入基线、跨容器/Pod 重建持久化、失败回滚、static-local Retain 手工重绑、组合回归与支持矩阵 | `83902212`；组合终验 `inv-a83x7s0g04`；独立审计 `inv-883xivg7ub`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s3.2/README.md)；同一 reviewer 确认 S3.2 `DONE` | S3.3 SecurityContext |
| S3.3 SecurityContext | `DONE` | Codex | S3.3a～S3.3f 已完成输入诊断、身份与组、capability/rootfs、NNP/seccomp、privileged 双门禁、exec 安全上下文和组合支持矩阵 | 实现 `7bf7f09d`；组合终验 `inv-v84gjpgj7k`；独立审计 `inv-884huw00ab`；[验收证据](../../handoffs/kubernetes-runtime/evidence/s3.3/README.md)；同一 reviewer `APPROVE S3.3f DONE` | S3.4 资源控制 |
| S3.4 资源控制 | `DONE` | Codex | S3.4a～S3.4d 全部完成；默认小 VM 启动、极端内存下调、Shim RPC client、生命周期 fence 及 systemd collection 等待后的 cgroup identity TOCTOU 已关闭 | 最终实现 `10b7af56`；QoS/多容器/Pod-level、Guest/Host 数值、OOM、resize、ephemeral-storage、在线 containerd restart、双 Worker exact zero 已闭环；持续长 exec+resize 与创建即取消零告警分别登记 `K8S-OQ-022/023`；[S3.4d 证据](../../handoffs/kubernetes-runtime/evidence/s3.4/s3.4d-execution-summary.md)；同一 reviewer `APPROVE S3.4 DONE`，P0/P1/P2=0 | S5.3 Kubernetes v1.36.4 Node E2E/Conformance |

### S3.1 子阶段执行记录

| 子阶段 | 状态 | 目标 | 验收标准 | 当前结果/下一步 |
|---|---|---|---|---|
| S3.1a 输入与现状诊断 | `DONE` | 冻结 kubelet/CRI/OCI Volume 输入和 Cube 当前语义 | runc 对照、Cube 读写/投射/更新/subPath 矩阵完整；活动与删除 mount 证据完整；同一 reviewer `APPROVE` | `inv-a83peh0hec` 通过；证实固定只读 share 同时导致可写卷 EROFS 和动态投射不可见 |
| S3.1b 可写 Volume 通道 | `DONE` | 为 Pod 增加独立 Volume share，并把标准 OCI bind 重写到该通道 | disk/memory emptyDir 跨 init/app/sidecar 双向读写；同卷不同路径与 `ro/rw` 正确；rootfs share 仍只读；失败创建和删除零残留 | `5b504b58` 实现 `cubeVolumes` 与 mount-aware 生命周期；`inv-a83rxbgg0g` 通过 Rust 137 项、Go race/vet 和真实特权 bind cleanup；`inv-a83sdvgumu` 与 `inv-883sh80mpp` 终验通过；同一 reviewer `APPROVE` |
| S3.1c 投射卷与 subPath | `DONE` | 验证启动注入、更新策略和 kubelet 已展开的 subPath | ConfigMap/Secret/projected/downwardAPI 启动值与 mode 正确；subPath 对照一致；动态更新支持状态明确写入 `K8S-OQ-007` | `20881f71` / `inv-a83th50gfh`：runc 1 秒、Cube 0 秒读到完整更新；Host/Guest generation 变化，subPath 值与 inode 固定，Sandbox/shim/VM/mount ID 稳定；清理恢复全量基线；同一 reviewer `APPROVE` |
| S3.1d 回归与支持矩阵 | `DONE` | 完成多容器、更新、失败清理和兼容性回归 | 自动化矩阵通过；Pod UID/IP、Sandbox、shim、VM 稳定；删除恢复全量基线；文档和 handoff 可复现 | `aafdef40` / `inv-a83u0wgvxv` / `inv-v83u490xa8`：组件 trace 为空，全局 8 组集合一致，tombstone +3，支持矩阵 14 项；同一 reviewer 确认 S3.1 `DONE` |

### S3.2 子阶段执行记录

| 子阶段 | 状态 | 目标 | 验收标准 | 当前结果/下一步 |
|---|---|---|---|---|
| S3.2a PVC/CSI 输入诊断 | `DONE` | 选择 PoC filesystem PVC 后端，冻结 kubelet/CRI/OCI 输入与回收边界 | 只读盘点 StorageClass/CSIDriver/CSINode/PV/PVC；runc 对照能绑定、挂载、读写、删除；Cube 标准 bind 输入完整；同一 reviewer `APPROVE` | `11ada44e` / `inv-983uns0e3g` / `inv-v83uqvgu6g`：集群没有 CSI；static local Filesystem/RWO/WFFC/Retain 基线绑定、CRI/OCI 等价、runc→Cube 数据保持、Guest 可写和全量清理通过；不外推为 CSI/动态制备/生产后端支持 |
| S3.2b RWO 持久化 | `DONE` | 让 filesystem RWO PVC 在 Cube Pod 内跨容器、跨 Pod 重建持久化 | writer/peer 读写一致；Pod UID/Sandbox/VM 更换后数据保持；PVC/PV 仍绑定；删除 Pod 零 runtime 残留 | `6e2df6fb` / `inv-983v8eg0jr` / `inv-983vb002pg`：四 marker 持久，Pod UID/Sandbox/lease/source 更新，PVC/PV 四时点 UID/Bound 稳定，两轮 runtime 和最终全量基线恢复，tombstone +2；同一 reviewer `APPROVE` |
| S3.2c 回收与故障 | `DONE` | 验证失败启动、卸载、重绑和 reclaim 语义 | 失败 Task generation/mount 清零；PVC 可重绑；Retain/Delete 行为与后端一致；无 active lease | `0bd25272` / `inv-b83w9pgt64` / `inv-b83wguggpg`：精确 `/dev/kvm` StartError 前已处理 PVC，连续 30 次 generation/mount 为 0 且取证时 VM runtime 目录存在；健康 Pod 复用数据；Retain PV 经 Released gate、管理员移除 claimRef 后绑定新 PVC，三个 marker 保持；三条 inactive tombstone、最终 active lease 和全量残留为 0；static-local Delete 明确为无 deleter 时不适用；同一 reviewer `APPROVE` |
| S3.2d 回归与支持矩阵 | `DONE` | 组合回归并冻结 filesystem PVC 支持范围 | 自动化回归通过；资源基线恢复；RWO/RWX、CSI/非 CSI、扩容等未覆盖项明确记录；handoff 可复现 | `83902212` / `inv-a83x7s0g04` / `inv-883xivg7ub`：按 SHA 固定并顺序重放 S3.2a～S3.2c，三次精确基线均首轮恢复，durable tombstone 总增量 6 且六个 Sandbox 各一条 inactive lease；20 项矩阵仅把 static-local Filesystem/RWO runtime 基线标为 PoC 支持，CSI、动态制备、CBS/CFS/COSFS、RWX、跨节点、扩容保持未验证，raw block/mountPropagation 为 `OUT_OF_SCOPE_POC`，snapshot 路由 S6；同一 reviewer 确认 S3.2 `DONE` |

### S3.3 子阶段执行记录

| 子阶段 | 状态 | 目标 | 验收标准 | 当前结果/下一步 |
|---|---|---|---|---|
| S3.3a 输入与现状诊断 | `DONE` | 冻结 kubelet/CRI/OCI 到 Guest 的安全字段输入和当前差异 | 8 个 runc/Cube 对照 Pod 覆盖六项字段；原始 CRI/ctr、Guest init/log、lease 与精确基线证据完整；同一 reviewer `APPROVE` | `9380c163` / `inv-9840smg1q7` / `inv-a840xpgpsu`：UID/GID、groups、NET_RAW、readonly rootfs、RuntimeDefault seccomp 当前匹配；host NNP=true 但 Cube Guest=0，记入 `K8S-OQ-013`；身份与组边界已由下一行 S3.3b 闭环 |
| S3.3b UID/GID 与组 | `DONE` | 固化用户、主组和 supplemental groups 的实现契约 | 数值 UID/GID、主 GID、多个 supplemental groups 的正反用例通过；runc/Cube 输入等价；重复创建删除无残留；同一 reviewer `APPROVE` | `d6c16e6b` / `inv-9841kq036r` / `inv-384315g7di` / `inv-a843e8g0wv`：create/exec 原样保留 UID/GID 和组顺序/重复项，exec 另覆盖 username；两轮 Merge/Strict、fsGroup emptyDir、classic init、restartable sidecar、PodStatus 与非 TTY exec 全部 runc/Cube 等价；14 个唯一 Pod UID、20 个唯一正例 container ID、7 个 Cube sandbox/tombstone，lease `466→473`，所有检查点与实时状态精确恢复基线；`runAsNonRoot=true + UID0` 在两种 runtime 均由 kubelet 于 workload 创建前拒绝；同一 reviewer 最终 `APPROVE` |
| S3.3c capabilities 与只读 rootfs | `DONE` | 固化 capability add/drop 和 rootfs 只读执行语义 | `drop ALL`、选择性 add、边界 capability 和只读写失败正反用例通过；Guest mask 与 OCI 输入一致；清理闭环 | `c55b759e` / `inv-b845t9grgt` / `inv-6846wbgtiv` / `inv-6847cm06pi`：两轮 18 个 Pod、26 个容器、9 个 Cube sandbox 覆盖五类 mask、CAP 40、RO/RW/emptyDir、非 TTY exec 和非法 capability host fail-closed；lease `479→488`、所有活动基线归零；legacy `inv-084814gvgg` 通过 324 项 race tests；同一 reviewer `APPROVE S3.3c DONE` |
| S3.3d NNP 与 seccomp | `DONE` | 去除 NNP 静默降级并固化 RuntimeDefault seccomp | host NNP=true 时 Guest `NoNewPrivs=1`；false/true 正反用例和 RuntimeDefault 过滤行为通过；关闭 `K8S-OQ-013`；清理闭环 | `5a851245` 保留 NNP 并对当前 protobuf 无法表达的 seccomp 字段 fail-closed；Shim `60ba8906…`。`inv-b849phgapi` 两轮 8 Pod 验证 runc/Cube 的 NNP `0/1`、seccomp mode `0/2` 和 `unshare` 允许/阻断，4 个 Cube sandbox、lease `488→492`、active lease 0、精确基线恢复；`inv-3849tjgnmx` 独立审计通过；同一 reviewer `APPROVE S3.3d DONE` |
| S3.3e privileged 双门禁 | `DONE` | 实现节点开关与 Pod 请求双门禁，只在 Guest 内提权 | 开关关闭时 privileged 请求明确失败；开关开启且 Pod 请求时才生效；普通 Pod 不提权；Host `/dev` 不透传；六次活动资源精确归零；同一 reviewer `APPROVE S3.3e DONE` | `d594a7fa` / `inv-684bwgg03r` / `inv-084cdrgc1k` / `inv-384cpa0n8v`：Shim `84c27649…`、Agent ext4 `87bac7a6…`；普通/privileged capability 与 mount 正反例、canonical OCI marker、Host `/dev` fail-closed、开关恢复均闭环；cgroup v2 的 Guest device rule 明确标为 E2E 不可观察，Agent wildcard 云单测 2/2 |
| S3.3f 回归与支持矩阵 | `DONE` | 顺序重放安全子阶段并冻结首版支持范围 | 固定脚本 hash 的组合回归通过；正反用例、失败语义、lease/资源基线和支持矩阵闭环；同一 reviewer `APPROVE` | `7bf7f09d` / `inv-v84gjpgj7k` / `inv-884huw00ab`：16 个 raw container、8 个 Cube sandbox/tombstone、lease `524→532`、14 类 exact baseline、21 项支持矩阵与 effective privileged switch=false 全部闭环；同一 reviewer `APPROVE S3.3f DONE` |

### S3.4 子阶段执行记录

| 子阶段 | 状态 | 目标 | 验收标准 | 当前结果/下一步 |
|---|---|---|---|---|
| S3.4a 资源输入与现状诊断 | `DONE` | 冻结 Kubernetes 1.36/containerd 2.3 在 cgroup v2 上对 CPU、内存、swap、PIDs、hugepages 和 ephemeral-storage 的职责边界，并定位 Cube create/update 的真实缺口 | runc/Cube 对照覆盖 BestEffort/Burstable/Guaranteed、request-only/limit、init/restartable sidecar/app；保存 raw Pod/CRI/ctr OCI、Host VM/Shim cgroup、Guest per-container cgroup 和 cleanup 基线；create/update/拒绝路径形成证据矩阵；同一 reviewer `APPROVE` | V15 `/data/cubelet/s3.4-evidence/s34a-20260901T145751Z-2537408`：6 个 Pod、17 个低层 Task、1 个预期 reject、2 个 invalid-unified、20 份 trace 与 exact cleanup 通过；quota 和 `memory.max` 数值链已生效，period 仅覆盖默认 `100000`、未独立证明；shares 映射不兼容、limit-only 隐式 swap=0，NoSwap 的 observable `0` 不是 unified 无损传输结果；其余缺口进入 S3.4b；同一 reviewer `APPROVE S3.4a DONE` |
| S3.4b Guest per-container cgroup | `DONE` | 保持 quota 与 `memory.max` 数值链，独立验证非默认 period，并让标准 OCI/Task Update 资源在 Guest resource parent 正确生效或明确拒绝 | 非默认 period create/update 正确；shares→weight 与当前 containerd/cgroups v3/runc 对照一致；limit-only 不改变 swap；无损处理或白名单实现 unified `memory.swap.max` 且 Kubernetes NoSwap 回归通过；reservation、显式 swap、cpuset、PIDs、hugepage、其他 unified 的 create/update 值正确；暂不能表示的字段 fail-closed，不再 accepted-unapplied；压力/OOM/PIDs/hugepage 正反例可归因到目标容器；同 Pod survivor 不受影响；validation/preflight 零写入，运行期失败且 rollback 成功时 controller/spec 复原，rollback 失败进入可重试 undo 的 fail-stop；create 失败由显式 pending owner 清理；同一 reviewer `APPROVE` | `be8e7304` 最终实现；正式矩阵 `inv-8853vxgxh1`、`inv-9855pngtst`、`inv-08564809p0`、`inv-68569j047d`、`inv-v856bt07f9` 与 clean preflight `inv-6856c8gt1t` 均通过；[证据摘要](../../handoffs/kubernetes-runtime/evidence/s3.4/s3.4b-execution-summary.txt)；同一 reviewer `APPROVE S3.4b DONE` |
| S3.4c Host Pod VM 资源包络 | `DONE` | 在 Host cgroup 对一个 Pod VM 的总 CPU/内存/进程资源实施静态 VM 容量 ceiling，并让 kubelet 父层和 Guest 容器层保持各自动态更新职责 | Host 预算算法有固定测试向量；VM/VMM/virtiofs/辅助进程归入唯一 Pod leaf；压力下祖先/leaf 交集生效且不影响其他 Pod；更新、OOM、删除和失败创建均收敛；同一 reviewer `APPROVE S3.4c DONE` | `2a23aa3c` 已完成六 Pod/九容器原始证据、启动阶段 `OOMKilled/137`、inactive scope 删除、在线 containerd restart 与双节点 exact baseline；同一 reviewer 确认无 P0/P1/P2 并 `APPROVE S3.4c DONE`；`K8S-OQ-021/022` 进入 S3.4d |
| S3.4d 压力回归与支持矩阵 | `DONE` | 组合验证 Host/Guest 双层限制、QoS、更新、故障与非 cgroup 资源，并冻结首版范围 | 多容器 CPU/内存压力、定向 OOM、in-place update、swap/hugepage/PIDs、ephemeral-storage 责任边界均有通过或明确拒绝证据；lease/Pod/VM/cgroup 全量基线恢复；独立审计和同一 reviewer `APPROVE S3.4 DONE` | `10b7af56`；`K8S-OQ-015/016/017/021` 已关闭，restart/resize/受控 long-exec、生命周期 fence 及 systemd collection 后 identity 重验已通过；最终构建 `inv-v86nregacb`、部署 `inv-686nvg0va4`/`inv-886nvfg6v6`，功能回归与清理 `inv-086ncr074p`、`inv-a86ndt0pkt`/`inv-a86nds0c3q`、`inv-v86nea09kv`。持续 long-exec+resize 和创建即取消零告警转 `K8S-OQ-022/023`；[执行摘要](../../handoffs/kubernetes-runtime/evidence/s3.4/s3.4d-execution-summary.md)；同一 reviewer `APPROVE S3.4 DONE`，P0/P1/P2=0 |

#### S3.4b 实现单元记录

| 实现单元 | 状态 | 完成内容 | 验收结果/下一步 |
|---|---|---|---|
| S3.4b.1 Shim/Protocol V2 | `DONE` | mirrored tag-8 envelope；managed create/update 在 typed 解析和副作用前做 raw duplicate/unknown 校验；canonical presence；devices update fail-close；capability gate；legacy 不发 V2 | `6a07ff69`；双侧 golden wire、Shim/Agent `cargo check`、`git diff --check` 通过；同一 reviewer `APPROVE S3.4b SHIM/PROTOCOL UNIT` |
| S3.4b.2 Agent decode 与 controller transaction | `DONE` | strict envelope/parser、presence 模型、字段 planner、确定顺序写入/readback/rollback/replay、逐字段 merge；cgroup v2 device eBPF；区间式 cpuset 与空值恢复 | `8e54a209`；资源专项 22/22、device eBPF 3/3、Agent 编译与 diff check 通过；同一 reviewer `APPROVE S3.4b.2` |
| S3.4b.3 degraded/PendingCreate | `DONE` | rollback failure fail-stop/undo replay、create 显式 owner 与可重试 cleanup；序列化 update/remove/stats；create 并发、storage/rootfs/process/cgroup/FD 的显式所有权与幂等清理 | `87848156`；Agent check/test compile、128 项 rustjail 非特权稳定集连续三轮、资源与 pending-create 专项均通过；全量仅宿主机特定 `fchown` 用例因 EINVAL 失败；同一 reviewer `APPROVE S3.4b.3 DONE` |
| S3.4b.4 云端矩阵与审计 | `DONE` | runc/Cube 数值、压力、失败注入、兼容路径、exact baseline 与独立审计 | `90934bb4` 广告 capability，最终 Shim/Agent SHA `398416c5…`/`2e3318e6…`；17 组数值、20 个 partial update、CPU/内存/PIDs/hugepage、真实 cgroup fault、capability、legacy 20×2、Kubernetes resize 与 exact cleanup 均闭环；同一 reviewer `APPROVE S3.4b DONE` |

#### S3.4c 实现单元记录

| 实现单元 | 状态 | 目标 | 验收标准/下一步 |
|---|---|---|---|
| S3.4c.1 包络输入与生命周期设计 | `DONE` | 冻结 CRI/RuntimeClass 输入、Host parent/static leaf owner、managed/legacy 分类、进程身份、bundle 外 containerd 接管、scanner 与 controller WAL 状态机 | 候选 V4 冻结 12 个固定向量、immutable/containment identity、external lifecycle + 双 owner、operation-owner epoch/revoke、INTENT-before-write WAL 和封闭恢复表；`inv-38589x0k30` 在 systemd `255.4-1ubuntu8` 连续 200 次通过且 cleanup exact/dropped=0；同一 reviewer 四轮复审后明确 `APPROVE S3.4c DESIGN` |
| S3.4c.2 Host cgroup 生命周期与进程归属 | `DONE` | 为 managed Sandbox 创建唯一 Pod leaf并从首次分配起放置 Shim/VMM/virtiofs；legacy Task 不迁移；长期 scanner 覆盖 bundle/socket/leaf | 最终实现 `90edf7bf`；Host lifecycle 55/55；双节点 gate 200；live Delete `inv-986cwegjsh`、sibling/PID 诱饵 `inv-386d0802k1`、containerd restart `inv-686d0r0frx`/`inv-a86d18gp2k`、legacy/watchdog `inv-p86d0q07k9` 与双 Worker 零基线 `inv-b86d1xgwuh`/`inv-v86d20090k` 全部通过；同一 reviewer 确认 P0/P1/P2=0 并 `APPROVE S3.4c.2`；[终验证据](../../handoffs/kubernetes-runtime/evidence/s3.4/s3.4c.2-execution-summary.md) |
| S3.4c.3 RuntimeClass overhead 与静态 leaf ceiling | `DONE` | 消费标准 cgroup_parent/overhead，应用静态 VM CPU/memory/PIDs ceiling；kubelet parent 与 Guest Task Update 各自负责动态 resize | `be91f9e0` 与 `inv-386fp40a6b` 已完成 157/157；双 Worker `inv-886ftngie9`/`inv-886ftp00b4` gate 200；真实 V1/controller/WAL `inv-886fv7gh79`/`inv-886fvfgqhw`、双节点 exact zero 与 V12/PIDs 对抗回归通过；同一 reviewer 已明确 `APPROVE S3.4c.3` |
| S3.4c.4 云端压力、故障与兼容审计 | `DONE` | 验证 Host 上限、隔离、OOM、更新、清理和旧路径兼容 | `2a23aa3c` 最终构建 Shim 160/160、OOM notifier 4/4；`inv-686i7a0qux`/`inv-686i7a0quv`/`inv-386i7ags0q` 保存六 Pod、九容器 Guest/Host 原始证据；`inv-886i0qgtq9` 启动即 OOM 8/8 为 `OOMKilled/137`；`inv-v86i55g64g`/`inv-b86i5egc5x` 关闭 inactive scope 删除；`inv-a86ig40cbx`/`inv-086ig5gp25` 双节点 exact zero，`inv-886iicgsqw` 集群健康；同一 reviewer 确认无 P0/P1/P2 并 `APPROVE S3.4c DONE`；两个未通过组合登记 `K8S-OQ-021/022`；[终验证据](../../handoffs/kubernetes-runtime/evidence/s3.4/s3.4c.4-execution-summary.md) |


### 目标

覆盖用户首版要求的 volume、安全上下文和资源控制主路径。

### 工作项

- 支持 `emptyDir`、ConfigMap、Secret、projected volume、基础文件系统 PVC 和 allowlist `hostPath`。
- 支持 UID/GID、supplemental groups、capabilities、只读 rootfs、`no_new_privileges` 和 seccomp。
- privileged 使用节点开关与 Pod 请求双门禁，只在 Guest 内提权，不自动透传 Host 设备。
- Host VM cgroup 限制总资源；Guest cgroup 限制每容器资源。
- PoC 使用固定 VM 规格并测量开销；是否增加资源 admission 由数据决定。

### 验收标准

- 同一 volume 可按不同目标路径/只读属性挂载到多个容器。
- RWO 文件系统 PVC 可挂载、读写、卸载并在 Pod 删除后无引用泄漏。
- ConfigMap、Secret、projected、downwardAPI 的启动值、mode 与 atomic-writer 动态更新正确；文件 `subPath` 保持 Pod 启动时的值和 inode，不随主卷更新（`K8S-OQ-007=DECIDED`）。
- UID/GID/groups、capability add/drop、readonly rootfs、seccomp 均有正反用例。
- privileged 未开启时请求被拒绝；开启后仍无法访问未授权 Host device/path。
- Host/Guest CPU、内存限制在压力测试中生效，OOM 能归因到正确 Pod/容器。
- raw block、完整 subPath、双向 mount propagation 等未实现能力返回明确结果并写入支持矩阵。

## 9. S4：恢复与可观测性
> Milestone 状态：`NOT_STARTED`。依赖 S3.1～S3.4 完成。

| Work Stage | 状态 | Owner | 已完成 | 验收证据 | 下一步 |
|---|---|---|---|---|---|
| S4.1 状态与重连 | `NOT_STARTED` | 待指定 | — | — | 定义最小持久状态并实现组件重连 |
| S4.2 Reconcile | `NOT_STARTED` | 待指定 | — | — | 对账并清理 VM、网络和 mount 资源 |
| S4.3 可观测性 | `NOT_STARTED` | 待指定 | — | — | 输出 logs、events、metrics 和 CRI stats |


### 目标

让 PoC 在组件重启和常见失败下保持可诊断、可清理，而不是只能在理想路径运行。

### 工作项

- 持久化最小 sandbox/container 状态并实现幂等操作。
- containerd、CubeShim、Cubelet 重启后重连存活 VM；节点重启由 Kubernetes 重建。
- 对 VM、tap、virtiofs、mount、socket 和 tombstone 做 reconcile。
- 输出 sandbox/容器事件、结构化日志、Prometheus 指标和 CRI stats。
- 统一 sandbox/container request ID，提供最小 inspect/diagnostic 命令。

### 验收标准

- 分别 kill/restart containerd、CubeShim、Cubelet，运行中的 Pod 要么恢复，要么进入明确失败并可被 kubelet 重建。
- Agent 断连能重试；超过阈值后状态明确，不无限卡住。
- CNI、mount、VM 删除故障可通过 reconcile 收敛，重复执行不会破坏其他 Pod。
- 故障注入后无跨 Pod 误删，残留资源数量回到基线。
- CRI stats 与 Host/Guest 原始数据误差在记录的容忍范围内。
- 每种失败至少能从日志或指标定位到具体生命周期阶段。

## 10. S5：PoC 集成交付
> Milestone 状态：`IN_PROGRESS`。按 PoC 快速验收优先级先执行 S5.3；S4.1～S4.3 仍需后续完成。

| Work Stage | 状态 | Owner | 已完成 | 验收证据 | 下一步 |
|---|---|---|---|---|---|
| S5.1 安装与共存 | `NOT_STARTED` | 待指定 | — | — | 提供安装、卸载和 runc 共存方案 |
| S5.2 升级与回滚 | `NOT_STARTED` | 待指定 | — | — | 验证版本协商、滚动升级和回滚 |
| S5.3 兼容性 | `DONE` | Codex | Kubernetes v1.36.4 官方 477 个 NodeConformance `It` 已通过互斥分片完整执行并唯一归并：456 Passed、17 Failed、4 Skipped；支持路径真实缺陷已修复，17 个失败和 4 个 Skip 均有上游名称、责任层、问题 ID 与后续方案；测试环境、普通 kubelet/CNI/系统 workload 已恢复 | 最终 Agent `64381287`；Device/PodResources `inv-389w3ggrk9` 为 10/10 通过、1 个 SR-IOV 条件 Skip；终审重跑后双节点 exact-zero `inv-98a04qgm41`；集群恢复 `inv-a8a04sguer`；同一 reviewer `PASS`（P0/P1/P2=0）；[最终报告](../../handoffs/kubernetes-runtime/evidence/s5.3/s5.3b-nodeconformance.md) | 兼容性回归输入留到 S5.5f；性能主线当前进入 S5.5c |
| S5.4 启动架构、性能与稳定性 | `IN_PROGRESS` | Codex | S5.4a/b/c 已完成：worker 拆分后以单次 D-Bus placement + inode/`/proc` 轻量门禁取代正常启动的重复 `systemctl show`；50 次串行和 5×10 并发均 100% 成功且无 PullImage，串行入口 P95 达标；生命周期矩阵和 exact-zero 无回退 | 实现 `7a4d5554 → 26d3ca74 → c949d6d4 → 94c01e21 → fa278467`；[S5.4b 证据](../../handoffs/kubernetes-runtime/evidence/s5.4/s5.4b-worker-split.md)；[S5.4c 证据](../../handoffs/kubernetes-runtime/evidence/s5.4/s5.4c-startup-fastpath.md)；同一 reviewer `PASS`，P0/P1/P2=0/0/1 | 先执行 S5.5 普通冷启动优化；最终一秒目标仍在 S6.2/S5.4d 关闭 |
| S5.5 普通冷启动性能优化 | `IN_PROGRESS` | Codex | S5.5a～d.2b 已完成且 reviewer `PASS`；d.2c-r1 串行门禁通过，但并发 385.254/489.974ms 与一次 neighbor retry 导致正式结论 FAIL（P0/P1/P2=0/2/1） | [S5.5 性能方案](./kubernetes-runtime-performance-s5.5.md)；[S5.5a 基线](../../handoffs/kubernetes-runtime/evidence/s5.5/s5.5a-final-baseline.md)；[S5.5b 证据](../../handoffs/kubernetes-runtime/evidence/s5.5/s5.5b-cross-sandbox-parallelism.md)；[S5.5c 最终证据](../../handoffs/kubernetes-runtime/evidence/s5.5/s5.5c-netlink-fastpath.md)；[S5.5d.1 证据](../../handoffs/kubernetes-runtime/evidence/s5.5/s5.5d.1-pre-shim-fastpath.md)；[S5.5d.2 证据](../../handoffs/kubernetes-runtime/evidence/s5.5/s5.5d.2-durable-create-fastpath.md) | 执行 S5.5d.3a neighbor reliability，再做 d.3b VMM/network overlap 与 d.3c 完整重验 |

### S5.3～S5.5 剩余实现单元与执行顺序

下列顺序是后续工作的权威顺序。worker 拆分、普通启动优化和 Kubernetes Node E2E 分片执行
均已完成，S5.3 最终 reviewer 审计 `PASS`。下一步先执行 S5.5 普通冷启动性能优化，再进入
S6.1 讨论 RuntimeTemplate、PodSnapshot 和 Pause/Resume；不回退已经验收的 worker 边界。

| 顺序 | 实现单元 | 状态 | 目标 | 验收标准/下一步 |
|---|---|---|---|---|
| 1 | S5.3a 既有兼容修复回归 | `DONE` | SIGKILL、Pod sysctl、cpuset、hostname/FQDN、stats 与 Agent fixture 修复已在 worker 路径回归 | SIGKILL、两类 sysctl、CPU Manager/PodResources、restartable sidecar、hostname 与 metrics 定向用例通过；失败对象清理后 runtime exact-zero |
| 2 | S5.4a SLO 与进程边界设计 | `DONE` | 已冻结 CubeShim/Cubelet/worker 所有权、普通启动 IPC v1、SCM_RIGHTS FD slot、spawn INTENT/启动 gate、故障收敛、回滚开关、单调时间戳和性能口径；不提前冻结 template、snapshot 或 pause/resume 语义 | `K8S-OQ-031/032=DECIDED`；契约见 `evidence/s5.4/s5.4a-worker-contract.md`；同一 reviewer 第三轮 `PASS`；`K8S-OQ-008` 保持延期 |
| 3 | S5.4b VMM worker 拆分 | `DONE` | 已将内嵌 VMM/vCPU/virtiofs/Guest memory 移入每 Pod 一个独立 worker；CubeShim 保留 Sandbox/Task 语义并管理 sandbox leaf/scope，Cubelet 只管理 RuntimeResource lease，worker 只接受 CubeShim 控制 | 双节点普通/多容器、worker/Shim kill、创建取消、containerd/RuntimeResource restart、embedded 回滚及全资源 exact-zero 均通过；[验收证据](../../handoffs/kubernetes-runtime/evidence/s5.4/s5.4b-worker-split.md)；同一 reviewer `PASS`，P0/P1/P2=0 |
| 4 | S5.4c 非快照启动优化与 E2E 入口门禁 | `DONE` | 已删除正常启动的 systemd CLI 门禁，使用单次 D-Bus placement + `/proc`/inode/epoch 轻量验证；100 个性能样本与生命周期故障矩阵证明 E2E 将运行在新 worker 快路径 | trace 中 `systemctl show=0`；串行 50/50，Scheduled→Ready P95=1935.438ms、RunPodSandbox P95=1575.632ms；5×10 并发 50/50；PullImage=0；故障后 exact-zero；[验收证据](../../handoffs/kubernetes-runtime/evidence/s5.4/s5.4c-startup-fastpath.md)；reviewer `PASS`，P0/P1/P2=0/0/1 |
| 5 | S5.3b Node E2E 支持面收口 | `DONE` | worker 普通启动路径上的 477 项已全部执行；支持路径缺陷已关闭，环境失败与当前架构差异分开记录 | 456 Passed、17 Failed、4 Skipped；其中 1 个环境限制、16 个已解释架构差异；3 个 hostNetwork 相关 Passed 未走 Cube；最终 Device/PodResources 10/10 通过、1 个硬件 Skip；同一 reviewer `PASS`（P0/P1/P2=0） |
| 6 | S5.3c 最终 Node E2E 与报告 | `DONE` | 477 项唯一归并、原始输入哈希、失败/Skip 分类、问题 ID、双节点恢复和 exact-zero 已完成 | [最终报告](../../handoffs/kubernetes-runtime/evidence/s5.3/s5.3b-nodeconformance.md)；`inv-98a04qgm41`/`inv-a8a04sguer` 证明 W1/W2 Ready、kube-system 全 Ready、临时 policy/auth 已删除且双 Worker exact-zero；`make handoff-validate` 通过；同一 reviewer `PASS`（P0/P1/P2=0） |
| 7 | S5.5a～S5.5f 普通冷启动性能优化 | `IN_PROGRESS` | 不依赖模板/快照，依次完成逐 Pod tracing和资源 A/B、跨 Pod 解锁、netlink、pre-Shim/CRI-CNI dispatch、durable create/cgroup、Guest boot/内存与端到端门禁 | 串行 PodScheduled→Ready P95≤1.5s；5×10 并发 P95≤1.8s 且相对串行增量≤300ms；普通冷启动资源开销完成同口径标定并达到 S5.5e 门禁；完整标准见 [S5.5 方案](./kubernetes-runtime-performance-s5.5.md) |
| 8 | S6.1～S6.4 模板、快照与暂停恢复 | `NOT_STARTED` | S5.5 后与用户讨论并冻结 RuntimeTemplate、PodSnapshot 和 Pause/Resume 的产品语义；先按 S6.2a～c 完成 RuntimeTemplate，再进入 PodSnapshot | 见 S6 子阶段；不得用旧 Pod UID、IP、DNS、Secret 或 volume mount 污染新 Pod；若设计需要调整 worker IPC，使用版本化扩展而非改写已经验收的普通启动路径 |
| 9 | S5.4d 最终一秒门禁与回归 | `NOT_STARTED` | 若普通 boot 尚未达到一秒目标，使用 RuntimeTemplate 快路径关闭最终 SLO；新默认路径必须补做 Node E2E 回归 | 所有镜像预拉取且日志证明无 PullImage；单容器无 probe 的 PodScheduled→Ready P95≤1s，同时 RunPodSandbox 接收→Ready P95≤700ms；50 次串行、10 并发，成功率 100%；P99、普通 boot fallback 和模板 miss 单列；若模板成为默认路径，NodeConformance 支持面回归仍为 0 失败 |

一秒门禁默认使用 P95 而不是单次最好值，且“不包含镜像拉取”必须由节点预拉取和运行日志共同证明。S5.4c 先给普通 boot 建立性能门禁，避免在已知慢路径上消耗完整 E2E 时间；S5.3c 随后完成 worker 普通路径的 Kubernetes 验收。若普通 boot 未达到最终一秒目标，S6.2 再用 runtime template restore 关闭差距，不把模板 miss 或 fallback 隐藏在命中样本中；若模板成为默认启动路径，必须补跑受影响的 Node E2E，而不是沿用普通路径结果。

### S5.5 子阶段状态

> Milestone 状态：`IN_PROGRESS`。S5.5 只优化普通冷启动；模板、快照和暂停恢复仍属于 S6。

| Work Stage | 状态 | Owner | 目标 | 验收标准/下一步 |
|---|---|---|---|---|
| S5.5a 最终制品基线与可观测性 | `DONE` | Codex | 已建立 kubelet/containerd/CubeShim/Cubelet/worker/Guest 的逐 Pod 单调时间线，并冻结 worker/embedded、1/5/20 Pod、PSS/cgroup 双账本和 virtiofs 0/1/2 resident 增量口径 | 串行和 5×10 各 50/50 唯一关联，覆盖最低 99.77%，trace 回退<0.05%；18 轮资源矩阵、9 轮 virtiofs 配对、生产恢复和 exact-zero 通过；[最终基线](../../handoffs/kubernetes-runtime/evidence/s5.5/s5.5a-final-baseline.md)；reviewer `PASS`（P0/P1/P2=0） |
| S5.5b 移除跨 Pod 串行 | `DONE` | Codex | adapter、Coordinator、Store 和 FD Registry 已改为 per-sandbox 并发；同 sandbox 仍线性化 | lock-wait P95=0.005ms；RuntimeResource P95 346.823→138.400ms；串行回退<0.4%；restart/cancel/exact-zero 通过；[最终证据](../../handoffs/kubernetes-runtime/evidence/s5.5/s5.5b-cross-sandbox-parallelism.md)；reviewer `PASS`（P0/P1/P2=0） |
| S5.5c netlink 网络快路径 | `DONE` | Codex | 生产 netlink backend 已取代热路径 `nsenter/ip/tc/ping`；直接耗时、Cilium IPv4、真实跨节点、真实内核双栈/故障回滚、command 回滚、restart 和 exact-zero 均完成 | network prepare 串行/并发 P95=4.313/6.293ms、exec=0；[三份可反向校验证据包与最终报告](../../handoffs/kubernetes-runtime/evidence/s5.5/s5.5c-netlink-fastpath.md)已完成；reviewer `PASS`（P0/P1/P2=0）。累计 CRI→start-vm 未达 checkpoint，债务显式转入 d.1/d.2 |
| S5.5d.1 CRI/CNI dispatch 与 Shim 连接前快路径 | `DONE` | Codex | 为 external shim sandboxer 增加默认关闭的 CNI/Create overlap；Cubelet 等待 CNI 接口地址/路由后建立 TAP；分析器使用两条单调链的偏序时间线 | 修复版首次正式 50+50 成功率 100%，Pod/Sandbox/Shim/worker 唯一绑定，绝对 pre-Shim P95=75.812/147.511ms，达到≤80/150ms；网络、跨节点、containerd restart、严格 10/10 Pending 创建取消、双节点 exact-zero 和原始证据包完成；[阶段证据](../../handoffs/kubernetes-runtime/evidence/s5.5/s5.5d.1-pre-shim-fastpath.md)；同一 reviewer `PASS`（P0/P1/P2=0） |
| S5.5d.2 durable create、持久化与 Host cgroup 快路径 | `VALIDATING` | Codex | d.2a/d.2b 已 reviewer PASS；d.2c-r1 串行 Shim→VMM/CRI→VMM=111.431/182.333ms，但并发=385.254/489.974ms，且一次 neighbor timeout 造成 retry/11.184s spread，reviewer 判定 FAIL | 失败证据永久保留；门禁不变且不得跨版本拼接。转 S5.5d.3a 邻居可靠性、d.3b VMM/network overlap、d.3c 同版本完整 50+50/回归关闭 |
| S5.5d.3 network/VMM 解耦与重验 | `IN_PROGRESS` | Codex | d.3a 正在修复 delayed gateway neighbor；d.3b 将使 VMM preboot 与 network finalize/attach 重叠；d.3c 负责完整重验 | 10 并发首次 CRI 无 retry；任一分支失败可恢复清零；同一新 commit/artifact/analyzer 达到 d.2 全部门禁并通过功能/故障/exact-zero；每个子阶段经同一 reviewer PASS |
| S5.5e Guest 冷启动与普通路径内存优化 | `NOT_STARTED` | Codex | 把 Agent/vsock 提前并缩短 kernel/init 关键路径；删除无收益的 Guest/worker 私有常驻页 | VMM→vsock 串行 P95≤950ms、并发≤1050ms；同口径 20 Pod 稳态 Host cgroup 均值≤100MiB/Pod，且节点 MemAvailable 差值摊销相对 S5.5a 下降≥15%或≤100MiB/Pod；能力冒烟零回退 |
| S5.5f 端到端门禁与回归 | `NOT_STARTED` | Codex | 证明局部收益转化为 Kubernetes Ready 延迟与可持续密度 | 串行 P95≤1.5s；5×10 并发 P95≤1.8s、增量≤300ms；100 Pod 报告启动/稳态/峰值资源；受影响 E2E 零新增失败、最终 exact-zero |

### S5.4a 已确认的 worker 通信与所有权边界

| 对象/接口 | 唯一 owner | 约束 |
|---|---|---|
| Kubernetes Pod parent cgroup | kubelet | Cube 只读，不创建、不写、不删除 |
| sandbox leaf/scope | CubeShim | 从标准 CRI `cgroup_parent` 和 sandbox ID 推导；CubeShim 以一次 systemd D-Bus placement 创建并回收 |
| RuntimeResource lease、Guest assets、TAP/network attachment、shared root | Cubelet | 只通过既有 `RuntimeResource` 与 FD handoff 服务暴露给 CubeShim |
| VMM、vCPU、Guest memory、virtiofs、设备生命周期 | cube-vmm-worker | 每 Pod 一个进程，只接受 CubeShim IPC；不链接 Cubelet client，不持有 RuntimeResource 凭据 |
| Sandbox/Task 状态、Guest Agent 操作、持久 lifecycle record | CubeShim | containerd 的唯一 Cube 适配和编排入口；Cubelet 与 worker 都不复制该状态机 |

普通启动按以下顺序线性化：CubeShim 先调用 Cubelet `PrepareSandbox` 并取得 lease/assets/TAP FD，持久化 VM INTENT 与带 generation/epoch/launch nonce 的 worker spawn INTENT，再以启动 gate 拉起 worker；CubeShim 将 worker PID 原子放入 sandbox leaf 并通过 PID start-time、executable、`/proc/<pid>/cgroup`、nonce 和 cgroup inode 回读身份，确认完成前 worker 不得创建 VMM thread、vCPU 或 Guest memory；随后 CubeShim 只通过 Unix socket `SCM_RIGHTS` 交付 TAP/设备 FD 和启动配置，解除 gate，等待 worker `Ready`，最后继续由 CubeShim 直接操作 Guest Agent。所有 FD 默认 `CLOEXEC`，child `pre_exec` 只保留 stdio 与控制/事件 child endpoint，worker 入口重新设置 `CLOEXEC`；TAP/设备 FD 不跨 exec。

worker 正常退出由 CubeShim 等待并完成 Cubelet `ReleaseSandbox`；worker 异常退出使 Sandbox 明确失败并进入幂等清理。S5.4b 不实现替代 Shim 重连：CubeShim 异常退出时，worker 由 parent-death signal/控制 EOF 自退，watchdog/reaper 只按 durable PID/start-time/executable/cgroup/nonce/epoch 精确回收并释放 RuntimeResource，随后由 kubelet 重建 Pod。Cubelet 重启不影响已运行 worker，CubeShim 使用 lease/generation 做 `Inspect`/重试。以后增加 Restore/Snapshot/Pause/Resume 时扩展 CubeShim↔worker 协议，仍不新增 worker↔Cubelet 控制面。


### 目标

形成可安装、可回滚、可重复演示的 Kubernetes runtime PoC，并给出是否进入生产化的证据。

### 工作项

- 节点安装/卸载、containerd 配置合并、RuntimeClass、label/taint 和版本兼容检查。
- runc/Cube 混部、cordon/drain、滚动升级和回滚。
- Kubernetes Node E2E/Conformance 结果分类。
- 多容器、PVC、监控、故障恢复和升级的完整回归。
- 性能、密度和稳定性测试。

### 验收标准

- 在至少 5 节点集群可重复安装、升级、回滚；现有 containerd 配置不被覆盖。
- runc 系统 workload 与 Cube Pod 同时稳定运行。
- 单节点 100 Cube Pods、10 并发创建完成测试，记录 P50/P95/P99、失败率和资源开销。
- 运行 24～72 小时 churn/soak，无持续资源泄漏或状态漂移。
- Node E2E/Conformance 每个失败项都有分类和链接，不用笼统豁免。
- 形成 PoC 验收报告：支持矩阵、已知限制、升级/回滚步骤和生产化建议。
- 100 节点验证是否执行取决于资源条件；未执行时明确记录为生产化前置项，不把它算作 PoC 通过证据。

## 11. S6：Template、Snapshot、Pause 与 Resume
> Milestone 状态：`NOT_STARTED`。S5.5 完成普通冷启动优化后再进入 S6；S6 不改写已验收的 worker 普通路径。worker IPC 只预留版本化扩展能力，不在 S6.1 前冻结快照制品或恢复语义。

| Work Stage | 状态 | Owner | 已完成 | 验收证据 | 下一步 |
|---|---|---|---|---|---|
| S6.1 模板、快照与暂停恢复设计 | `NOT_STARTED` | Codex/用户 | — | — | E2E 后确认 RuntimeTemplate、PodSnapshot、同 Pod Pause/Resume 的状态模型、切点、worker IPC 扩展、CRD/annotation、卷、分发、保留和失败语义 |
| S6.2a RuntimeTemplate artifact 与恢复链路 | `NOT_STARTED` | Codex | — | — | 在 `CreateSandbox` 前的空白 Guest/Agent 切点制作节点本地不可变模板，worker 以版本化 IPC 恢复，miss/corrupt/incompatible 明确 fallback 或 fail-fast |
| S6.2b 新 Pod 身份与设备动态注入 | `NOT_STARTED` | Codex | — | — | 恢复时注入新 UID、sandbox ID、vsock、TAP、Pod IP、hostname、DNS、namespace、rootfs、volumes、时间和熵；50 串行与 10 并发不得继承旧身份或数据 |
| S6.2c RuntimeTemplate 性能、密度与 overhead 标定 | `NOT_STARTED` | Codex | — | — | 完成一秒门禁、1/5/20/100 Pod 资源曲线和 RuntimeClass CPU/memory overhead 最终值；模板命中、miss 和普通 fallback 分开报告 |
| S6.3 显式 Snapshot 启动新 Pod | `NOT_STARTED` | Codex | — | — | 通过 CRD 管理制品、Pod annotation 引用不可变 digest，恢复多容器文件系统/进程状态和新身份 |
| S6.4 Pause/Resume | `NOT_STARTED` | Codex/用户 | — | — | S6.1 决定是否纳入当前 PoC；如实现，在显式 Snapshot 启动稳定后验证同 Pod 短时暂停恢复和失败收敛 |


### 目标

在 worker 普通启动和标准 Pod 生命周期稳定后，增加两层快照能力：runtime template 只保存无 Pod 身份的 Guest/Agent 基线，用于一秒启动；显式 Pod snapshot 保存已定义的一致性状态，用于用户指定从快照创建新 Pod。

### 工作项

- S6.1 在 Node E2E 后冻结三类不可混用的状态模型：`RuntimeTemplate` 切在 Agent ready、`CreateSandbox` 之前；`PodSnapshot` 切在已定义的多容器一致性点；Pause/Resume 作用于同一个 Pod 实例。
- S5.4 只要求 worker 使用版本化 IPC、稳定设备槽位与显式 FD handoff，S6.1 再增加 Restore/Snapshot/Pause/Resume 操作和 artifact compatibility key；不得为快照提前阻塞普通启动 worker 拆分。
- 定义 `CubeSandboxSnapshot` CRD/controller；Pod annotation `cubesandbox.io/restore-from` 只引用 controller 已解析的不可变 digest。
- 生成 VM memory/device state、rootfs/写层引用和兼容性 manifest；明确 OCI image、Guest、Agent、worker、CPU/内存规格的匹配规则。
- runtime template 恢复时使用新的 worker、Pod UID、sandbox ID、vsock、TAP、Pod IP、hostname、DNS、namespace、rootfs 和 volumes，并重置时间与熵。
- 显式 Pod snapshot 是否保留进程状态、如何处理 writable layer、emptyDir、Secret/ConfigMap 和 PVC，由 S6.1 与用户确认；PVC 数据不默认复制进 VM artifact。
- 首个 PoC 使用节点本地不可变 artifact/cache；是否必须通过 COS 分发及 CSI VolumeSnapshot 协调由 S6.1 决定。
- Pause/Resume 在显式 Snapshot 启动稳定后再评估，不阻塞本轮三个硬目标。

### 验收标准

- S6.1 输出经用户确认的应用状态模型、切点、worker IPC 扩展、设备恢复模型、manifest schema、CRD/annotation 契约、卷与分发语义；未完成前不实现不可逆 artifact 格式和 S6.2～S6.4。
- RuntimeTemplate 恢复的新 Pod 使用新 UID、sandbox ID、Pod IP、hostname、DNS、namespace、rootfs 和 volumes；50 次串行与 10 并发无跨 Pod 残留，并满足 S5.4d 一秒门禁。
- S6.2c 在固定最终制品上报告 1/5/20/100 Pod 的 cgroup、节点 MemAvailable、进程 PSS、CPU、PID 和启动峰值；20 Pod 模板命中稳态的节点 MemAvailable 差值摊销目标≤60MiB/Pod，未达到时 S6.2 保持 `VALIDATING` 并给出私有/共享页归因。
- `RuntimeClass.overhead` 只依据 S6.2c 的启动峰值、稳态 P99、压力和功能回归标定；配置、scheduler accounting、Pod parent/leaf 上限与实测证据一致，不再把临时 PoC 值当成产品结论。
- 多容器 Pod 可制作显式快照并在兼容节点恢复为新 Pod；容器文件系统和进程状态符合 S6.1 定义的一致性级别。
- Secret 不进入 artifact；ConfigMap/Secret 使用新 Pod 当前投射；PVC snapshot/reference 可验证且失败时不修改原卷。
- 不兼容 CPU/Guest/Agent/worker/snapshot format 时在启动前明确拒绝。
- artifact 缺失、损坏、恢复中断和网络/卷重新绑定失败均回滚 worker、scope、TAP、mount 和 lease；重复请求幂等。
- 最终默认快路径重新通过 S5.3c Node E2E；显式 snapshot 路径完成多容器、网络、卷、身份、Secret、Shim/Cubelet/worker 重启与 exact-zero 专项。

## 12. Stage 执行与 Handoff

Stage 进度只记录在本文各 `Sx.x` 状态表中；活动 handoff 只保存当前工作入口，不再复制整项进度。详细规则见 [PoC Handoff 规则](../../dev/handoff-policy.md)。状态变化时按以下顺序更新：

1. 直接更新对应 `Sx.x` 行的状态、Owner、已完成内容、验收证据和下一步。
2. 在活动 handoff 中写当前 `Sx.x`、基线 commit、最后一项验证、阻塞和接手动作。
3. 在 `open-questions.md` 更新该 Work Stage 必须关闭的问题。
4. 附可复现命令和结果摘要；接手者先复现最后一项关键验证。

Work Stage 未达到全部验收标准时不能标记 `DONE`。允许以 `DEFERRED` 延期非关键项，但必须注明新的目标 Stage；会改变主架构或公共接口的问题不能带入不可逆实现。

GLM 在冻结分支和独立工作目录执行的全量 Node E2E 属于外部并行验证，不进入上述 Stage 状态，
也不作为 S5.5c～S5.5e 的进入或退出门禁。其报告只有在绑定 commit/artifact SHA、原始结果可
复验且归因审阅通过后，才作为 S5.5f 或 S6.2c 的补充回归输入；GLM 发现的问题先登记、复现和
归因，不能直接修改主线 Stage 状态。主线继续在 W2/W3 推进，避免与其使用的 W1 相互干扰。


## 13. 未确认问题记录规则

权威清单是 `docs/handoffs/kubernetes-runtime/open-questions.md`。新增问题使用连续 ID：

```text
K8S-OQ-009 | 问题 | 当前假设 | Owner | 最迟 Stage | OPEN | 需要的证据
```

状态流转：

```text
OPEN -> VALIDATING -> DECIDED
  └----------------> DEFERRED -> OPEN
```

- `OPEN`：知道问题，但还没有足够证据。
- `VALIDATING`：已经有 owner 和正在执行的探针/测试。
- `DECIDED`：证据和最终选择已写入最后一列，历史行保留。
- `DEFERRED`：当前 stage 不阻塞，并明确了新的解决 stage。

如果实测推翻本文档的假设，先更新问题记录和总体设计，再改实现；不允许让代码成为唯一的事实来源。
