# S5.5 Kubernetes 普通冷启动性能优化方案

## 1. 目标与边界

S5.5 在不使用 RuntimeTemplate、VM Snapshot 或预创建 Pod VM 的前提下，优化缓存 OCI 镜像的
普通冷启动路径。阶段主目标是把单容器、无 probe Pod 的 `PodScheduled→Ready` 串行 P95 从
约 1.94 秒降到 1.5 秒以内，同时消除 10 Pod 并发时约 1 秒的额外放大。

本阶段不修改“一 Pod 一个 Cube VM、Pod 内容器共享 VM/网络”的架构，不合并 CubeShim 与
`cube-vmm-worker`，不提前冻结 S6 的模板、PodSnapshot 或 Pause/Resume 制品格式。最终一秒目标
仍由 S6.2 RuntimeTemplate 和 S5.4d 最终门禁关闭。

## 2. 当前基线与判断

最近一次可复现基准来自 `fa278467` 制品，镜像已经缓存且 `PullImage=0`：

| 场景 | PodScheduled→Ready P50/P95/P99 | RunPodSandbox P50/P95/P99 |
|---|---|---|
| 50 次串行 | 1911.587 / 1935.438 / 1949.250 ms | 1553.762 / 1575.632 / 1592.374 ms |
| 5 轮×10 并发 | 2719.128 / 2907.534 / 2970.607 ms | 2366 / 2564 / 2628 ms |

并发 RunPodSandbox 是用同一节点 containerd 与 CubeShim 日志按 sandbox ID 重建的逐 Pod
wall-clock 分布；旧报告中的 2236.777～2415.862 ms 是每轮均值，不能代替逐 Pod 分位数。

RunPodSandbox 的平均增量为 783 ms，其中 VMM 启动前增加 669 ms，占 85.4%；Guest 冷启动增加
111 ms，占 14.1%；Agent ready 之后仅增加约 3 ms。当前首要瓶颈因此是 RuntimeResource 的跨
Pod 串行、外部 `ip/tc/nsenter` 进程和多层同步持久化，`cube-vmm-worker` 自身不是主瓶颈。

当前最终代码把无显式资源 Pod 的默认 VM 内存从 256 MiB 调整为 512 MiB。S5.5a 必须先使用
最终 Host/Guest 制品重新建立基线；上述数字只作为回归参照，不作为当前二进制的性能承诺。

W1 的方向性资源探针显示，5 个缓存 BusyBox Cube Pod（每 Pod request 10m/16Mi、limit
100m/64Mi）稳定 30 秒后，Host Pod cgroup 为 104.55～104.69MiB/Pod，节点
`MemAvailable` 差值摊销约 119.4MiB/Pod，worker PSS 约 102MiB、Shim PSS 约 6.1MiB，空闲
CPU 约 1.7m/Pod，启动累计 CPU 约 1.08 CPU-s/Pod，约 24 PID/Pod。该探针没有完成同节点
embedded/worker、1/5/20 密度和最终制品 A/B，只用于确定 S5.5a 的测量范围，不作为 overhead
或优化验收值。历史 Cube PVM RuntimeTemplate 报告的 27～34MB/Sandbox 也只作方向参照，不能
与当前 Kubernetes 普通冷启动直接相减。

## 3. 阶段门禁

所有门禁均使用同一观察进程的 `CLOCK_MONOTONIC`、nearest-rank 分位数、缓存固定 digest 的
BusyBox 镜像、`imagePullPolicy: Never`、单容器、无 init/sidecar/probe，并要求 kubelet 指标和
containerd 日志共同证明 `PullImage=0`。

### 3.1 必须达到的 S5.5 退出门禁

| 场景 | PodScheduled→Ready | RunPodSandbox | 其他条件 |
|---|---:|---:|---|
| 50 次串行 | P95 ≤ 1500 ms，P99 ≤ 1700 ms | P95 ≤ 1250 ms | 50/50 成功 |
| 5 轮×10 并发 | P95 ≤ 1800 ms，P99 ≤ 2000 ms | P95 ≤ 1500 ms | 50/50 成功 |

并发 P95 相对串行 P95 的增量不得超过 300 ms。若串行达标但并发未达到上述门禁，S5.5 不能
标记 `DONE`，必须保留为 `VALIDATING` 并记录剩余阶段归因。

### 3.2 冲刺目标

- 50 次串行和 5×10 并发的 `PodScheduled→Ready P95` 均不超过 1500 ms。
- 两种场景的 `RunPodSandbox P95` 均不超过 1250 ms。
- 不通过并发限流、延迟创建或减少样本数量隐藏排队时间。

### 3.3 串行预算

| 阶段 | P95 预算 | 当前参考 P95 |
|---|---:|---:|
| CRI receive→`start vm start` | 220 ms | 436 ms |
| `start vm start`→vsock ready | 950 ms | 1134 ms |
| vsock ready→RunPodSandbox return | 25 ms | 约 19 ms |
| RunPodSandbox 外围：Scheduled→CRI + container + Ready 传播 | 250 ms | 约 360 ms |

前三项合计目标约 1195 ms，为 `RunPodSandbox P95≤1250ms` 留出抖动空间；外围预算使端到端
P95 保持在 1500 ms 内。分位数不能直接逐项相加，预算只用于定位和阻止局部优化掩盖端到端
回退，最终门禁始终以逐 Pod 端到端样本为准。

### 3.4 10 并发预算

| 阶段 | P95 预算 |
|---|---:|
| CRI receive→`start vm start` | 300 ms |
| `start vm start`→vsock ready | 1050 ms |
| vsock ready→RunPodSandbox return | 30 ms |
| RunPodSandbox 外围 | 300 ms |

## 4. 子阶段与验收标准

### S5.5a：最终制品基线与逐 Pod 可观测性

目标：让每个 Pod 的排队、持锁、持久化、网络、worker、Guest 和 kubelet 外围耗时都可独立
归因，然后在 W2 上重建最终制品的串行/并发基线。

工作项：

- 所有组件记录同一 host `CLOCK_MONOTONIC` 时间、Pod UID、sandbox ID 和 operation ID。
- 增加 CNI ADD、CubeShim CreateSandbox、Host placement、journal commit、RuntimeResource RPC、
  Coordinator/Store/adapter lock wait、每个网络步骤、worker fork/Hello/placement、CreateVm、
  BootVm、vsock、Agent、CreateContainer、StartContainer 和 Ready 传播时间戳。
- runner 保存每个 Pod 的真实 RunPodSandbox 时延；禁止把轮均值复制为逐 Pod 样本。
- 并发窗口采集 CPU runqueue、上下文切换、CPU/memory/I/O PSI、块设备延迟和 systemd D-Bus
  延迟。
- 在同一 W2、同一 Guest/Host artifact、同一 workload 下完成 worker cold 与 embedded cold A/B；
  若历史 RuntimeTemplate 制品不能在相同环境运行，只保留为“非同口径参考”，不得计算优化率。
- 对 1/5/20 Pod 分别采集稳定 30 秒后的 Pod/leaf cgroup `memory.current`/`memory.peak`、节点
  `MemAvailable` 差值、worker/Shim/virtiofs PSS、CPU、PID 和启动累计 CPU；记录 page cache
  warmup、采样顺序和三轮重复值。

验收：

- 最终 Host/Guest SHA 与测试报告绑定；50 串行和 5×10 并发均 100% 关联到唯一 sandbox。
- 每个 RunPodSandbox 的阶段顺序单调，已归因区间覆盖总时长至少 95%，未知区间单列。
- 输出 P50/P95/P99、均值、最大值、lock wait、fsync 次数/耗时和资源压力原始数据。
- 输出 worker cold/embedded cold 的同口径延迟和资源 A/B，以及 1/5/20 Pod 的总量、边际量和
  置信区间；能区分 Guest private dirty、共享文件页、Shim/worker/virtiofs 和 Host kernel。
- 本子阶段只加观测，不接受端到端 P95 回退超过 3%。

### S5.5b：移除 RuntimeResource 跨 Pod 串行

目标：同一 sandbox 保持线性化，不同 sandbox 的 Prepare、Inspect、OpenTap 和 Release 可以并行。

工作项：

- 把 adapter 节点级大锁改为带引用计数的 per-sandbox keyed lock。
- `tapFiles` 使用独立短临界区；网络操作、文件 I/O、FD duplicate 不持有全局 map 锁。
- Coordinator 和 Store 改为 per-sandbox 锁或固定分片锁；registry map 锁只保护内存发布。
- 所有 fsync、RuntimeResource RPC 和网络操作都移出跨 sandbox 临界区。

验收：

- race/unit 测试证明同 sandbox Prepare/Release/OpenTap 仍线性化，跨 sandbox 操作真实重叠。
- 10 并发时 adapter 跨 sandbox lock-wait P95≤10 ms，成功率 100%。
- 串行 Ready 与 RunPodSandbox 相对 S5.5a 回退均不超过 3%，并发 RuntimeResource P95 明确下降。
- Cubelet/RuntimeResource restart、创建中取消和重复 Release 后全部资源 exact-zero。

S5.5b 实测证明 keyed lock 已消除，但 absolute VMM start 展开仍受 CNI 和持久化阶段影响。
S5.5c 实测进一步证明网络 backend 的直接耗时已经达标，但原先把整个
`CRI receive→start vm` 压入网络阶段的累计门禁无法归因：串行/并发 P95 分别仍为
429.479/965.868ms，其中主要剩余时间位于 Shim 连接前和 durable create/cgroup 路径。该累计
门禁按 reviewer 要求重新划归 S5.5d.1/S5.5d.2；S5.5c 必须如实记录累计 checkpoint 未通过，
不能用 network prepare 的局部通过掩盖。S5.5d 总门禁仍为串行≤220ms、并发≤300ms，并最迟
在 S5.5d.2 重验每轮 10 Pod 的 absolute VMM start 展开≤250ms。S5.5f 最终端到端门禁不变。

### S5.5c：进程内 netns/netlink 网络快路径

目标：移除热路径中的 `nsenter/ip/tc/ping` 派生进程和重复 JSON 状态发现。

工作项：

- 使用锁定 OS thread 的 netns 切换和 netlink 完成 link/address/route/neighbor 查询。
- 使用 netlink 创建 multi-queue/vnet_hdr TAP、ingress qdisc 和双向 mirred filter。
- 邻居未解析时使用受控 netlink/探测逻辑；保留 IPv4、IPv6、MTU、多路由语义。
- 过渡期间保留旧 command backend 作为节点配置回滚项，验收后默认使用 netlink backend。

验收：

- 当前 PoC 选定的 Cilium IPv4 集群上，ClusterIP、真实跨节点 PodIP、NetworkPolicy、DNS 和
  MTU 专项无回归；生产 netlink backend 还需通过两个真实 netns 的 IPv4/IPv6、并发和故障
  回滚内核测试。完整 Cilium 双栈集成留到 S5.5f 网络兼容矩阵，不把单栈环境伪装成双栈通过。
- trace 证明普通启动不再 exec `nsenter`、`ip`、`tc` 或 `ping`。
- RuntimeResource network prepare 串行 P95≤25 ms、10 并发 P95≤50 ms。
- command backend 可通过节点配置回滚，且回滚和再次切回 netlink 都通过相同冒烟与清理检查。
- 失败回滚后 TAP、qdisc/filter、netns FD 和 lease 全部归零。

`CRI receive→start vm` 在本阶段作为非阻断累计 checkpoint 报告；若超过串行 300ms/并发
450ms，必须带不重复计费的偏序分段转交 S5.5d.1/S5.5d.2，不能扩大 S5.5c 的实现边界。

### S5.5d.1：CRI/CNI dispatch 与 Shim 连接前快路径

目标：先建立允许 CNI/controller 并行的偏序时间线，再消除 `RunPodSandbox` 接收至 CubeShim create 开始前的排队、
重复配置发现和非必要进程/IPC；不在本子阶段修改 durable journal 或 Host cgroup 状态机。

工作项：

- 补齐同一时钟域的 CRI receive、CNI begin/end、shim resolve/spawn/connect 和 Shim create begin
  事件；分别验证 CNI 链与 controller 链的单调性，显式计算重叠，不再把并行区间相加成“上界”。
- 修正性能 runner：新 run 启动时截断 append-only manifest/output，结果中写入真实分位数算法，
  并在验收前断言 manifest、Pod UID、sandbox ID 的期望数和唯一数，禁止复用目录污染样本。
- 区分 containerd CRI 排队、CNI、shim manager 查找/连接和新 Shim 拉起；只优化 Cube 可控且有
  实测占比的步骤。
- 保持 RuntimeClass handler、sandbox ownership 和 containerd shim v2 契约不变。若实测 CNI 是冻结
  绝对门禁的主因，可为 external shim sandboxer 增加默认关闭的 opt-in：先 dispatch CNI，再并行
  `CreateSandbox`，但必须等二者都成功后才 `StartSandbox`，并完整处理任一分支失败的取消/回滚；
  runc 和其他未开启 runtime 的既有顺序不得改变。

本阶段同时保留两条口径：`CRI receive→Shim create begin` 是冻结硬门禁；顺序路径的
`Cube-controlled pre-Shim` 可扣除同一 Pod、同一单调时钟上与 controller 相邻的 CNI ADD，
只用于内部归因。并行路径不能再次扣除已经重叠的 CNI 时间，此时诊断值等于绝对值。不得扣除
CRI 排队、containerd dispatch、Shim resolve/spawn/connect，也不得用限并发或删样本降低分位数。
S5.5f 仍以完整
`PodScheduled→Ready` 验收，CNI 不从任何最终 SLO 中排除。

验收：

- 50 串行和 5×10 并发样本均能一一绑定 Pod UID、sandbox ID、Shim PID 和 worker PID；CNI 与
  controller 两条链各自单调，重叠量显式记录，controller 关键路径总和与绝对 pre-Shim 残差为 0。
- 绝对 `CRI receive→Shim create begin` 串行 P95≤80ms、10 并发 P95≤150ms；成功率 100%；
  Cube-controlled 数值只做根因定位。
- DNS、ClusterIP、跨节点 PodIP、NetworkPolicy、创建中取消、containerd restart 和 exact-zero
  无回退。

修复版 `overlap-v2` 首次正式 50+50 结果为串行/并发绝对 pre-Shim
P95=75.812/147.511ms，均通过≤80/150ms；Ready P95=1833.551/2297.276ms，继续转交
S5.5d.2/e/f。早期 `overlap-v1` 因 duration 结束点和 Create 后、Start 前回滚缺口全部作废。
同一 reviewer 终审 `PASS`（P0/P1/P2=0），实现 commit 为
`8129b3a9451b21f496f75d3faa8d8ca72ff3b265`。
完整原始证据和失败回滚语义见
[S5.5d.1 阶段证据](../../handoffs/kubernetes-runtime/evidence/s5.5/s5.5d.1-pre-shim-fastpath.md)。

### S5.5d.2：durable create、持久化与 Host cgroup 快路径

目标：保留崩溃恢复能力，同时减少每 Pod 原子文件提交、目录 fsync 和 systemd placement 固定等待。

工作项：

- RuntimeResource adapter 用包含完整 old/target 的 INTENT 加最终 PREPARED，减少中间重复提交。
- Host controller journal 一次记录四个 controller 的 old/target，完成写入和精确回读后一次提交
  COMMITTED；恢复时按实际 old/target 继续或回滚。
- 评估 1～2 ms 有界 group commit，减少并发目录 fsync 尾延迟。
- 优先使用 pidfd、cgroup inode 和 `/proc/<pid>/cgroup` 的事件/精确回读替代固定 5×采样；验证
  可行后评估 `clone3(CLONE_INTO_CGROUP)`，保留 systemd D-Bus fallback。

验收：

- 正常路径 `systemctl show=0`，每 Pod journal commit/fsync 数量和累计耗时明确下降。
- 全部既有 atomic persistence failpoint、worker/Shim kill、containerd/Cubelet restart 测试通过。
- 不接受通过关闭 fsync、把状态放入 tmpfs 或删除精确 readback 得到的性能结果。
- `Shim create begin→start vm` 串行 P95≤140ms、10 并发 P95≤150ms。
- `CRI receive→start vm` 串行 P95≤220 ms、10 并发 P95≤300 ms。
- 每轮 10 Pod 的 absolute VMM start 展开≤250 ms。

首次正式 d.2c-r1 在 `49313e43` 上得到串行 111.431/182.333ms，但并发
385.254/489.974ms；一次 gateway neighbor 超时还造成 CRI retry 和 11.184s round spread。
同一 reviewer 判定 `FAIL`。Cilium CNI ADD P95=431.321ms，且成功样本全部在 network prepare
完成后才 start-vm；因此不能只靠 group commit 或放宽门禁关闭本阶段，后续增加以下三个子阶段：

### S5.5d.3：VMM 与网络关键路径解耦

- **S5.5d.3a neighbor reliability**：把 gateway neighbor 获取改成 context-bounded probe/poll，
  覆盖延迟超过 20ms 后成功、永久缺失时有界失败并完整回滚、10 并发无 CRI retry 与 exact-zero。
- **S5.5d.3b VMM/network overlap**：优先在 TAP FD 可用后立即 start VMM，把邻居解析、TC redirect
  和 network commit 与 Guest boot 重叠；若该边界不能满足门禁，再使用 hypervisor NIC hotplug
  实现无 NIC preboot。`StartSandbox` 返回前必须 join VMM-ready 与 network-committed；任一分支失败
  必须取消另一分支，状态机可在 Shim/containerd/RuntimeResource restart 后收敛。
- **S5.5d.3c formal close**：同一新 commit/artifact/analyzer 重新执行完整串行 50、5×10 并发、
  网络/跨节点/NetworkPolicy、创建中取消、service/worker/Shim kill 与双节点 exact-zero。不得拼接
  不同实现结果；d.2 原门禁 140/150、220/300、spread≤250ms 与 no-retry 全部保持不变。

### S5.5e：Guest 冷启动、内存与 worker/VMM 细化

目标：在不使用模板和快照的情况下，把 Guest 冷启动 P95 压到预算内。

工作项：

- 采集 kernel boot milestones、initcall、Agent main/vsock listen 的单调时间线。
- 让 Agent/vsock readiness 位于 Guest 启动关键路径最前，非启动必需初始化转到 ready 之后。
- 清理 Guest kernel/initrd 中本 PoC 路径不需要的启动项，评估 initrd 压缩、页面预热和共享只读
  asset page cache；不得删除已通过 Node E2E 所需的模块和能力。
- 逐页归因 Guest kernel/Agent/virtiofs/VMM 的 private dirty 与匿名内存，移除重复 buffer、过大的
  预分配和非启动必需常驻页；保持 OCI lower layer、kernel/initrd 和只读 asset 的 Host page cache
  可共享，不以降低 VM 可用内存或规避工作负载 limit 伪造收益。
- worker 只优化已测量的 fork/Hello/FD gate/placement；不以重写 worker 边界替代主要优化。

验收：

- `start vm→vsock ready` 串行 P95≤950 ms、10 并发 P95≤1050 ms。
- LaunchVmm 串行 P95≤20 ms、10 并发 P95≤40 ms。
- 同 S5.5a 口径的 20 Pod 稳态 Host cgroup 均值≤100MiB/Pod；节点 `MemAvailable` 差值摊销
  相对 S5.5a 下降≥15%或达到≤100MiB/Pod（二者任一）；启动时 memory peak、CPU 和延迟不得
  因换取稳态数字出现未解释回退。
- Guest capability、网络、volume、privileged、device、sysctl、hostname 和多容器冒烟无回归。
- 新 Guest asset 使用独立 digest，可一条命令切回基线版本。

S5.5e.3 实测采用两项相互独立的优化：PVM Guest 关闭运行时 BTF（保留 DWARF、BPF/JIT、
kallsyms、kprobe/uprobe、ftrace、perf 和 livepatch），以及默认启用 size=0 的 virtio-balloon
free-page reporting。后者可通过 containerd 与 watchdog 环境变量
`CUBE_FREE_PAGE_REPORTING=0` 移除设备并恢复旧 PCI 拓扑；修改后需重启这两个服务，只影响
新建 Pod，运行中的 VM 不热切换设备。

20 Pod 三轮稳态 `memory.current` mean 为 `94.857/94.859/94.860MiB/Pod`，相对
S5.5e.1 的 `104.93MiB/Pod` 下降约 `9.6%`，通过 `≤100MiB/Pod` 门禁。50 次串行正式
`PodScheduled→Ready` P50/P95/max 为 `1222.148/1235.888/1254.664ms`，50/50 成功且
没有启动回退。free-page reporting 单独对从未分配过大量内存的 idle baseline 没有显著收益；
它的价值由 128MiB 两轮工作集压力后 Host PSS/cgroup 回落证明，不能与 BTF 常驻段节省重复
计算。完整能力、回退和 exact-zero 证据见
[S5.5e 阶段记录](../../handoffs/kubernetes-runtime/evidence/s5.5/s5.5e-guest-cold-memory.md)。

### S5.5f：端到端门禁与 Kubernetes 回归

目标：确认局部优化真实转化为 kubelet 观察到的 Ready 延迟，并关闭所有资源和功能回归。

工作项：

- 优化 Scheduled→CRI dispatch 和 RunPodSandbox return→Ready publish 中已测出的 Cube 可控部分。
- 执行 50 串行、5×10 并发、100 Pod 密度、创建中取消和连续 create/delete churn；100 Pod
  同时报告启动峰值与稳定 30 秒后的节点/cgroup/PSS/CPU/PID，不能只报告“成功创建”。
- 重跑受改动影响的 Node E2E 分片，不重跑与启动路径无关且已冻结的分片。

验收：

- 达到 3.1 的全部退出门禁，并报告 3.2 冲刺目标是否达到。
- 所有性能样本明确使用 `runtimeClassName: cube`，Sandbox/worker/VMM/Agent 日志形成一一对应链。
- 多容器、emptyDir、ConfigMap/Secret、PVC 冒烟和受影响 Node E2E 支持面零新增失败。
- 测试结束后 sandbox、worker、VMM、TAP、mount、CNI、active lease 和 reaper exact-zero。

## 5. 代码组织

| 改动 | 主要目录 | 提交边界 |
|---|---|---|
| 逐阶段 tracing/metrics | `CubeShim/`、`Cubelet/services/runtime/`、benchmark runner | 单独观测提交 |
| keyed lock 与 Store 分片 | `Cubelet/services/runtime/`、`Cubelet/plugins/cube/runtime_resource/` | 不混入网络实现 |
| netlink backend | `Cubelet/plugins/cube/runtime_resource/` | 独立 backend 和回滚开关 |
| journal/cgroup 快路径 | `CubeShim/shim/src/service/host_cgroup.rs`、Cubelet state | 每种状态机独立提交 |
| Guest boot | `image/`、`agent/`、Guest config | Host 与 Guest 制品分开 |
| runner 与门禁 | `tests/e2e/kubernetes-runtime/` | 不与性能实现混合 |

每个子阶段先冻结基线和目标，再提交实现，再运行专项、故障和 exact-zero 验收。若某项优化未使其
负责阶段的 P95 明显下降，回滚该项并记录测量结论，不把复杂度带入下一子阶段。

每个子阶段结束后由独立 reviewer 检查实现范围、原始数据、回归和资源归零。review 仍有 P0/P1
或验收证据缺口时，当前子阶段保持 `IN_PROGRESS/VALIDATING`，修复并复审；只有 reviewer 明确
给出 `PASS` 后才更新 stage/handoff、独立提交并进入下一子阶段。

## 6. S5.5 结束后的决策

- 达到必需门禁且冲刺目标达成：进入 S6.1，同时保留普通冷启动作为可靠 fallback。
- 达到必需门禁但并发仍高于 1.5 秒：进入 S6.1，RuntimeTemplate 同时负责最终并发和一秒目标。
- 未达到串行 1.5 秒：只有在证据证明剩余耗时主要是不可继续压缩的 Guest cold boot 时，才进入
  S6.1；否则 S5.5 保持 `VALIDATING`，不能把普通路径问题隐藏到模板路径。
