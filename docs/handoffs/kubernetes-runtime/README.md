# Kubernetes RuntimeClass PoC Handoff

## 当前 Stage

S5.5d.2c-r1 首次正式跑数为 `FAIL`（reviewer P0/P1/P2=0/2/1），失败证据永久保留；
当前进入 S5.5d.3a 邻居可靠性修复。
S5.3、S5.3a、S5.3b、S5.3c、S5.4a～S5.4c 与 S5.5a～S5.5d.2b 均为 `DONE`。
用户决定先优化普通 OCI 冷启动，目标是串行 PodScheduled→Ready P95≤1.5s 并消除并发放大；
S5.5 完成后再进入 S6.1。不得回退已验收的普通 worker 启动路径。

## 基线

当前最后已提交实现为 `49313e43`；S5.5d.2b 已完成。W2 保留 containerd
`59a92496…` 与 RuntimeResource harness `b3822aa3…`，已部署 CubeShim/worker
`d044d841…`/`cd401d89…`，保持 Ready+cordoned；`RuntimeClass/cube` 保留。W3 是 Rust
精确源码构建机。W1 由 GLM 独立使用，主线未执行 TAT 或修改。

## 已完成

Kubernetes v1.36.4 官方 477 个 `[NodeConformance]` `It` 已完整执行和唯一归并：456
Passed、17 Failed、4 Skipped；Cube 可归因通过 453 项。17 个失败包括 16 个有明确后续
方案的架构差异和 1 个既有 kubeadm control-plane 测试环境限制；没有将其声明为全绿或
认证。最终 Device/PodResources 为 10/10 Passed、1 个无 SR-IOV VF 的条件 Skip。支持路径
发现的 Device、CPU/NUMA、route、stats、hostname、sysctl、SIGKILL 与 sidecar 等缺陷已修复。
同一 reviewer 终审 `PASS`（P0/P1/P2=0）。完整证据见
[S5.3 最终报告](./evidence/s5.3/s5.3b-nodeconformance.md)和
[477 项分类与失败分析](./evidence/s5.3/s5.3-nodeconformance-classification.md)。

S5.4b/c 已完成每 Pod `cube-vmm-worker` 拆分及普通启动快路径：正常启动不再执行
`systemctl show`；50 次串行与 5×10 并发成功率 100%、PullImage=0。串行
PodScheduled→Ready P95=1935.438ms、RunPodSandbox P95=1575.632ms。

S5.5 性能方案已冻结：依次执行逐 Pod tracing、RuntimeResource 跨 Pod 解锁、进程内 netlink、
持久化/cgroup 快路径、Guest cold boot 和端到端回归。并发新增 RunPodSandbox 平均 783ms 中
85.4% 位于 VMM 前；串行 RunPodSandbox 约 72% 位于 Guest 启动到 vsock。

S5.5a 已完成最终制品基线：worker 串行/5×10 Ready P95 为 1965.379/2899.045ms，trace
覆盖最低 99.77% 且开销低于 0.05%；worker/embedded 的 1/5/20 Pod×3 轮资源矩阵完成，
20 Pod 稳态 cgroup 为 104.664/99.989MiB/Pod。virtiofs 0/1/2 配对估计、生产制品恢复与
exact-zero 均通过；同一 reviewer 终审 `PASS`（P0/P1/P2=0）。详见
[S5.5a 最终基线](./evidence/s5.5/s5.5a-final-baseline.md)。

S5.5b 已把 adapter、Coordinator、Store 和 FD Registry 的跨 sandbox 大锁改为 keyed lock；
5×10 adapter lock-wait P95 从 232.910ms 降至 0.005ms，RuntimeResource P95 从
346.823ms 降至 138.400ms，Ready P95 从 2899.045ms 降至 2701.742ms。串行回退小于
0.4%；RuntimeResource restart、确定性创建中取消、trace-off 恢复和 exact-zero 均通过；
同一 reviewer 终审 `PASS`（P0/P1/P2=0）。详见
[S5.5b 最终证据](./evidence/s5.5/s5.5b-cross-sandbox-parallelism.md)。

S5.5c 已完成生产 netlink backend、command 回滚开关和单元/race/vet；云上 50 串行与 5×10
并发均 50/50 成功，network prepare P95 为 4.313/6.293ms，普通 netlink 路径 network exec=0，
当前 Cilium IPv4 的 DNS/PodIP/ClusterIP/NetworkPolicy/MTU、真实内核双 netns IPv4/IPv6、
RuntimeResource restart 和清理已经通过。累计 CRI→start-vm P95 仍为 429.479/965.868ms，
明确转交 S5.5d.1/d.2，不把它归咎于 netlink。真实 W2↔W3 Cube Pod 双向 PodIP、实际内核
部分失败注入、command↔netlink 完整往返、活动 Pod restart、最终 exact-zero 和包含完整
runner/源码的三份可反向校验 v6 证据包均已完成；独立 reviewer 终审 `PASS`
（P0/P1/P2=0），状态为 `DONE`。完整结果见 [S5.5c 最终证据](./evidence/s5.5/s5.5c-netlink-fastpath.md)。

S5.5d.1 修复版候选已把 external shim sandboxer 的 CNI ADD 与 `CreateSandbox` 改为默认关闭、
仅 Cube 开启的并行准备，`StartSandbox` 仍等待两者成功；任一分支失败均有取消/回滚。Cubelet
在 Pod netns 等待 CNI 地址/路由再建立 TAP。首次正式串行/5×10 各 50/50 成功，绝对
pre-Shim P95 为 75.812/147.511ms，达到≤80/150ms；Ready P95 为
1833.551/2297.276ms。网络、跨节点、containerd restart、严格 10/10 Pending 创建取消和双节点
exact-zero 均通过；同一 reviewer 终审 `PASS`（P0/P1/P2=0）。早期 `overlap-v1` 因 duration
结束点和回滚缺口已全部作废，不构成验收。详见
[S5.5d.1 证据](./evidence/s5.5/s5.5d.1-pre-shim-fastpath.md)。

S5.5d.2a 已删除 systemd 固定 4×20ms 稳定等待，保留 parent/leaf/PID 精确 identity readback；
Cubelet 新请求的 WAL 从 `INTENT→SHARED_ROOT→PREPARED` 收敛为 `INTENT→PREPARED`，旧记录仍可
恢复；TAP allocated 与 VM intent 合为一次原子提交。runtime cleanup queue 现在也负责 Shim 在
worker 启动前崩溃时遗留的本地 VM 目录，并以严格 containerd ID 语法在任何 path join 前拒绝
root alias。W3 utils/Host 测试 1/1、82/82，W2 普通和 pre-start-vm SIGKILL 两条链分别独立
13 项 exact-zero；单样本 Shim create→start VM 为 134.482ms。同一 reviewer 终审 `PASS`
（P0/P1/P2=0）。完整证据见
[S5.5d.2 证据](./evidence/s5.5/s5.5d.2-durable-create-fastpath.md)。

S5.5d.2b 已把新 Host controller journal 升级为 schema v2：四个 controller 在任何外部写前一次
持久化 old/target 与 owner identity，全部幂等 write/readback 后一次提交完成；schema v1 继续可
恢复，PREPARED 第三值进入 durable DEGRADED。controller journal 正常路径由 10 次降为 2 次；
本地 Host 测试 96/96，W2 普通、controller 中点 SIGKILL、worker kill/restart 及五次 13 项
exact-zero 全部通过。单样本 Shim create→start VM 为 107.591ms；正式 P95 留给 d.2c。
同一 reviewer 终审 `PASS`（P0/P1/P2=0）。完整证据仍见
[S5.5d.2 证据](./evidence/s5.5/s5.5d.2-durable-create-fastpath.md)。

S5.5d.2c-r1 已在同一 `49313e43`/制品上完成首次串行 50 与 5×10 并发。串行
Shim→VMM/CRI→VMM P95=111.431/182.333ms，通过局部门禁；并发为
385.254/489.974ms，超过 150/300ms，且一次 Cilium gateway neighbor 20ms 超时导致
RunPodSandbox 重试、round spread=11.184s。Ready P95 为 1.714/2.255s。reviewer 明确判定
`FAIL`，不得拼接旧串行与新实现并发结果。证据和后续拆解见
[S5.5d.2 证据](./evidence/s5.5/s5.5d.2-durable-create-fastpath.md)。

## 未完成

- S5.5d.3a～c、S5.5e～S5.5f 普通冷启动性能优化。最终退出门禁为串行
  P95≤1.5s、5×10 并发 P95≤1.8s，冲刺并发 P95≤1.5s。
- S6.1、S6.2a～c、S6.3～S6.4：模板、快照与暂停恢复设计和实现；S6.2c 负责模板路径密度和
  RuntimeClass overhead 最终标定。
- S4.1～S4.3：状态重连、Reconcile 与可观测性，权威计划中仍为 `NOT_STARTED`。
- S5.4d：通过 RuntimeTemplate 把预拉取镜像的 PodScheduled→Ready P95 收到 1 秒内，
  并对成为默认路径的改动重跑 Node E2E。
- S5.1/S5.2：安装共存、升级和回滚产品化；完整多节点 soak/PVC 验收也尚未完成。
- S5.3 已解释差异保留在 `K8S-OQ-025/034/035/036/037/038`，由 S6.1 决定实现或专用
  fixture/hardware 的闭环方式。

## 验证

- 477 项归并输出 SHA-256：`fe78040305a0f7bc58d8a2bc569d5a755c5a02d7bca8a0fa1466d0cbc0fd2424`。
- 477 项已归入 8 个能力域、63 个上游测试文件；分类与失败分析经同一 reviewer
  `PASS`（P0/P1/P2=0）。
- Device/PodResources：`inv-389w3ggrk9`；privileged 定向终审：`inv-689xwbgpag`。
- 双 Worker exact-zero：`inv-98a04qgm41`。
- W1/W2 Ready、kube-system 非 Ready=0、e2e namespace/policy=0：`inv-a8a04sguer`。
- S5.5a W2/控制/本地工具权威证据包 SHA-256 分别为 `38841b44…`、`00cf570e…`、
  `8bcd0b24…`；全部从 COS 反向下载校验，local-tooling-v2 内嵌 37 项 checksum 全部通过。
- S5.5a 生产恢复 `inv-a8cm3egxjv`；W2 exact-zero `inv-08cm4gg07f`；控制端目标 W2
  Ready 且测试对象归零 `inv-a8cm6pgic4`；reviewer `PASS`（P0/P1/P2=0）。
- S5.5b W2/控制证据包 SHA-256 为 `c2d802a8…`/`189362f2…`，均已从 COS 反向下载核验；
  trace-off 恢复 `inv-68cp87gx7f`，最终 exact-zero `inv-88cp8q0ni2`/`inv-08cp8pg2rr`；
  reviewer `PASS`（P0/P1/P2=0）。
- S5.5c 三份 v6 包的外层/内层 checksum、credential scan、command/netlink 往返、restart、
  双节点 exact-zero 均通过；独立 reviewer `PASS`（P0/P1/P2=0）。
- S5.5d.1 修复版正式串行/并发分析为 `inv-a8dgrtgtav`/`inv-a8dgur0vux`，冻结门禁均通过；
  W2/控制/W3 证据包 SHA-256 为 `3a5aa93f…`/`4d299303…`/`4dde7923…`，均通过源端
  credential/内层 checksum、COS 反向下载、Builder 解包复验和本地逐字节分析复算；同一
  reviewer 终审 `PASS`（P0/P1/P2=0）。
- S5.5d.2a 最终 W2/W3/控制证据包 SHA-256 为 `bd8f6325…`/`c61b7917…`/`a09632b0…`，
  均从 COS 反向下载复核；W3 build/audit 为 `inv-b8dpx40cud`/`inv-98dq3g0q8d`，普通和注入
  exact-zero 为 `inv-88dq7p0ft4`/`inv-38dqbpgtrx`，同一 reviewer `PASS`（P0/P1/P2=0）。
- S5.5d.2b 最终 W2/W3/控制证据包 SHA-256 为 `42bb35c1…`/`9bf89922…`/`c2a98ba2…`，
  均从 COS 反向下载复核；W3 build/audit 为 `inv-38drh50kue`/`inv-a8drnmgfhi`，五次独立
  exact-zero 均为 13 项全零，同一 reviewer `PASS`（P0/P1/P2=0）。
- 实现 commit 为 `49313e43`；`git diff --check`、
  credential scan、`make handoff-validate` 已通过。

## 阻塞

GLM 的冻结分支全量 Node E2E 是独立并行验证，不占用主线 Stage，也不阻塞 S5.5；只有绑定
commit/artifact SHA 且原始结果可复验后才接收入回归证据。GLM 当前使用的 W1 可处于
NotReady，主线不得恢复或修改 W1。当前明确卡点是 delayed gateway neighbor 的首次 CRI
可靠性，以及“network prepare 完成后才启动 VMM”的顺序导致并发 CRI→VMM 无法满足 300ms。

## 受保护路径

`CubeShim/`、`Cubelet/`、`agent/`、`deploy/kubernetes/runtimeclass/`、
`deploy/kubernetes/smoke/`、`tests/e2e/kubernetes-runtime/` 和本 handoff bundle。只操作本
PoC 创建的云资源；所有带“勿删”的 CVM/TKE/COS 资源不得删除。不得覆盖既有证据、Guest
assets 和回滚副本；不得在仓库或 handoff 中记录凭证、token、私钥或 kubeconfig 内容。

## 下一步

1. S5.5d.3a 用 context-bounded probe/poll 修复 delayed gateway neighbor，完成 10 并发无 retry、
   永久缺失超时回滚、exact-zero，并取得同一 reviewer PASS。
2. S5.5d.3b 让 VMM preboot 与 network async finalize/attach 重叠；StartSandbox 返回前 join
   VMM-ready 与 network-committed，任一分支失败须取消另一分支并可恢复清零。
3. S5.5d.3c 在同一新 commit/artifact/analyzer 上重跑完整 50 串行与 5×10 并发及功能/故障回归。
4. S5.5f 达到串行 P95≤1.5s、并发 P95≤1.8s，并完成受影响 Node E2E 回归；完整方案见
   [S5.5 性能优化方案](../../zh/dev/kubernetes-runtime-performance-s5.5.md)。
5. S5.5 后进入 S6.1；按 S6.2a 恢复链路、S6.2b 动态身份、S6.2c 性能/密度/overhead 顺序
   完成 RuntimeTemplate 和 S5.4d 一秒门禁，再进入 S6.3 PodSnapshot。
