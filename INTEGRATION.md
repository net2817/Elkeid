# Elkeid 二开整合状态

审计日期：2026-11-23  
上游基线：[bytedance/Elkeid `main`](https://github.com/bytedance/Elkeid/tree/main)，`c906c512`  
本仓库：[net2817/Elkeid `main`](https://github.com/net2817/Elkeid/tree/main)，本轮审计的起始版本为 `e5873fe`。

目标仓库从上游 `main` 基线派生。审计开始时目标 `main` 为 `e5873fe`；下表列出已确认的上游分支代码导入。全分支账本记录尚未导入的公开分支功能和待评估项。

下表两项上游分支代码导入在审计开始前已存在。之后，目标仓库在 `plugins/driver/` 完成了基于 v3.0 RingSlot/SmithControl 接口的本地适配（事件读取、白名单/阻断控制和事件字段映射）；该适配不是上游某个完整企业版分支的整支合并。Ubuntu 22.04 / kernel 5.15.0-203 曾有构建与运行验证记录；本轮另按内核事件定义静态核对并修正 DNS IPv6 字段映射，尚未重跑构建。

| 已验证的导入提交 | 来源 | 导入内容 |
|---|---|---|
| [`43de387`](https://github.com/net2817/Elkeid/commit/43de387dc7a8eb504f6cc2e93f941bcb99dbc133) | 上游 `v3.0` | 整个 `driver/` 子树；目录内容与上游该分支一致，版本文件为 `3.0.0.7` |
| [`18c40c0`](https://github.com/net2817/Elkeid/commit/18c40c01fcfe23a0032e27ced543a7a41fb7eeba) | 上游 `2.2.3/ac` | 整个 `server/agent_center/` 子树；目录内容与上游该分支一致 |

## 从其它分支导入

### 驱动：上游 `v3.0`

- 新驱动代码含 LKM、BPF 和 ring 通道。
- 执行路径/命令规则与 MD5 规则用于阻断匹配的程序；`smith_exec_load` 对命中规则返回 `-EACCES`。
- `protector.c` 的 `-EPERM` 用于保护 Elkeid 进程/目录不被 kill、ptrace 或写改；它不是程序白名单的拒绝策略。
- 驱动中的 exe/argv allowlist 用于过滤部分采集事件。它没有实现“只允许白名单程序执行”的默认拒绝模式，也未看到完整策略签名、灰度和审计接口。

### Agent Center：上游 `2.2.3/ac`

- 动态连接限流、配置指纹热更新、增强防护等级字段、ZSTD 传输、批量心跳和指标字段更新。
- 该导入只替换 `server/agent_center/`，需要与目标 Agent、Console、HUB 的协议和配置共同联调。

### 插件本地适配：目标仓库实现

- `plugins/driver` 通过 `ringslot::RingSlot` / `SmithControl` 使用 v3.0 驱动的 RingSlot v1.9 ABI，包含 HIPS 阻断、自保护和 PSAD 控制。
- 插件里 9001–9009 是本地控制任务码；本轮未检出 Manager/Console/Agent 端对应的策略下发映射，需补齐并联调。
- exe/argv 驱动 allowlist 过滤采集事件，不能作为“白名单之外拒绝运行”的执行白名单。HIPS 阻断规则是另一套能力。

## 集成风险与立即待办

1. **服务端策略下发仍待接通。** 插件处理 9001–9009 任务码，但未确认 Manager/Console/Agent 有对应生成、授权、审计及字段字典；不能把插件侧 handler 当成端到端功能已交付。
2. **驱动装载与发布流程需补齐。** 插件只连接已加载的 `elkeid` 模块；现有 build/release workflow 仍引用 `driver/build_script/*`、`driver/dockerfiles.*`，这些路径不在已导入的 `driver/` 子树中。需提供与当前 LKM 匹配的构建、签名、发布和安装流程。
3. **验证范围有限。** 仓库记录了 Ubuntu 22.04 / kernel 5.15.0-203 的构建与运行验证；本轮静态修正尚未重跑，其他发行版/内核/架构及策略端到端流程未验证。

## 默认已有能力

上游 README 将 Linux 数据采集、RASP 探针、Kubernetes Audit Log、Agent 控制面、主机状态/详情、基础资产、容器集群资产、告警白名单、病毒扫描、插件管理、系统监控和系统管理列为社区版与企业版共有能力。目标仓库继承这些上游能力，但 `driver/` 和 `agent_center/` 已被上表分支版本替换，不能再描述为“默认目录未改动”。

Hub 的“告警白名单”和驱动 exe/argv 采集过滤都不是执行型程序白名单。主线 Scanner 中的 fanotify 代码可对文件事件触发扫描；这不等于具有基线、变更历史、完整性告警和漏事件 reconciliation 的完整 FIM。

来源：[上游功能表](https://github.com/bytedance/Elkeid/blob/main/README-zh_CN.md)、[主线 Scanner](https://github.com/bytedance/Elkeid/blob/main/plugins/scanner/src/model/functional/fmonitor.rs)

## 还需按企业业务补齐

- **程序执行白名单：** 策略 API、签名者/哈希身份、审核模式、默认拒绝模式、例外、灰度、回滚、离线策略和阻断审计。
- **完整 FIM：** 文件基线与变更前后记录，创建/修改/删除/重命名事件，队列溢出恢复、跨容器/overlayfs/网络盘覆盖和事件留存。
- **内核安全：** 修复上面的接口与 CI 缺口，建立内核/发行版矩阵、kprobe/tracepoint/锁和卸载路径审查、Secure Boot/签名模块/lockdown 降级策略。
- **企业检测响应：** 按上游 README 企业差异完成行为序列关联、溯源聚合、K8s 威胁分析、进程/网络/文件处置、隔离、漏洞情报热更新、RASP 热补丁、UEBA 和 Windows Agent。

README 将蜜罐、主动防御、云查杀和防篡改标为规划项。它没有把完整 FIM 单列为已完成企业能力。

详细 87 分支账本、开发分支候选和 PR 状态见 [`docs/enterprise-branch-audit.md`](docs/enterprise-branch-audit.md)。
