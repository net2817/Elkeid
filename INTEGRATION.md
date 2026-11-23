# Elkeid 二开整合状态

审计日期：2026-11-23  
上游基线：[bytedance/Elkeid `main`](https://github.com/bytedance/Elkeid/tree/main)，`c906c512`  
本仓库：[net2817/Elkeid `main`](https://github.com/net2817/Elkeid/tree/main)，审计起点为 `e5873fe`，当前头为 [`ade7778`](https://github.com/net2817/Elkeid/commit/ade7778a2803c7079e6d5f0c1377ce62a928ae51)

审计起点 `e5873fe` 相对上游基线领先 3 个提交（其中两项是分支代码导入）；截至当前 `main` 共领先 5 个提交，新增的两个提交均为审计文档：

| 目标提交 | 来源 | 导入内容 |
|---|---|---|
| [`43de387`](https://github.com/net2817/Elkeid/commit/43de387dc7a8eb504f6cc2e93f941bcb99dbc133) | 上游 `v3.0` | 整个 `driver/` 子树；目录内容与上游该分支一致，版本文件为 `3.0.0.7` |
| [`18c40c0`](https://github.com/net2817/Elkeid/commit/18c40c01fcfe23a0032e27ced543a7a41fb7eeba) | 上游 `2.2.3/ac` | 整个 `server/agent_center/` 子树；目录内容与上游该分支一致 |
| [`e5873fe`](https://github.com/net2817/Elkeid/commit/e5873fe72fede48355cfb68e58b3627156f180b5) | 本仓库文档 | 首版整合说明 |
| [`7667e3c`](https://github.com/net2817/Elkeid/commit/7667e3c1c2d5ef0e4eb09a4eb4414c2c348e6649) | 本仓库文档 | 全分支账本与整合状态校正 |
| [`ade7778`](https://github.com/net2817/Elkeid/commit/ade7778a2803c7079e6d5f0c1377ce62a928ae51) | 本仓库文档 | 校正审计快照与提交计数 |

## 从其它分支导入

### 驱动：上游 `v3.0`

- 新驱动代码含 LKM、BPF 和 ring 通道。
- 执行路径/命令规则与 MD5 规则用于阻断匹配的程序；`smith_exec_load` 对命中规则返回 `-EACCES`。
- `protector.c` 的 `-EPERM` 用于保护 Elkeid 进程/目录不被 kill、ptrace 或写改；它不是程序白名单的拒绝策略。
- 驱动中的 exe/argv allowlist 用于过滤部分采集事件。它没有实现“只允许白名单程序执行”的默认拒绝模式，也未看到完整策略签名、灰度和审计接口。

### Agent Center：上游 `2.2.3/ac`

- 动态连接限流、配置指纹热更新、增强防护等级字段、ZSTD 传输、批量心跳和指标字段更新。
- 该导入只替换 `server/agent_center/`，需要与目标 Agent、Console、HUB 的协议和配置共同联调。

## 集成风险与立即待办

1. **Agent 与新驱动接口需对齐。** `plugins/driver/src/config.rs` 仍声明 `KMOD_VERSION=1.7.0.6`、`/proc/elkeid-endpoint`、`/dev/hids_driver_allowlist`；新驱动 README 写 `/proc/hids_driver/1` 和 `/dev/hids_driver_whitelist`。LKM 的 `trace.h` 与 Rust 插件对 add/delete 白名单命令的字符定义也不一致。应先统一模块版本、事件 pipe、控制节点和指令码。
2. **驱动 CI 仍指向旧目录。** `.github/workflows/Elkeid_driver_build.yml` 和 release workflow 引用 `driver/build_script/*`、`driver/dockerfiles.*`；当前导入的 `driver/` 子树没有这些路径。需要将 build/release workflow 改到 v3.0 驱动构建方式后再发版。
3. **尚未做 Linux 构建和运行联调。** 需要验证 x86_64/aarch64、支持内核、驱动安装/卸载、Agent 数据通路、事件丢失和策略更新。当前仓库记录的是代码导入，不代表已验证可部署。

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
