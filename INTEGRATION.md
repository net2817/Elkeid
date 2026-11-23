# Elkeid 二开整合说明（net2817 fork）

本文档说明本仓库相对上游 `bytedance/Elkeid`（main 分支）做了哪些精选整合、来源分支、以及哪些仍待补充。

基准：上游 `main`（commit `c906c512`，2026-04-27）。

---

## 一、从其它分支合并进来的功能（精选整合）

### 1. driver v1.9（来源：`bytedance/Elkeid` 分支 `v3.0`）

将上游 `driver/` 整体替换为 v1.9 自包含驱动包（C LKM + Rust 用户态 + eBPF）。相对 main 的 v1.7 驱动，新增/变化：

| 能力 | 说明 |
|---|---|
| **HIPS 执行阻断** | `LKM/src/protector.c` 等，支持 exe/argv 规则，命中返回 -EPERM（主动防御/高危命令前置阻断） |
| **钩子迁移 tracepoint** | 从 kprobe/kretprobe 迁移到 tracepoint，性能与覆盖更好 |
| **Rust 用户态 + eBPF** | `driver/rust`、`driver/BPF`、`driver/ebpf`、`driver/libbpf`、`driver/ring`、`driver/xfer` |
| **移除 /proc /dev 暴露** | 接口从 `/proc/elkeid-endpoint`、`/dev/hids_driver_allowlist` 改为 `/proc/hids_driver/N`，反规避 |
| 内核版本兼容 | >= 3.10 |

> ⚠️ 注意：v1.9 驱动接口变化（`/proc/hids_driver/N`），原 `plugins/driver`（读 `/proc/elkeid-endpoint`）需同步适配后才能联调；该驱动为 WIP，需在 Linux 上编译验证（LKM + Rust musl + eBPF CO-RE）。

### 2. agent_center 2.2.3（来源：`bytedance/Elkeid` 分支 `2.2.3/ac`）

将 `server/agent_center/` 整体替换为 2.2.3 版本。相对 main 新增：

| 能力 | 说明 |
|---|---|
| 连接限流 | `conn/limit` 动态限流接口（`http_handler/limit.go`） |
| 配置指纹热更新 | `grpc_handler/config_handler.go`，release 版本号校验 + 配置下发 |
| Enhanced 防护等级字段 | `grpc.proto` 中 `MQData.Enhanced = 16`，用于区分防护等级 |
| ZSTD 压缩 | 传输压缩增强 |
| 心跳批量 | join/evict bulk 写入 |
| 指标增强 | agent/plugin/driver 心跳 metric 字段校验 |

---

## 二、默认功能（main 原生，未改动）

以下为上游 main 自带的社区能力，保持原样：

- 采集：execve(59)、connect(42)、dns(601)、提权(604/611)、模块加载(603)、ptrace(101)、文件类(rename/link/mount/memfd) 等内核钩子
- 反 rootkit：syscall 表 hook(701)、中断表 hook(703)、proc 文件 hook(700)、隐藏模块(702)
- 插件：driver / collector（资产、漏洞、弱口令、完整性）/ scanner（yara+clamav+fanotify FIM+蜜罐）/ journal_watcher（SSH）/ baseline
- RASP 探针（CPython/Golang/JVM/NodeJS/PHP，含 JVM 内存马检测）
- 后端：AgentCenter、ServiceDiscovery、Manager、Console、HUB 规则引擎集成

---

## 三、评估后未合并的分支（及原因）

| 分支 | 内容 | 未合并原因 |
|---|---|---|
| `2.2.x/scanner` | 扫描器更新 | main 的 scanner 已更新于分支（分支是 2023 年旧开发线，落后 main） |
| `memshell-main` | JVM 内存马检测 | 已并入 main 的 rasp/jvm（SmithProbe 等） |
| `rasp-feat-asmhook` | ASM hook | 相对 main 空 diff（WIP/未落地） |
| `rasp-engine` | RASP 引擎重构 | WIP，改动 jvm+librasp+plugin，会破坏稳定 rasp |
| `csc/0.9.12` | 云安全中心(CSC) | 与 2.2.3/ac 的 agent_center 重叠；CSC 为云化专用能力，需人工评估后并入 |
| `audit_log` 等 | 审计日志等 | 2021 年旧单点分支 |

---

## 四、按业务要求仍需补充/开发的功能

结合企业版功能表与目标场景，仍需补充（详见排期计划文档）：

1. **白名单放行**：v1.9 HIPS 阻断需配套 exe/argv 白名单/例外/学习模式（否则误伤）；v1.9 移除了 `/dev/hids_driver_allowlist`，需确认白名单下发新通道。
2. **文件完整性监控（FIM）告警闭环**：fanotify + SHA-256 基线已有，需接 HUB 规则 + Console 展示。
3. **网络阻断**：外联 IP/域名实时 drop（eBPF socket/TC）——driver v1.9 的 eBPF 为采集，阻断需扩展。
4. **检测/分析**：行为序列检测、告警聚合/降噪、威胁情报（离线 IOC）、事件追溯、UEBA。
5. **响应处置**：进程/文件处置、文件隔离。
6. **合规**：审计留存防篡改(WORM)、合规报表、离线 NTP、RBAC/操作审计。
7. **验证**：整合后的 driver v1.9 与 agent_center 2.2.3 需在 Linux 上编译 + 联调验证（本整合为代码级合并，未做编译验证）。
