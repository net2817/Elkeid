# Elkeid 上游分支与企业功能整合审计

审计日期：2026-11-23  
上游：[bytedance/Elkeid](https://github.com/bytedance/Elkeid)  
目标：[net2817/Elkeid](https://github.com/net2817/Elkeid)

## 现状与已合入的代码

上游 `main` 基线为 `c906c512d20c0d56f2b779b8558ed69abae718c8`。本轮审计开始时目标 `main` 为 `e5873fe72fede48355cfb68e58b3627156f180b5`；该版本已有两项上游分支代码导入。下文按审计时可见的公开 refs、PR、README 和代码文件区分已进入目标仓库的代码与尚待评估的分支内容。

目标仓库已经导入两项上游分支代码：

| 已验证的导入提交 | 上游来源 | 当前文件核对 |
|---|---|---|
| [`43de387`](https://github.com/net2817/Elkeid/commit/43de387dc7a8eb504f6cc2e93f941bcb99dbc133) | [`v3.0`](https://github.com/bytedance/Elkeid/tree/v3.0) | `driver/` 子树文件内容与分支相同；`driver/VERSION=3.0.0.7` |
| [`18c40c0`](https://github.com/net2817/Elkeid/commit/18c40c01fcfe23a0032e27ced543a7a41fb7eeba) | [`2.2.3/ac`](https://github.com/bytedance/Elkeid/tree/2.2.3/ac) | `server/agent_center/` 子树文件内容与分支相同 |

### 驱动分支实际能力与边界

`v3.0` 驱动包含 LKM、BPF 和 ring 通道。执行路径/命令规则和 MD5 规则在命中时阻止启动；`smith_exec_load` 返回 `-EACCES`。此外 `protector.c` 中的 `-EPERM` 保护 Elkeid 进程/目录不被 kill、ptrace 或写改。

驱动中的 exe/argv allowlist 用于过滤一部分采集事件，不能当作“只允许白名单程序执行”的默认拒绝策略。当前实现已有执行阻断规则，但业务层还需补全可信软件身份、白名单策略管理、灰度/回滚、策略审计和离线更新。

另有接口与构建集成风险：

- `plugins/driver/src/config.rs` 仍是 `KMOD_VERSION=1.7.0.6`、`/proc/elkeid-endpoint`、`/dev/hids_driver_allowlist`；新驱动 README 写 `/proc/hids_driver/1`、`/dev/hids_driver_whitelist`。
- LKM `driver/LKM/include/trace.h` 与插件配置对 exe/argv allowlist add/delete 字符定义不一致，驱动 README 与两者也有不一致。需统一协议后才能依赖动态白名单下发。
- 当前 driver build/release workflow 仍引用 `driver/build_script/*` 与 `driver/dockerfiles.*`，这些路径不在已导入的 `driver/` 子树中。

这些静态接口差异尚需与新驱动的实际加载方式联调。当前没有构建/测试结果。

### Agent Center 2.2.3/ac

目标仓库已整体导入该分支的 `server/agent_center/`，包含动态连接限流、配置指纹热更新、增强防护等级字段、ZSTD 传输、批量心跳和指标字段变更。需要与目标 Agent、Console、HUB 的协议和配置联调。

## 默认已有能力（上游 README 标注社区版与企业版共有）

Linux 数据采集、RASP 探针、Kubernetes Audit Log、Agent 控制面、主机状态和详情、基础资产采集、容器集群资产采集、告警白名单、病毒扫描、插件管理、系统监控和系统管理。

Hub 的“告警白名单”用于告警过滤。驱动 exe/argv allowlist 用于采集事件过滤。两者都不等同于操作系统层的执行型程序白名单。Scanner 的 fanotify 代码可按文件事件触发扫描，但不等于有基线、完整变更历史、完整性告警和漏事件补偿的 FIM。

来源：[上游 README 功能表](https://github.com/bytedance/Elkeid/blob/main/README-zh_CN.md)、[主线 Scanner fanotify](https://github.com/bytedance/Elkeid/blob/main/plugins/scanner/src/model/functional/fmonitor.rs)

## 尚未纳入的公开开发内容

| 来源 | 已确认内容 | 状态与处理 |
|---|---|---|
| `v1.8-rc` | eBPF 保存可信 executable path/argv 哈希；命中后在部分 syscall/exec 数据路径提前返回 | 采集降噪，不是执行允许策略；旧驱动线，重复/移植前需核验 |
| `2.2/scanner`、`2.2.1/scanner`、`2.2.2/scanner` | fanotify 目录/递归配置、静态 exe/argv 过滤和文件创建/修改/删除/移动事件 | 比当前 Scanner 配置更细；仍是旧 Scanner 版本线，需要移植并验证，不是完整 FIM |
| `2.2.0.2/scanner` | 分支头提交明确关闭 `proc_scan`、`fanotify`、`arf` 和进程全盘扫描 | 不能作为“功能全开”的默认版本 |
| `2.2.2/ac_csc*`、`csc/0.9.x` | CSC/Agent Center 指标、插件退出指标和 Metrics SDK 变更；多个分支重复 | 需要数据 schema、后端消费者和版本依赖评估 |
| `audit_log` | K8s audit 事件接收/转发改动 | 主线已含 K8s Audit 接收端，README 将其列为社区能力 |
| [PR #741](https://github.com/bytedance/Elkeid/pull/741) | 弱口令规则、更新字典接口、Java 应用采集 | 已关闭且未合并；不是当前分支中的可发布功能 |
| `v1.9` / PR #729 | 新内核 `file_ref` 适配所在版本线 | #729 的 base 是 `v1.9`；同类修复 #728 已合入上游 `main`，不要整条替换当前 driver |
| RASP 分支（`rasp-engine`、`rasp-v2.2.0.3-*`、`stack-frame-block`） | JVM hook、规则引擎、类扫描和栈帧处理的不同迭代 | 依赖旧版本线；逐提交评估。开放 PR #634 是 native `.so` 路径改动 |
| [PR #732](https://github.com/bytedance/Elkeid/pull/732) | Rust zip 依赖和 GitHub Actions 版本更新 | 开放中的构建维护，不是企业安全功能 |

上游还存在大量发布分支、旧版本快照和仅修复提交。分支头 commit 计数不能单独表示代码是否未合入：上游存在 squash/rebase 合并。

## README 标注的企业版差异

勒索诱饵、高级资产采集、暴露面与脆弱性分析、主机/容器/RASP/K8s 行为序列检测、K8s 威胁分析、行为/驻留溯源、多告警聚合、进程/网络/文件处置、文件隔离、漏洞情报热更新、RASP 热补丁、用户行为日志分析和 Windows 支持。

README 另将蜜罐、主动防御、云查杀、防篡改标为规划项。功能表没有证明这些完整实现存在于公开分支；FIM 也未被单独列为已完成企业功能。Scanner 的 fanotify 代码不等于完整 FIM。

## 按业务要求仍需补充

### 执行型程序白名单

给现有执行阻断规则补充签名者/哈希/可信路径策略，支持策略 API、审计模式、默认拒绝模式、例外、灰度、回滚、离线策略和阻断审计。先统一驱动/Agent 的版本与控制接口。

### 完整 FIM

fanotify/fsnotify 捕获写入、创建、删除、重命名；维护元数据/权限/所有者/哈希基线和变更前后记录；加入队列溢出后的 reconciliation、告警查询与留存；覆盖 overlayfs、bind mount、网络盘和容器场景。

### 内核和企业能力

维护发行版/内核矩阵，核对 kprobe/tracepoint/回调上下文/锁/卸载路径，处理 Secure Boot、模块签名和 BPF verifier 降级。企业侧还需行为序列关联、溯源聚合、K8s 威胁分析、进程/网络/文件响应、文件隔离、漏洞情报更新、RASP 热补丁、UEBA 和 Windows Agent。

## 全部公开分支账本

审计时 `/branches?per_page=100&page=1` 返回 87 个公开分支，含 `main`。逐个比较上游 `main` 后，21 个分支头有 0 个 main 外提交，65 个分支分叉并有分支独有 commit。这里的 `ahead/behind` 是提交图计数，不是文件差异行数。

| 分支 | 比较状态 | ahead | behind | 分支头提交主题 |
|---|---:|---:|---:|---|
| [`1.8-svr`](https://github.com/bytedance/Elkeid/tree/1.8-svr) | behind | 0 | 983 | 无 main 外提交 |
| [`1.8/scanner_clamav_org`](https://github.com/bytedance/Elkeid/tree/1.8%2Fscanner_clamav_org) | diverged | 4 | 965 | update build docker |
| [`1.9-svr`](https://github.com/bytedance/Elkeid/tree/1.9-svr) | behind | 0 | 733 | 无 main 外提交 |
| [`2.0-svr`](https://github.com/bytedance/Elkeid/tree/2.0-svr) | diverged | 4 | 974 | SetAgentDetail add state/state_detail checker |
| [`2.0/scanner`](https://github.com/bytedance/Elkeid/tree/2.0%2Fscanner) | diverged | 35 | 517 | Merge branch 'main' into 2.0/scanner |
| [`2.1-svr`](https://github.com/bytedance/Elkeid/tree/2.1-svr) | diverged | 10 | 974 | add version for ac hb update |
| [`2.2-svr`](https://github.com/bytedance/Elkeid/tree/2.2-svr) | diverged | 14 | 974 | disable retry config.Producer.Retry.Max && set config.Net.MaxOpenRequests = 10 |
| [`2.2/scanner`](https://github.com/bytedance/Elkeid/tree/2.2%2Fscanner) | diverged | 44 | 899 | fix: scanner 6053 finished with nil path |
| [`2.2.0.1/scanner`](https://github.com/bytedance/Elkeid/tree/2.2.0.1%2Fscanner) | diverged | 63 | 899 | revert: cgroup-rs version |
| [`2.2.0.2/scanner`](https://github.com/bytedance/Elkeid/tree/2.2.0.2%2Fscanner) | diverged | 64 | 899 | func: disable proc_scan, fanotify, arf, and fullscan with proc |
| [`2.2.1/ac`](https://github.com/bytedance/Elkeid/tree/2.2.1%2Fac) | diverged | 24 | 974 | CheckCommonConfig update some log |
| [`2.2.1/scanner`](https://github.com/bytedance/Elkeid/tree/2.2.1%2Fscanner) | diverged | 55 | 899 | fix docker -it |
| [`2.2.2/ac_csc_exit_metrics`](https://github.com/bytedance/Elkeid/tree/2.2.2%2Fac_csc_exit_metrics) | diverged | 91 | 974 | fix: take part agent and plugin exit metrics |
| [`2.2.2/ac_csc_metrics_upd`](https://github.com/bytedance/Elkeid/tree/2.2.2%2Fac_csc_metrics_upd) | diverged | 79 | 974 | Merge branch '2.2.2/ac_csc' of github.com:bytedance/Elkeid into 2.2.2/ac_csc |
| [`2.2.2/ac_csc_performance_test`](https://github.com/bytedance/Elkeid/tree/2.2.2%2Fac_csc_performance_test) | diverged | 81 | 974 | fix: Performance testing to 500000 |
| [`2.2.2/ac_csc_test_zm`](https://github.com/bytedance/Elkeid/tree/2.2.2%2Fac_csc_test_zm) | diverged | 80 | 974 | feat: update plugin metrics |
| [`2.2.2/ac_csc_test`](https://github.com/bytedance/Elkeid/tree/2.2.2%2Fac_csc_test) | diverged | 79 | 974 | Merge branch '2.2.2/ac_csc' of github.com:bytedance/Elkeid into 2.2.2/ac_csc |
| [`2.2.2/ac_csc_vestack_zm`](https://github.com/bytedance/Elkeid/tree/2.2.2%2Fac_csc_vestack_zm) | diverged | 68 | 974 | feat: update plugin metrics |
| [`2.2.2/ac_csc_vestack`](https://github.com/bytedance/Elkeid/tree/2.2.2%2Fac_csc_vestack) | diverged | 68 | 974 | feat: update plugin metrics |
| [`2.2.2/ac_csc`](https://github.com/bytedance/Elkeid/tree/2.2.2%2Fac_csc) | diverged | 81 | 974 | Merge pull request #722 from bytedance/2.2.2/ac_csc_test_zm |
| [`2.2.2/ac_ty`](https://github.com/bytedance/Elkeid/tree/2.2.2%2Fac_ty) | diverged | 37 | 974 | add refreshIaasInfo |
| [`2.2.2/ac`](https://github.com/bytedance/Elkeid/tree/2.2.2%2Fac) | diverged | 15 | 974 | update hb when pid changed |
| [`2.2.2/scanner`](https://github.com/bytedance/Elkeid/tree/2.2.2%2Fscanner) | diverged | 60 | 899 | reset macos x64 cmake host |
| [`2.2.3/ac`](https://github.com/bytedance/Elkeid/tree/2.2.3%2Fac) | diverged | 42 | 974 | feat: 优化handlerFile，避免文件覆盖 |
| [`add_driver_doc`](https://github.com/bytedance/Elkeid/tree/add_driver_doc) | diverged | 4 | 899 | Update Description_of_Elkeid's_Crash_caused_by_fput_in_low_version_Kernel.md |
| [`archive_driver_1.7.0.8`](https://github.com/bytedance/Elkeid/tree/archive_driver_1.7.0.8) | diverged | 55 | 676 | update alma8 url |
| [`audit_log`](https://github.com/bytedance/Elkeid/tree/audit_log) | diverged | 8 | 1227 | AuditEvent remove some useless field |
| [`b_buzz_pipe`](https://github.com/bytedance/Elkeid/tree/b_buzz_pipe) | diverged | 1 | 230 | Tracing: plugin got garbage binary data when reading pipe |
| [`b_sockfd_put_async`](https://github.com/bytedance/Elkeid/tree/b_sockfd_put_async) | diverged | 1 | 17 | FIXME: making sockfd_put async for kernels <= 3.6 |
| [`b1_7_dkms_khead`](https://github.com/bytedance/Elkeid/tree/b1_7_dkms_khead) | behind | 0 | 26 | 无 main 外提交 |
| [`b1_7_file_ref`](https://github.com/bytedance/Elkeid/tree/b1_7_file_ref) | behind | 0 | 28 | 无 main 外提交 |
| [`b_1_7_0_13`](https://github.com/bytedance/Elkeid/tree/b_1_7_0_13) | diverged | 1 | 473 | version updated to 1.7.0.13 |
| [`b1.7.0.19`](https://github.com/bytedance/Elkeid/tree/b1.7.0.19) | diverged | 10 | 360 | Version updated to 1.7.0.19 |
| [`b1.7.0.22-driver`](https://github.com/bytedance/Elkeid/tree/b1.7.0.22-driver) | diverged | 3 | 33 | Version 1.7.0.22 to be released |
| [`b1.7.0.23-driver`](https://github.com/bytedance/Elkeid/tree/b1.7.0.23-driver) | behind | 0 | 26 | 无 main 外提交 |
| [`b1_8_RAWTP_SWITCH`](https://github.com/bytedance/Elkeid/tree/b1_8_RAWTP_SWITCH) | behind | 0 | 18 | 无 main 外提交 |
| [`b1_9_file_ref`](https://github.com/bytedance/Elkeid/tree/b1_9_file_ref) | diverged | 72 | 415 | FIXME: building errors with new kernels after 6.13 |
| [`bug_fix_20250712`](https://github.com/bytedance/Elkeid/tree/bug_fix_20250712) | diverged | 1 | 2 | fix auth problem |
| [`bugfix/modify-aarch64-compile`](https://github.com/bytedance/Elkeid/tree/bugfix%2Fmodify-aarch64-compile) | diverged | 1 | 148 | aarch64 batch compile bugfix |
| [`connection-patch`](https://github.com/bytedance/Elkeid/tree/connection-patch) | behind | 0 | 875 | 无 main 外提交 |
| [`csc/0.9.11`](https://github.com/bytedance/Elkeid/tree/csc%2F0.9.11) | diverged | 88 | 974 | fix: fix config |
| [`csc/0.9.12_metrics_sdk`](https://github.com/bytedance/Elkeid/tree/csc%2F0.9.12_metrics_sdk) | diverged | 89 | 974 | feat: use metrics sdk 2.0 to report |
| [`csc/0.9.12`](https://github.com/bytedance/Elkeid/tree/csc%2F0.9.12) | diverged | 88 | 974 | fix: fix config |
| [`driver_archive_1.7.0.5`](https://github.com/bytedance/Elkeid/tree/driver_archive_1.7.0.5) | diverged | 3 | 546 | update volc ci |
| [`elkeid-rasp-guoyj`](https://github.com/bytedance/Elkeid/tree/elkeid-rasp-guoyj) | behind | 0 | 271 | 无 main 外提交 |
| [`feat-java-performance`](https://github.com/bytedance/Elkeid/tree/feat-java-performance) | behind | 0 | 71 | 无 main 外提交 |
| [`feat-jvm-switch`](https://github.com/bytedance/Elkeid/tree/feat-jvm-switch) | diverged | 1 | 361 | feat jvm hook switch |
| [`feat-main-benchmark`](https://github.com/bytedance/Elkeid/tree/feat-main-benchmark) | behind | 0 | 390 | 无 main 外提交 |
| [`fix-agent-name`](https://github.com/bytedance/Elkeid/tree/fix-agent-name) | diverged | 1 | 951 | Update module.go |
| [`fix-child`](https://github.com/bytedance/Elkeid/tree/fix-child) | diverged | 4 | 54 | remove probe file |
| [`fix-cloader`](https://github.com/bytedance/Elkeid/tree/fix-cloader) | behind | 0 | 266 | 无 main 外提交 |
| [`gqds_tmp`](https://github.com/bytedance/Elkeid/tree/gqds_tmp) | diverged | 2 | 1020 | disable insecurity ssl cipher |
| [`hotfix/rasp/2.2.0.3`](https://github.com/bytedance/Elkeid/tree/hotfix%2Frasp%2F2.2.0.3) | diverged | 2 | 503 | fix bug: update musl toolchain path |
| [`librasp-modify-guoyj`](https://github.com/bytedance/Elkeid/tree/librasp-modify-guoyj) | diverged | 2 | 231 | Cherry-pick:a0403b9c1d6d4eecf83d18c8384a0dcdbea278d5 |
| [`m_opt_plugins_lib`](https://github.com/bytedance/Elkeid/tree/m_opt_plugins_lib) | diverged | 3 | 27 | opt: update github actions deps in gen_ci python script |
| [`main-hupdate-guoyj`](https://github.com/bytedance/Elkeid/tree/main-hupdate-guoyj) | behind | 0 | 152 | 无 main 外提交 |
| [`main-rasp-fixupdate`](https://github.com/bytedance/Elkeid/tree/main-rasp-fixupdate) | behind | 0 | 149 | 无 main 外提交 |
| [`memshell-main`](https://github.com/bytedance/Elkeid/tree/memshell-main) | diverged | 6 | 308 | add benchmark package |
| [`memshell-main-guoyj`](https://github.com/bytedance/Elkeid/tree/memshell-main-guoyj) | behind | 0 | 329 | 无 main 外提交 |
| [`metrics_dev`](https://github.com/bytedance/Elkeid/tree/metrics_dev) | diverged | 43 | 1005 | add write agent err log to es |
| [`plugin/lib/rust`](https://github.com/bytedance/Elkeid/tree/plugin%2Flib%2Frust) | behind | 0 | 30 | 无 main 外提交 |
| [`plugin/records`](https://github.com/bytedance/Elkeid/tree/plugin%2Frecords) | behind | 0 | 893 | 无 main 外提交 |
| [`rasp/fix/mount`](https://github.com/bytedance/Elkeid/tree/rasp%2Ffix%2Fmount) | diverged | 1 | 786 | fix mount missing |
| [`rasp/fix/patch_issue`](https://github.com/bytedance/Elkeid/tree/rasp%2Ffix%2Fpatch_issue) | diverged | 33 | 781 | fix device mapping issue |
| [`rasp/improve/auto_delete_pervlib`](https://github.com/bytedance/Elkeid/tree/rasp%2Fimprove%2Fauto_delete_pervlib) | diverged | 1 | 863 | clean prev lib |
| [`rasp/improve/stack`](https://github.com/bytedance/Elkeid/tree/rasp%2Fimprove%2Fstack) | diverged | 3 | 517 | no more config_id |
| [`rasp_jvm_benchmark`](https://github.com/bytedance/Elkeid/tree/rasp_jvm_benchmark) | diverged | 1 | 400 | Add run time statistics code |
| [`rasp_191`](https://github.com/bytedance/Elkeid/tree/rasp_191) | behind | 0 | 890 | 无 main 外提交 |
| [`rasp-engine`](https://github.com/bytedance/Elkeid/tree/rasp-engine) | diverged | 11 | 64 | Add unit test cases for mocking the SmithProbeProxy class. |
| [`rasp-feat-asmhook`](https://github.com/bytedance/Elkeid/tree/rasp-feat-asmhook) | behind | 0 | 363 | 无 main 外提交 |
| [`rasp-feat-asmhook-matadata`](https://github.com/bytedance/Elkeid/tree/rasp-feat-asmhook-matadata) | behind | 0 | 364 | 无 main 外提交 |
| [`rasp-main`](https://github.com/bytedance/Elkeid/tree/rasp-main) | diverged | 13 | 527 | fix patch empty |
| [`rasp-v2.2.0.3-feathook`](https://github.com/bytedance/Elkeid/tree/rasp-v2.2.0.3-feathook) | diverged | 31 | 527 | remove tranform memshell check |
| [`rasp-v2.2.0.3-fixversion`](https://github.com/bytedance/Elkeid/tree/rasp-v2.2.0.3-fixversion) | diverged | 7 | 527 | Merge pull request #603 from driftli/rasp-v2.2.0.3-fixversion |
| [`rasp-v2.2.0.3-scanclass`](https://github.com/bytedance/Elkeid/tree/rasp-v2.2.0.3-scanclass) | diverged | 30 | 527 | fix compile |
| [`rustlib_update`](https://github.com/bytedance/Elkeid/tree/rustlib_update) | diverged | 2 | 42 | fix: replace WRITE_PIPE_FD with HIGH_PRIORIT_FD in unix get_high_writer |
| [`shenping-pledge-improvement`](https://github.com/bytedance/Elkeid/tree/shenping-pledge-improvement) | behind | 0 | 25 | 无 main 外提交 |
| [`stack-frame-block`](https://github.com/bytedance/Elkeid/tree/stack-frame-block) | diverged | 3 | 527 | support build RASP without O_PATH |
| [`update_rasp_server`](https://github.com/bytedance/Elkeid/tree/update_rasp_server) | diverged | 90 | 981 | fix typo |
| [`update/1.7`](https://github.com/bytedance/Elkeid/tree/update%2F1.7) | behind | 0 | 982 | 无 main 外提交 |
| [`v1.7-ringslot`](https://github.com/bytedance/Elkeid/tree/v1.7-ringslot) | diverged | 62 | 1198 | update rust-toolchain |
| [`v1.8-rc`](https://github.com/bytedance/Elkeid/tree/v1.8-rc) | diverged | 70 | 781 | Optimization: using hash for trusted exe & arg check |
| [`v1.9`](https://github.com/bytedance/Elkeid/tree/v1.9) | diverged | 110 | 415 | Version 1.9.1.19 |
| [`v1.9.1-agent`](https://github.com/bytedance/Elkeid/tree/v1.9.1-agent) | diverged | 6 | 726 | fix: doc. |
| [`v1.9.1_agent`](https://github.com/bytedance/Elkeid/tree/v1.9.1_agent) | diverged | 14 | 781 | feat: update 1.9.1 driver plugin. |
| [`v3.0`](https://github.com/bytedance/Elkeid/tree/v3.0) | diverged | 80 | 415 | Update for v3.0 of driver modules (LKM & ebpf) |
| `main` | 基准 | 0 | 0 | `c906c512` fix auth problem |

完整列表：[上游 branches](https://github.com/bytedance/Elkeid/branches)。公开 PR：[上游 Pull Requests](https://github.com/bytedance/Elkeid/pulls)。

## 审计范围和验证状态

只检查公开 refs、PR、README 和相关文件。无法从公开资料判断 ByteDance 私有分支或内部企业实现。本次没有运行构建或测试；代码已经在目标 `main`，但驱动与 Agent 接口/构建集成仍需修正并在 Linux 上验证。