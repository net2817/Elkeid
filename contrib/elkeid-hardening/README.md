# Elkeid 社区版增强包（elkeid-hardening）

本目录记录在 **上游开源社区版 v1.9.1** 基础上所做的能力补齐工作，包括：规则库扩充、漏洞情报、基线、驱动 P0/P1/P2 能力、文件读写采集钩子，以及配套的转换/导入/诊断脚本和验证报告。

> 所有脚本均为运维侧工具，**不修改上游核心逻辑**；唯一涉及源码的改动是 `driver/test/src/main.rs`（增加 SmithControl 控制命令调用）和 `plugins/driver`（移除死依赖），见仓库提交 `feat(driver): enable P0 execution allowlist control + drop dead deps`。

## 目录结构

```
contrib/elkeid-hardening/
├── reports/        验证与方案报告（Markdown + PDF）
├── rules/          规则库转换与导入脚本（Falco / Sigma / CISA KEV）
├── fim/            fanotify FIM 采集与基线比对原型（C + Python）
├── baseline/       社区 Linux 加固基线 YAML（6000.yaml）
├── hooks/          驱动执行白名单控制与文件读写钩子启用脚本
├── runbooks/       运维排障手册（HUB 告警误报风暴排查与修复脚本）
└── diagnostics/    HUB / Kafka / Agent 诊断脚本
```

## 数据变化对照（实测）

| 数据 | 社区版原始 | 增强后 | 说明 |
|---|---|---|---|
| HUB ruleset | 18 | **33** | +15 个规则集 |
| `hids_detect` 规则 | 25 | **35** | 新增 7 条文件类规则 |
| `vuln_info` | 25 | **1821** | +1792 条 CISA KEV + 8 条近期高危 CVE |
| `baseline_info` | 10 | **11** | 新增社区 Linux 加固基线 |
| baseline_config YAML | 4 | **5** | 新增 `6000.yaml` |
| `cpe_info` | — | 18287 | 漏洞 CPE 匹配库 |

## 规则库来源

| 规则集 | 条数 | 来源 |
|---|---|---|
| `falco_full_detect` | 33 | [falcosecurity/rules](https://github.com/falcosecurity/rules) `falco_rules.yaml` + `falco-incubating_rules.yaml` + `falco-sandbox_rules.yaml` 中 execve 类规则自动转换 |
| `falco_pass2_detect` | 5 | 同上，二轮转换（ptrace / 内核模块 / 矿池端口 / chmod / symlink） |
| `falco_adapted_detect` | 10 | 手工字段映射适配 |
| `community_extra_detect` | 3 | 社区补充 |
| `sigma_exec_detect` 等 | 4 套 | Sigma 规则（exec / auditd / file / net） |
| `lkrg_detect` | 1 | LKRG 内核完整性告警 |

**转换说明**：Falco 的 `open(2)` 事件在 Elkeid 驱动中的字段名是 `filename` 而非 `file`（见 `driver/LKM/include/kprobe_print.h:549-561`），转换脚本已按此映射。

## 驱动能力（P0/P1/P2）

| 项 | 状态 | 验证方式 |
|---|---|---|
| **P0 执行白名单（内核侧）** | ✅ 已验证 | `ac_set_block_exe_argv` 使 `curl`/`wget` 返回 `-EACCES`（shell 退出码 126）；`ac_add_allow_exe` 放行 `ls`。在 3.10 / 5.15 / 7.0 三种内核上均验证。 |
| **P1 FIM（最小闭环）** | ✅ 已验证 | `fim/fim_monitor.c` 用 fanotify 捕获 MODIFY/CLOSE_WRITE/OPEN 并计算 SHA-256；`fim/fim.py` 做基线 + 变更检测 + 漏事件补偿对账。 |
| **P2 LKRG** | ✅ 已验证（5.15） | `lkrg.ko` 编译加载成功，`/proc/sys/lkrg/` 接口齐全，dmesg 输出 `LKRG initialized successfully`。 |

## 文件读写采集钩子

`OPEN_HOOK` / `WRITE_HOOK` 在驱动中是 **0444 只读参数**，运行时无法修改，必须在加载模块时指定：

```bash
rmmod elkeid
insmod /path/to/elkeid.ko OPEN_HOOK=1 WRITE_HOOK=1
```

验证方式：`dmesg | grep register_kprobe` 应出现 `open_hook:1, ... write_hook:1`；驱动插件心跳 `tx_tps` 会明显上升（实测约 102 事件/秒）。

## 已知边界

1. **执行白名单业务层未做**：内核侧阻断可用，但可信身份、策略管理、默认拒绝开关、灰度/回滚等业务层尚未实现。
2. **FIM 未生产化**：当前为独立原型，尚未整合进 Elkeid 插件体系（未产出 6012 事件）。
3. **file_read/file_write 完整闭环未通**：`open(2)` 事件已确认进入 HUB（`hub_sample` 可见 `filename` 字段），但规则引擎侧字段映射仍需对齐。
4. **LKRG 仅编译了 5.15 内核版本**，3.10 / 7.0 未做。
5. **Falco 96 条规则中导入 51 条**，其余因 Elkeid 不采集容器元数据（privileged/uid）和文件 syscall 级 fd 字段，无法等价转换。

## 使用方式

```bash
# 1. 导入规则（需在 Elkeid all-in-one 容器内执行，MongoDB 连接串见脚本）
python convert-falco.py          # 转换 Falco 规则
python gen-falco-ruleset.py      # 生成 ruleset JSON
# 2. 通过 docker cp + mongo --eval 导入，详见各脚本内的 import 段落

# 3. 导入漏洞情报
python convert-kev.py            # 转换 CISA KEV
# 4. 导入基线
cp baseline/baseline-6000.yaml /elkeid/manager/conf/baseline_config/
# 5. 重启 HUB 使规则生效
docker exec <container> systemctl restart elkeid_hub
```

## 许可

本目录内容与上游 Elkeid 保持一致的许可（Apache-2.0）。
