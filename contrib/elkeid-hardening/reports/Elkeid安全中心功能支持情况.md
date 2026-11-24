# Elkeid 安全中心功能支持情况（按部署环境实际）

**环境**：10.255.255.249（CentOS 7.9 / 内核 3.10.0-1160.80.1.el7.x86_64）
**驱动**：elkeid.ko v3.0.0.7（driver v1.9）
**日期**：2026-11-24

---

## 一、总览

| 层级 | 状态 |
|---|---|
| 内核采集/检测（驱动 LKM） | ✅ 已部署，大部分钩子运行中 |
| 反 rootkit | ✅ 已启用 |
| 端口扫描检测（PSAD） | ✅ 已开启（psad_switch=Y） |
| HIPS 执行阻断 / 自保护 | ❌ 关闭（protector_switch=N） |
| 沙箱 | ❌ 关闭（SANDBOX=0） |
| 用户态插件（driver.plg） | ❌ 未部署（编译工具链墙） |
| 完整告警链路（驱动→插件→agent→HUB 告警） | ❌ 未打通 |
| 后端（HUB/Kafka/MongoDB/告警） | ✅ 运行中（容器化） |

---

## 二、已支持的安全功能（实际运行）

### 1. 内核级采集钩子（已注册，dmesg 确认 = 1）

| 功能 | data_type | 说明 |
|---|---|---|
| 进程执行审计 | execve(59) | 完整 argv/父子链/cwd/stdin/stdout/md5 |
| 网络连接审计 | connect(42) | 外联 IP/端口，C2 检测 |
| 网络接入审计 | accept(43) / bind(49) | 服务监听与接入 |
| DNS 查询审计 | dns(601) | DNS 隧道/异常域名 |
| 端口扫描检测 | psad(612) | **已开启**（psad_switch=Y） |
| 内核模块加载 | load_module(603) | Rootkit/.ko 注入检测 |
| 提权检测 | update_cred(604) | old_uid≠0 → new_uid==0 |
| 进程注入 | ptrace(101) | PTRACE_POKETEXT/DATA |
| 文件改名/链接 | rename(82) / link(86) | 文件篡改/横向移动 |
| 挂载审计 | mount(165) | 可疑挂载 |
| 权限变更 | chmod(90) | 提权前置 |
| 内存文件 | memfd_create(356) | 无文件落盘攻击 |
| 文件创建 | create_file(602) / file_creation(613) | 恶意文件投放 |
| 会话管理 | setsid(112) / prctl(157) | 进程名伪装检测 |
| 内核回调执行 | call_usermodehelper_exec(607) | 内核态执行用户程序 |
| 设备事件 | udev(610) | USB 插拔等 |

### 2. 反 Rootkit（ANTI_ROOTKIT_CHECK: 1，已启用）

- 系统调用表篡改检测（701）
- 中断表篡改检测（703）
- proc 文件钩子检测（700）
- 隐藏内核模块检测（702）

### 3. 后端组件（运行中）

HUB（规则引擎）、Kafka（事件队列）、MongoDB（存储）、Prometheus（监控）、Alertmanager（告警）、ServiceDiscovery（服务发现）、ProcessExporter（进程监控）。

---

## 三、实际支持的检测规则（已实弹验证）

| 检测规则 | 触发事件 | 演练验证 |
|---|---|---|
| 命令注入 / RCE 检测 | execve(59) 含可疑 argv | ✅ 已验证（curl/wget/base64） |
| C2 外联检测 | connect(42) 可疑 dip/dport | ✅ 已验证（203.0.113.x:4444） |
| 文件篡改检测 | rename(82) / create_file(602) / file_creation(613) | ✅ 已验证（mv/rm） |
| 内核模块加载检测 | load_module(603) | 🟡 钩子 ON，未实弹（modprobe -n dry-run） |
| 提权检测 | update_cred(604) | 🟡 钩子 ON，未实弹（未做真实 setuid） |
| 端口扫描检测 | psad(612) | ✅ 已开启 |

---

## 四、未启用 / 关闭（开发中或需补）

| 项 | 状态 | 说明 |
|---|---|---|
| **HIPS 执行阻断** | ❌ protector_switch=N | v1.9 的 exe/argv 规则阻断（-EPERM）未开启，需插件下发规则才生效 |
| **驱动自保护** | ❌ protector_switch=N | 驱动可被 root rmmod |
| **沙箱** | ❌ SANDBOX=0 | 关闭 |
| **file_write/file_read** | ❌ 钩子 OFF | 需加 watch list 才触发（FIM 文件写监控） |
| **mprotect** | ❌ 钩子 OFF | 内存执行保护检测（RASP 相关） |
| **open** | ❌ 钩子 OFF | 文件打开审计 |
| **kill/tkill/exit** | ❌ 钩子 OFF | 进程杀死/退出审计 |
| **write** | ❌ 钩子 OFF | 写事件审计 |

---

## 五、阻塞项（关键缺口）

1. **driver.plg 插件未部署**（最高优先级）：
   - 原因：CentOS 7（glibc 2.17）只能用 Rust 1.74，而插件依赖树（libbpf-sys/jobserver 等）需 Rust 1.82-1.85；musl 静态路径又缺 argp（elfutils 依赖 glibc 专有函数）。
   - 影响：**驱动采集的事件没有消费者**，HUB 收不到数据，所有检测规则无法产生告警。当前「检测」停留在驱动采集层。

2. **HUB 规则未验证**：规则集在容器内（宿主机文件系统不可达），且因插件未部署，规则即使存在也不生效。

---

## 六、结论与建议

**实际支持范围**：内核级采集/检测（18 类钩子 ON）+ 反 rootkit + 端口扫描，**采集能力完整且已实弹验证**（命令注入/C2/文件篡改）。

**尚未落地**：HIPS 阻断、自保护、沙箱、文件写监控（FIM）、完整告警链路（插件未部署）。

**优先级建议**：
1. 解决 driver.plg 编译（musl 静态 + argp shim，或 CentOS 7 构建容器）→ 打通告警链路。
2. 部署后开启 HIPS 阻断（protector_switch=Y）+ 配置白名单。
3. 按需打开 file_write/file_read（FIM）等 OFF 钩子。
4. 验证 HUB 规则集并补充 CVE 检测规则。
