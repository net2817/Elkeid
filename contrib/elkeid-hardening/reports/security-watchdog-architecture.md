# 安全值守程序（Linux 主机）架构设计

> 版本：v0.2　｜　日期：2026-11-21　｜　范围：**仅 Linux**（云主机 / 物理机 / K8s 节点）
> 定位：主机侧「采集 — 检测 — 阻断 — 值守」一体化 Agent 与管控平台

---

## 0. 一页纸摘要

| 能力 | 关键实现 | 内核门槛 | 默认动作 |
|---|---|---|---|
| 核心命令拦截 | eBPF LSM `bprm_check_security` | ≥ 5.7 且 `lsm=bpf` | 阻断 |
| 内核安全 | kprobe / tracepoint / 硬化基线 / 模块签名 | ≥ 4.19 | 告警 |
| 文件变动监控 | eBPF `vfs_*` + fanotify + 周期哈希 | ≥ 4.19 | 分级处置 |

**三个判断，决定后面所有取舍：**

1. **内核能力是第一性问题。** 同一套 Agent 在 CentOS 7（3.10）和 Ubuntu 22.04（5.15）上能做的事差一个时代。所以方案的第一步不是写探针，而是**探测分档**——先知道这台机器能干什么，再发什么策略。
2. **告警可以激进，阻断必须克制。** 误拦一次业务比漏报十次更伤项目。所有阻断默认 observe，灰度后才 enforce。
3. **命令拦截是入口，行为拦截是兜底。** 只拦 `execve` 注定被绕过，真正的防线是"写 `/dev/sda`、改 `/etc/passwd`、`finit_module`"这些**结果动作**。

---

## 1. 目标与边界

### 1.1 目标

| # | 目标 | 验收标准 |
|---|---|---|
| G1 | 危险命令在**执行前**被拒 | 阻断时延 P99 < 2ms；`rm -rf /` 命中率 100% |
| G2 | 内核层异常可发现 | 模块加载、BPF 滥用、`/dev/mem`、提权链全覆盖 |
| G3 | 关键文件变更**秒级**感知 | 写入到告警 < 5s |
| G4 | 告警进入值班闭环 | 每条 P0/P1 有工单、有响应人、有 SLA |
| G5 | 平台可运营 | 策略灰度、白名单、一键回滚、审计留痕 |

### 1.2 明确不做

- 不做全流量 NDR、不做病毒库特征匹配（交给现有 HIDS/AV）
- 不做漏洞扫描（消费漏扫平台结果做资产关联即可）
- 不做全量日志长期存储（只存安全事件 + 关键审计，6 个月）

### 1.3 为什么云安全中心不够用

| 差距 | 说明 |
|---|---|
| 策略不可定制 | 表达不了"生产库禁止 `docker exec` 进容器""跳板机禁止 `scp` 到公网"这类业务规则 |
| 多云不统一 | 阿里云、腾讯云、华为云、IDC 各一套控制台，值班开四个页面 |
| 深度不足 | 多数云 Agent 以命令审计 + 基线为主，内核回调级拦截和文件实时拦截有限 |
| 闭环断裂 | 告警出不了云控制台，进不了自有工单 / 飞书值班体系 |
| 数据主权 | 部分行业要求事件数据不出域、可私有化 |

**结论**：云厂商能力作为「合规兜底层」保留，本系统作为「业务策略层 + 深度检测层 + 值班闭环层」。

### 1.4 内核能力是硬约束（全文骨架）

Linux 方案的第一个事实：**不是所有机器都能拦。** 按能做的事分三档：

| 档位 | 条件 | 能拿到 | 能做什么 | 占比预估 |
|---|---|---|---|---|
| **A** | 内核 ≥5.7 且 `/sys/kernel/security/lsm` 含 `bpf` | filename + **argv** + 父进程链 + cgroup | 按命令行参数精确拦截、内核态拦截文件写 | 新建集群多为此档 |
| **B** | 内核 ≥5.0，但无 BPF LSM | 只有文件路径 | 按可执行文件路径拦截（`fanotify FAN_OPEN_EXEC_PERM`） | 存量 Ubuntu 20.04 / TencentOS |
| **C** | <5.0 或容器内无特权 | 只有审计日志 | 只告警，事后处置 | CentOS 7 存量 |

**关键设计要求**：策略引擎必须感知主机档位，**同一条规则在 C 档主机上自动降级为 alert**，绝不能出现"策略显示已启用、实际根本没拦"的假象。这是多发行版环境里最容易出的事故。

---

## 2. 总体架构

### 2.1 分层图

```
管控面 Control Plane（云端 / 私有化均可）
├── 策略中心        规则版本、灰度发布、白名单
├── 资产台账        主机、标签、能力档位（A/B/C）
├── 事件检索        热 7d / 温 90d / 冷 180d
├── 值班工单        分级、SLA、升级路径
└── 合规报表        等保检查项、审计导出
        ▲  策略下发（mTLS，增量 + 签名，按档位分发）
        │
        ▼  事件上报（WAL → 批量 → zstd → 边缘聚合）

数据面 Agent（每台主机常驻，systemd 服务）
├── ① 采集层      Exec 探针 · Kernel 探针 · File 探针
│                     │
│                     └──▶ ringbuf（内核态 → 用户态）
├── ② 检测层      规则匹配 · 基线比对 · IOC 与上下文富化
├── ③ 决策层      风险打分 · 白名单 · 灰度状态机 · 档位裁决
├── ④ 执行层      LSM 拒绝 / fanotify 拒绝 / 杀进程 / 网络隔离 / 回滚
└── 支撑          本地 WAL（断电不丢）· 本地规则包（离线可用）· 看门狗（自愈）
```

> 热路径（①→④）全程不落盘、不发网络；任何一步异常都 fallback 到只记录。

### 2.2 模块职责

| 模块 | 职责 | 关键约束 |
|---|---|---|
| Exec 探针 | 进程创建、命令行、父子链、会话、cgroup | 必须在放行**之前**给出决策 |
| Kernel 探针 | 模块加载、BPF 滥用、内核内存、提权 | 内核态无循环、无睡眠、栈 ≤512B |
| File 探针 | 关键路径读写、属性变更、哈希 | 不能因事件风暴拖垮宿主机 |
| 事件总线 | ringbuf 汇聚、序列化、本地落盘 | 用户态消费跟不上就丢事件 |
| 检测层 | 规则匹配 + 基线比对 + 上下文富化 | 纯内存，P99 < 1ms |
| 决策层 | 打分、白名单、灰度、档位降级 | 决策必须可解释（命中哪条规则） |
| 执行层 | 放行/阻断/杀进程/隔离/回滚 | 阻断失败必须 fail-open（L4 除外） |
| 上报通道 | 批量压缩、断网缓存、mTLS | 离线至少缓存 24h |

### 2.3 三条数据流

1. **检测链路（热）**：内核 → ringbuf → 检测 → 决策 → 执行，不落盘不发网络。
2. **上报链路（冷）**：事件 → WAL → 批量 → 压缩 → 边缘聚合 → 存储。
3. **策略链路（控制）**：版本化 → 签名 → 按档位增量下发 → 加载 → 生效回执。

---

## 3. 能力一：核心命令拦截

### 3.1 先定义"核心命令"

**不按命令名定义，按行为后果定义。** 同一个 `rm`，删 `/tmp/build` 和删 `/etc` 是两件事。

| 类别 | 典型命令 | 默认动作 |
|---|---|---|
| 破坏性删除 | `rm -rf /`、`rm -rf /etc`、`find / -delete` | 阻断 |
| 磁盘/文件系统 | `dd of=/dev/sd*`、`mkfs.*`、`wipefs`、`shred /dev/*` | 阻断 |
| 关机重启 | `shutdown`、`reboot`、`init 0`、`kexec` | 告警（生产阻断） |
| 账户与权限 | `useradd`、`usermod -aG sudo`、写 `/etc/sudoers` | 告警 |
| 网络与防火墙 | `iptables -F`、`nft flush`、`ip link set down`、删默认路由 | 告警（核心链路阻断） |
| 内核与模块 | `insmod`、`modprobe`、`rmmod`、写 `/proc/sys/kernel/*` | 阻断（白名单除外） |
| 安全组件对抗 | `kill` 安全进程、`systemctl stop` 安全服务、`chattr -i`、`setenforce 0` | 阻断 |
| 远程执行 | `curl \| bash`、`wget -O- \| sh`、`nc -e`、`bash -i >& /dev/tcp/*` | 阻断 |
| 数据外发 | `scp`/`rsync` 到非白名单、`tar czf` 打包 `/etc` | 告警 |
| 持久化 | `crontab`、`systemd` unit、`~/.ssh/authorized_keys`、`/etc/ld.so.preload`、`.bashrc` | 阻断 + 告警 |

完整清单见 **附录 B**。

### 3.2 A 档：eBPF LSM 原生拦截

**为什么必须是 LSM**：`execve` 成功之前，只有 `bprm_check_security` 这个钩子能返回 `-EPERM` 把进程掐死在门内。tracepoint 只能事后观察。

```
execve()
  └─▶ security_bprm_check()
        └─▶ BPF LSM 程序（BPF_PROG_TYPE_LSM，attach bprm_check_security）
              ├── bpf_probe_read_kernel_str(bprm->filename)   → 可执行文件路径
              ├── 读 bprm->mm->arg_start / argc                → 真实 argv
              ├── bpf_get_current_task() 回溯父进程链
              ├── 查 BPF hash map（规则集常驻内存，O(1)）
              ├── 命中 → return -EPERM    （进程根本没起来）
              └── 未命中 → return 0
```

**实现要点：**

- **argv 读取**：`bprm->mm->arg_start` 在 `bprm_check_security` 阶段已被内核填好，`bpf_probe_read_kernel_str` 一次拷完立刻判定，不要分多次读（避免逐次读之间的竞态）。
- **规则查找**：规则预编译进 `BPF_MAP_TYPE_HASH`（路径精确匹配）和 `BPF_MAP_TYPE_LPM_TRIE`（前缀匹配），LSM 回调里只做 map lookup，不做字符串正则。
- **复杂规则前置到用户态**：正则、语义解析、上下文关联都在用户态算好，热路径只接收"路径 → 动作"的扁平表。这样 LSM 程序可以做到 100 行以内。
- **绝不匹配复杂模式**：BPF 校验器对循环和指令数有限制，正则放进去必然被踢回来。
- **程序持久化**：用 `bpf_link` 而非 raw fd 持有 attach 句柄。**Agent 进程退出 → link 自动 detach → 拦截自动失效**，这是刻意的设计：宁可"守护进程挂了就只剩告警"，也不要留下没人管的僵尸策略拦住业务。规则 map 仍可 pin 在 `/sys/fs/bpf/watchdog/` 供重启后快速恢复。

**LSM 钩子选择表：**

| 钩子 | 用途 |
|---|---|
| `bprm_check_security` | 拦 exec，拿 argv |
| `file_open` | 拦写 `/dev/sd*`、`/dev/mem`、`/proc/sys/*` |
| `inode_unlink` / `inode_rename` | 拦删改关键文件 |
| `inode_setattr` | 拦 `chmod`/`chattr` 关键文件 |
| `kernel_module_request` / `kernel_load_data` | 拦模块加载 |
| `task_kill` | 拦杀安全进程 |
| `bpf` | 拦非授权的 BPF 程序加载 |

**能力验证（必须实测，不能只看版本号）：**

```bash
# 唯一权威判据：运行时已启用的 LSM 列表
cat /sys/kernel/security/lsm        # 输出里必须有 "bpf"
# 编译配置
zcat /proc/config.gz | grep CONFIG_BPF_LSM    # 或 /boot/config-$(uname -r)
```

`CONFIG_BPF_LSM=y` 在多数发行版默认开着但**不在默认 LSM 列表里**。不加 `lsm=bpf` 启动参数时，钩子**完全不生效，也不报任何错**——这是本方案最大的坑，纳管必须逐台实测。grub 配置：

```
GRUB_CMDLINE_LINUX="... lsm=lockdown,yama,integrity,apparmor,bpf"
```

### 3.3 B 档：fanotify 路径级拦截

内核 5.0+ 支持 `FAN_OPEN_EXEC_PERM`，可以在 exec 之前拿到权限事件并拒绝。拿不到 argv，但能按路径拦。

```c
fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
              O_RDONLY | O_LARGEFILE | O_CLOEXEC);
fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
              FAN_OPEN_EXEC_PERM, AT_FDCWD, "/");
```

- `FAN_MARK_FILESYSTEM`（整挂载点递归）需 5.13+；更低版本按挂载点逐个 `FAN_MARK_MOUNT`
- 收到事件后读 `/proc/<pid>/cmdline` 补 argv（有 TOCTOU，判错就漏，但方向是"宁可漏不可误"）
- 事件处理必须**多线程 + 高优先级**：每个被拦的 exec 都在等你的响应，用户态一卡，全机 exec 都卡

### 3.4 C 档：auditd 审计，仅告警

```
-a always,exit -F arch=b64 -S execve -F exit=0 -k exec_watch
-w /etc/passwd -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd
```

延迟秒级，只能事后。**价值在于把 C 档主机纳入统一事件流**，而不是提供保护。

### 3.5 语义鸿沟（必须承认的局限）

`execve` 只看到最终被执行的二进制：

| 场景 | 探针看到 | 用户以为 |
|---|---|---|
| `bash -c "rm -rf /"` | `/usr/bin/bash -c rm -rf /` | 拦 `rm`（A 档能还原） |
| `echo cm0gLXJmIC8= \| base64 -d \| sh` | `sh` | 拦 `rm` |
| `python -c "shutil.rmtree('/')"` | `python3` | 拦 `rm` |
| `busybox rm -rf /` | `busybox` | 拦 `rm` |
| 静态编译的恶意二进制 | 陌生 ELF | — |

**四层对策：**

1. **解析 `-c` 字符串**：用户态对 `bash -c` / `sh -c` 做轻量分词还原真实命令（只用于**告警增强**，不用于热路径阻断）
2. **行为拦截优先**：`file_open(O_WRONLY)` 打 `/dev/sd*`、`inode_unlink` 打 `/etc`、`kernel_module_request` —— 这些是绕不过去的
3. **上下文关联**：父进程是 `sshd`/`cron`/`docker exec` + uid=0 + 非变更窗口 → 提升风险分
4. **接受不完美**：目标是"高置信告警 + 关键路径硬阻断"，不是滴水不漏

### 3.6 误杀控制（决定项目生死）

| 机制 | 做法 |
|---|---|
| 三态发布 | `observe`（只记录）→ `alert`（告警不拦）→ `enforce`（真拦），每条规则独立走完 |
| 灰度 | 按标签（prod/staging）、按百分比、按时间段逐步放量 |
| 白名单 | 带 **TTL + 审批人 + 到期提醒**，杜绝"临时放开变永久" |
| Kill Switch | 本地哨兵文件 + 云端指令 + 心跳超时自动降级，三种任一可用 |
| 回滚 | 策略版本化，一键回滚，30 秒内全量生效 |
| 演练 | staging 用真实业务脚本跑 72 小时影子模式，统计误报率 |

---

## 4. 能力二：内核安全

### 4.1 监控面

| 攻击面 | 钩子 | 威胁 |
|---|---|---|
| 模块加载 | kprobe `load_module`、tracepoint `module_load` | rootkit |
| 内核内存写入 | `file_open` on `/dev/mem`、`/dev/kmem` | 打补丁 |
| eBPF 滥用 | `bpf()` syscall 参数（隐藏进程/文件） | 隐身 |
| 提权 | kprobe `commit_creds` 前后 uid 对比 | 本地提权 |
| 注入/调试 | `ptrace(PTRACE_ATTACH)`、`process_vm_writev` | 凭据窃取 |
| 启动链 | `kexec_load`、`/boot` 完整性 | bootkit |
| 内核配置 | 写 `/proc/sys/kernel/*`、`/proc/sys/vm/*` | 关防护 |
| 命名空间逃逸 | `setns`、`nsenter`、`mount --bind /` on host | 容器逃逸 |

### 4.2 硬化基线（可直接当验收清单）

```
kernel.kptr_restrict = 2            # 隐藏内核符号地址
kernel.dmesg_restrict = 1           # 非 root 不可读 dmesg
kernel.unprivileged_bpf_disabled = 2
kernel.kexec_load_disabled = 1
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 3        # 禁止任意 ptrace
kernel.perf_event_paranoid = 3
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
```

启动参数：`module.sig_enforce=1`（强制模块签名）、`lockdown=confidentiality`（5.4+，锁死 `/dev/mem`、kexec）、`slab_nomerge`、`init_on_alloc=1`。
内核编译项：`CONFIG_STRICT_KERNEL_RWX`、`CONFIG_STRICT_MODULE_RWX`、`CONFIG_DEBUG_WX`、`CONFIG_STACKPROTECTOR_STRONG`。

> `kernel.modules_disabled=1` 是"核弹开关"——开启后永远无法再加载模块，只适合启动后不再需要模块的专用设备。

### 4.3 rootkit 检测思路

内核级 rootkit 的本质是**让用户态看到的世界与真实世界不一致**。检测就是找这种不一致：

| 手段 | 做法 |
|---|---|
| 模块列表交叉验证 | `/proc/modules` 与 `/sys/module/` 目录对比，缺一即可疑 |
| 符号地址异常 | `/proc/kallsyms` 中 `sys_call_table`、`do_sys_open` 地址与基线比对；落在模块地址段即可疑 |
| 模块签名 | `modinfo -F sig_id` 为空且非白名单 → 高危 |
| 隐藏进程 | `kill -0` 遍历 `/proc` 与 `ps` 输出对比（轻量版），或直接读 `/proc` 目录项与 `getdents` 结果比对 |
| 内核文本段 | `/sys/kernel/debug/kernel_page_tables`（需 root + DEBUG_WX）检查可写映射 |
| 定时器/ftrace | `ftrace` 被占用且非本 Agent 使用 → 可疑 |

> 完整的 rootkit 检测（读块设备重建目录树）代价太大，不走这条路。A 档主机上 eBPF LSM 本身就是最好防线——rootkit 想藏起来就得先加载模块，而模块加载已被拦。

### 4.4 内核完整性基线

| 项 | 采集 | 频率 |
|---|---|---|
| 内核版本 / 编译时间 | `uname -a` | 启动 + 每日 |
| 已加载模块 + 签名 | `/proc/modules`、`modinfo` | 启动 + 变更事件 |
| 关键符号地址 | `/proc/kallsyms` | 启动 + 每日 |
| 内核配置 | `/boot/config-$(uname -r)` | 每日 |
| 启动项 | `/boot/grub2/grub.cfg`、EFI 分区 | 每日 |
| sysctl 快照 | `sysctl -a` | 每日 |

差异即告警；基线自身受 5.1 的 L3 文件保护。

---

## 5. 能力三：文件变动监控（FIM）

### 5.1 监控分级

| 级别 | 路径示例 | 处置 |
|---|---|---|
| L0 静默 | `/tmp`、`/var/log/*.log`、`/proc`、`/sys` | 不采集 |
| L1 记录 | `/var/www`、应用日志目录 | 入库，聚合摘要 |
| L2 告警 | `/etc`（非变更窗口）、`/opt/app/config` | IM 告警 |
| L3 阻断 | `/etc/passwd`、`/etc/shadow`、`/etc/sudoers`、`~/.ssh/authorized_keys`、`/etc/cron*`、`/etc/systemd/system/*`、`/etc/ld.so.preload`、`/boot/*`、Agent 自身目录 | 拒绝写入 + 告警 + 工单 |

### 5.2 方案对比

| 方案 | 实时 | 可拦截 | 递归 | 开销 | 局限 |
|---|---|---|---|---|---|
| inotify | ✅ | ❌ | 需逐目录 `add_watch` | 中 | `max_user_watches` 上限，易漏事件 |
| fanotify | ✅ | ✅ `FAN_OPEN_PERM` | `FAN_MARK_FILESYSTEM`（5.13+） | 低 | 需 `CAP_SYS_ADMIN` |
| eBPF `vfs_*` | ✅ | ✅（配 LSM） | ✅ | 低 | 需内核版本 |
| auditd `-w -p wa` | ✅ | ❌ | ✅ | 中 | 规则数上限，重启丢失 |
| 周期哈希（AIDE 式） | ❌ | ❌ | ✅ | 高（全盘） | 只能事后 |

**推荐组合**：eBPF 实时为主 + fanotify 兜底（B 档）+ 周期哈希做完整性证明（C 档唯一手段）。

### 5.3 基线策略

- **首次全量哈希**（SHA-256），排除虚拟磁盘、大文件、缓存目录
- **实时变更**即时上报，**每日增量校验**、**每周全量校验**
- `ssdeep` 相似度区分「改配置」与「换文件」——换文件更可疑
- **变更窗口**：发布窗口内 L1，窗口外同路径 L2/L3
- 基线库哈希存云端，本地被改可发现

### 5.4 容器场景

- 容器内 FIM 意义有限（镜像不可变），重点监控**宿主机侧**：`/var/lib/kubelet`、`/etc/kubernetes`、`docker.sock`、`containerd` 配置、`/var/lib/docker`
- 逃逸检测：读 `/proc/1/root`、`nsenter` 到 host namespace、`mount` 宿主路径、异常 capabilities、`/proc/sysrq-trigger`
- 云盘快照作为 L4 恢复手段，与事件时间点对齐

---

## 6. 策略引擎与决策

### 6.1 规则模型

```yaml
apiVersion: watchdog/v1
kind: Rule
metadata:
  id: R-EXEC-0012
  name: 禁止删除根目录或系统关键目录
  severity: critical
  tags: [destructive, "mitre:T1485"]
spec:
  match:
    event: process_exec
    all:
      - exe_in: [/bin/rm, /usr/bin/rm]
      - argv_regex: '(^|\s)-[a-zA-Z]*[rf][a-zA-Z]*\s+(/|/\*|/etc|/usr|/var|/boot)(\s|$)'
  action:
    type: block                 # 在 C 档主机上自动降级为 alert
    response: [alert_card, record]
  exception:
    users: [deploy]
    hosts: ["tag:batch-job"]
  rollout:
    mode: enforce               # observe | alert | enforce
    percent: 100
    since: "2026-12-01"
```

### 6.2 决策流水线

```
事件 → 归一化 → 富化（资产 / 身份 / 威胁情报 / 时间窗口）
     → 档位裁决（A: 全能力 / B: 仅路径 / C: 仅告警）
     → 规则匹配（本地规则包 + 云端策略）
     → 风险打分
     → 决策 ┬ allow
            ├ alert（异步上报）
            └ block（同步返回 -EPERM / fanotify 拒绝）
```

时延预算：热路径 P99 < 2ms，规则匹配 < 1ms。

### 6.3 灰度与例外

- 灰度维度：规则 × 主机标签 × 百分比 × 时间窗
- 例外必须有：审批人、原因、TTL、到期自动失效、审计记录
- 每条规则强制经过 observe 阶段，observe 期数据用于评估误报率

### 6.4 双引擎

| 引擎 | 作用 | 特点 |
|---|---|---|
| 本地引擎 | 断网 / 管控面失联时仍工作 | 规则包签名、启动加载、只读 |
| 云端引擎 | 集中管理、跨主机关联、评分 | 版本化、增量下发、可回滚 |

---

## 7. 响应分级

| 级别 | 名称 | 动作 | 自动化 | 示例 |
|---|---|---|---|---|
| L0 | 记录 | 入库、聚合 | 全自动 | 普通文件变更 |
| L1 | 告警 | IM 卡片 + 工单 | 全自动 | 敏感文件被改 |
| L2 | 阻断 | 拒绝系统调用 | 全自动 | `rm -rf /`、加载未签名模块 |
| L3 | 遏制 | 杀进程 + 断网 + 冻结账号 + 快照 | 半自动（需确认） | 反弹 shell、挖矿 |
| L4 | 恢复 | 快照回滚、配置还原、重装 | 人工 | 勒索加密、内核被植入 |

**原则**：L2 以下全自动；L3 需值班人一键确认；L4 必须双人复核。

---

## 8. 事件模型与数据管道

### 8.1 事件 Schema

```json
{
  "event_id": "01JC8Z3K7Q2M9X",
  "ts": "2026-11-20T23:12:00.123+08:00",
  "host": {
    "id": "i-bp1xxxx",
    "name": "prod-db-01",
    "kernel": "5.10.0-28-amd64",
    "tier": "A",
    "cloud": { "provider": "aliyun", "region": "cn-hangzhou" },
    "tags": ["prod", "db"]
  },
  "category": "process_exec",
  "subject": {
    "pid": 12873, "ppid": 12800, "uid": 0, "gid": 0,
    "comm": "bash", "exe": "/usr/bin/bash",
    "cmdline": ["bash", "-c", "rm -rf /tmp/cache"],
    "cwd": "/root", "session": "ssh:10.0.0.5",
    "cgroup": "/system.slice/sshd.service"
  },
  "object": { "path": "/usr/bin/rm", "inode": 131075, "hash": "sha256:..." },
  "action": { "decision": "block", "rule_id": "R-EXEC-0012", "latency_us": 840 },
  "risk": { "score": 92, "tags": ["destructive", "root"] },
  "raw": { "hook": "bprm_check_security" }
}
```

### 8.2 上报

- **本地 WAL**：先落盘再上报，断电不丢
- **批量**：1000 条 / 5s 触发，zstd 压缩
- **mTLS** 双向认证，证书由管控面签发并轮换
- **断网缓存**：至少 24h，恢复后按时间序补传
- **边缘聚合**：每 region 一个 collector，避免跨区带宽

### 8.3 存储

| 层 | 介质 | 保留 | 用途 |
|---|---|---|---|
| 热 | ClickHouse / ES | 7 天 | 检索、看板 |
| 温 | 对象存储 + 索引 | 90 天 | 溯源 |
| 冷 | 对象存储归档 | 6 个月 | 合规 |

**事件风暴治理**：高频文件事件按「主机 + 路径 + 5 分钟窗口」聚合成摘要，只留首末条 + 计数；阻断类事件永不聚合。

---

## 9. 安全值守（值班运营）

技术只是工具，**值守流程才是产品**。

### 9.1 告警分级与 SLA

| 级别 | 首次响应 | 处置时限 | 升级规则 |
|---|---|---|---|
| P0 | 5 min | 30 min | 15 min 未响应 → 值班主管 → 安全负责人 |
| P1 | 15 min | 2 h | 1 h 未响应 → 升级 |
| P2 | 1 h | 24 h | 次日复盘 |
| P3 | 次日 | 1 周 | 周会汇总 |

### 9.2 值班组织

- 一线（研判）：确认真实性、定级、初判影响面
- 二线（处置）：遏制、取证、恢复
- 三线（研发）：规则优化、Agent 问题、误报治理
- 交接班清单：未闭环 P0/P1、在途变更、已知误报、Agent 离线清单

### 9.3 IM 联动

复用已有转发通道（本工作区 `dingtalk-relay` + 飞书卡片方案已验证可用）：

- 告警以**图片卡片**推送，高亮命中命令 / 路径 / 主机
- P0/P1 卡片带「阻断 / 放行 / 隔离 / 转工单」按钮
- 按钮回调管控面 API，结果回写卡片（闭环，不用切系统）
- 静默规则：同主机同规则 5 分钟内合并

### 9.4 处置 SOP

```
确认（真/假） → 遏制（隔离/杀进程） → 取证（内存/磁盘/日志快照）
→ 根除（清持久化） → 恢复（回滚/重装） → 复盘（5 Whys）
→ 沉淀（新增规则 / 白名单 / 检测项）
```

每次 P0/P1 必须产出：时间线、根因、影响面、改进项（带负责人和截止日期）。

---

## 10. 部署形态

### 10.1 systemd 服务

```ini
[Unit]
Description=Security Watchdog Agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=notify
ExecStart=/usr/lib/watchdog/watchdog --config /etc/watchdog/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitMEMLOCK=infinity
CPUQuota=100%
MemoryMax=256M
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

> `LimitMEMLOCK=infinity` 是 BPF map 的前提，漏了会在 `bpf_create_map` 报 `Operation not permitted`，且报错信息完全不提 memlock —— 第二个常见坑。

### 10.2 Kubernetes

```yaml
kind: DaemonSet
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      containers:
        - name: watchdog
          securityContext:
            privileged: true     # 或精确 capabilities + seccomp
          volumeMounts:
            - { name: proc, mountPath: /host/proc }
            - { name: sys,  mountPath: /host/sys }
            - { name: bpf,  mountPath: /sys/fs/bpf }
            - { name: etc,  mountPath: /host/etc, readOnly: true }
```

### 10.3 打包与升级

- 静态编译（musl 或 `-static`），单二进制 + 规则包
- RPM/DEB 双格式，`/usr/lib/watchdog/`（程序）、`/etc/watchdog/`（配置）、`/var/lib/watchdog/`（WAL、基线）
- 升级：双版本目录 + 原子软链切换 + 失败自动回滚
- 卸载：需口令 + 工单审批（防攻击者卸载）

---

## 11. 非功能设计

### 11.1 性能预算

| 指标 | 目标 |
|---|---|
| 空闲 CPU | < 1% |
| 峰值 CPU | < 5% 单核 |
| 内存 RSS | < 150 MB |
| 拦截时延 P99 | < 2 ms |
| 事件吞吐 | 5k EPS/主机（突发） |
| 事件丢失率 | < 0.01% |

### 11.2 稳定性

- 采集层与业务解耦：独立进程 + 看门狗，崩溃自动拉起
- 内核态程序：无循环、无睡眠、栈 < 512B（BPF 校验器强制）
- ringbuf 满：丢弃并计数，上报 `event_drop` 指标（丢事件本身就是告警）
- **fail-open 默认**：阻断通道异常时放行；仅 L4 场景 fail-close
- 升级灰度：1% → 10% → 50% → 100%，异常自动回滚

### 11.3 自保护

| 手段 | 做法 |
|---|---|
| 进程/文件保护 | A 档主机用 LSM 程序拒绝 `unlink`/`open(O_WRONLY)` 打到 `/usr/lib/watchdog/*`、`/etc/watchdog/*` |
| 权限最小化 | `CapabilityBoundingSet` 只留必需项，不用全 root |
| 通信 | mTLS + 请求签名 + 防重放 |
| 卸载 | 口令 + 工单 |
| 静默失联 | 心跳缺失 → 云端判定离线并告警（防"先卸载再攻击"） |

### 11.4 合规

- 等保 2.0 三级：入侵防范、恶意代码防范、集中管控、安全审计
- 《网络安全法》日志留存 ≥ 6 个月
- 命令行**脱敏**：命中 `password=`、`--token`、`Authorization:` 等模式打码后再入库
- 数据分级：命令行为「敏感」，文件内容不采集，只采哈希

---

## 12. 实施路线图

| 阶段 | 周期 | 交付物 | 验收 |
|---|---|---|---|
| **P0 看得见** | 2 周 | 能力探测（A/B/C 分档）+ exec 审计 + 关键文件监控 + 飞书卡片 | 能看见、能告警 |
| **P1 拦得住** | 4 周 | eBPF LSM 阻断 + 规则引擎 + 灰度机制 + Kill Switch | `rm -rf /` 拦住且不误伤 |
| **P2 有深度** | 8 周 | 内核监控 + 完整性基线 + 容器逃逸检测 | 覆盖 5 类内核异常 |
| **P3 成体系** | 12 周 | 自动化响应 + 多集群策略编排 + 权限最小化改造 | L3 半自动处置上线 |

> 顺序刻意如此：**先能看见，再能拦住，最后做深**。反过来做，会在没有误报数据的情况下拍脑袋定规则，第一次灰度就打断业务。

---

## 13. 主要风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| 存量机器内核过低（CentOS 7） | 无法阻断 | 分档 + 自动降级为告警；推动 OS 升级 |
| `lsm=bpf` 未开启且无报错 | 假象"已拦截" | 纳管时读 `/sys/kernel/security/lsm` 实测，加入巡检项 |
| 误拦截打断业务 | 生产事故 | 三态灰度 + Kill Switch + 白名单 TTL |
| 命令语义被绕过 | 漏报 | 行为拦截为主（`file_open`/`unlink`/`module_load`） |
| 事件风暴压垮存储 | 成本/稳定性 | 聚合 + 采样 + 分级保留 |
| 与云厂商 Agent 抢钩子 | 性能下降 | 错开 kprobe 点、压测、厂商兼容确认 |
| 团队缺少内核开发经验 | 项目停滞 | P0/P1 全用 eBPF（门槛远低于写内核模块），libbpf + CO-RE 是现成范式，不必碰内核源码 |

---

## 附录 A：发行版兼容矩阵

| 发行版 | 默认内核 | BPF LSM | fanotify EXEC_PERM | 档位 | 备注 |
|---|---|---|---|---|---|
| CentOS 7 | 3.10 | ❌ | ❌ | C | 只能 auditd |
| CentOS 8 / Rocky 8 | 4.18 | ❌ | ❌（需 5.0） | C | |
| Ubuntu 18.04 | 4.15 | ❌ | ❌ | C | |
| Ubuntu 20.04 | 5.4 | ❌ | ✅ | B | |
| Ubuntu 22.04 / 24.04 | 5.15 / 6.8 | ✅（需 `lsm=bpf`） | ✅ | A | |
| Debian 11 | 5.10 | ✅（需确认配置） | ✅ | A | |
| Debian 12 | 6.1 | ✅ | ✅ | A | |
| Alibaba Cloud Linux 2 | 4.19 | ❌ | ✅ | B | 需实测 |
| Alibaba Cloud Linux 3 / Anolis 8 | 5.10 | ✅（需实测） | ✅ | A | 云上主力 |
| TencentOS Server 3 | 5.4 | ❌ | ✅ | B | |
| openEuler 22.03 | 5.10 | ✅（需实测） | ✅ | A | |
| K8s 容器内（无特权） | 宿主内核 | — | — | C | 由宿主机 DaemonSet 代拦 |

> 表里 "需实测" 的都是不能只看版本号推断的：**必须跑附录 C 的探测脚本拿到运行时结论**。

## 附录 B：核心命令清单（节选）

| 类别 | 命令/模式 |
|---|---|
| 破坏性删除 | `rm -rf /`、`rm -rf /etc`、`rm -rf /usr`、`find / -delete`、`shred`、`> /etc/passwd` |
| 磁盘操作 | `dd of=/dev/sd*`、`dd of=/dev/nvme*`、`mkfs.*`、`wipefs`、`fdisk`、`parted mklabel` |
| 关机重启 | `shutdown`、`reboot`、`halt`、`poweroff`、`init 0`、`kexec -l` |
| 账户权限 | `useradd`、`usermod -aG sudo`、`passwd`、`chpasswd`、`visudo`、写 `/etc/sudoers.d/*` |
| 网络防火墙 | `iptables -F`、`iptables -P INPUT ACCEPT`、`nft flush ruleset`、`ip link set down`、`ip route del default` |
| 内核模块 | `insmod`、`modprobe`、`rmmod`、`depmod`、写 `/proc/sys/kernel/modprobe` |
| 安全对抗 | `kill <安全进程>`、`systemctl stop <安全服务>`、`chattr -i`、`setenforce 0`、停 `auditd` |
| 远程执行 | `curl ... \| bash`、`wget -O- \| sh`、`nc -e`、`bash -i >& /dev/tcp/*`、`socat exec:` |
| 持久化 | 写 `crontab`、`/etc/cron.*`、`systemd` unit、`~/.ssh/authorized_keys`、`/etc/ld.so.preload`、`.bashrc` 追加 |
| 数据外发 | `scp`/`rsync` 到非白名单 IP、`tar czf` 打包 `/etc`、`base64` + `curl -d` |

## 附录 C：主机能力探测脚本

纳管第一件事就是跑这个，输出直接回填资产台账的 `tier` 字段。

```bash
#!/usr/bin/env bash
# watchdog-probe.sh —— 判定主机拦截能力档位（A/B/C）
# 用法：sudo bash watchdog-probe.sh
set -u

KREL=$(uname -r)
KMAJ=${KREL%%.*}
KREST=${KREL#*.}
KMIN=${KREST%%.*}

say() { printf '  %-22s %s\n' "$1" "$2"; }
ge()  { [ "$KMAJ" -gt "$1" ] && return 0
        [ "$KMAJ" -eq "$1" ] && [ "$KMIN" -ge "$2" ] && return 0
        return 1; }

echo "== 主机信息 =="
say "hostname" "$(hostname)"
say "kernel"   "$KREL"
[ -r /etc/os-release ] && say "distro" "$(. /etc/os-release && echo "$PRETTY_NAME")"

# --- 1. LSM 运行时状态（唯一权威判据）---
LSMS=$(cat /sys/kernel/security/lsm 2>/dev/null || true)
say "active LSM" "${LSMS:-<unreadable>}"

BPF_LSM=0
if [ -n "$LSMS" ] && echo "$LSMS" | tr ',' '\n' | grep -qx 'bpf'; then
  BPF_LSM=1
fi
say "bpf LSM enabled" "$([ "$BPF_LSM" -eq 1 ] && echo yes || echo no)"

# --- 2. 内核编译配置 ---
cfg_get() {
  local key=$1 f
  for f in "/boot/config-$KREL" /proc/config.gz; do
    [ -r "$f" ] || continue
    zcat -f "$f" 2>/dev/null | grep -m1 "^${key}=" | cut -d= -f2
    return 0
  done
  echo "unknown"
}
say "CONFIG_BPF_LSM"       "$(cfg_get CONFIG_BPF_LSM)"
say "CONFIG_DEBUG_INFO_BTF" "$(cfg_get CONFIG_DEBUG_INFO_BTF)"
say "CONFIG_FANOTIFY"      "$(cfg_get CONFIG_FANOTIFY)"

# --- 3. BTF（CO-RE 编译前提）---
if [ -r /sys/kernel/btf/vmlinux ]; then
  say "vmlinux BTF" yes
else
  say "vmlinux BTF" "no (需外置 BTF 或按内核编译)"
fi

# --- 4. 运行权限 ---
if [ "$(id -u)" -eq 0 ]; then
  CAPS=$(grep -m1 '^CapEff:' /proc/self/status | awk '{print $2}')
  say "CapEff" "${CAPS:-unknown}"
else
  say "root" "no —— 请用 sudo 重新执行"
fi

# --- 5. 判档 ---
echo "== 结论 =="
if [ "$BPF_LSM" -eq 1 ]; then
  TIER=A
  ACTION="eBPF LSM 原生拦截（argv 级，可精确匹配命令行参数）"
elif ge 5 0; then
  TIER=B
  ACTION="fanotify FAN_OPEN_EXEC_PERM 路径级拦截（拿不到 argv）"
else
  TIER=C
  ACTION="auditd 审计，仅告警，无阻断能力"
fi
say "TIER" "$TIER"
say "capability" "$ACTION"

# --- 6. 给运维的下一步提示 ---
if [ "$BPF_LSM" -eq 0 ] && [ "$(cfg_get CONFIG_BPF_LSM)" = "y" ]; then
  echo
  echo "!! 内核已编译 BPF LSM 但未启用，加上启动参数可升到 A 档："
  echo "   grubby --update-kernel=ALL --args='lsm=lockdown,yama,integrity,apparmor,bpf'"
  echo "   （先确认现有 LSM 列表，别把 SELinux/AppArmor 写丢了）"
fi
```

**判档后的动作：**

| 档位 | 策略动作 |
|---|---|
| A | 全能力：命令参数级阻断 + 文件写拦截 + 内核监控 |
| B | 降级：按可执行文件路径阻断，命令行只做告警 |
| C | 只告警：全部规则 `action` 强制降为 `alert`，并在看板标红 |

---

*本文档为架构设计初稿，具体规则集、阈值和 SLA 需结合业务实际压测与试运行数据校准。*
