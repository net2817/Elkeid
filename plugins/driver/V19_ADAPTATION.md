# driver v1.9 插件适配说明（plugins/driver）

本文件说明将 `plugins/driver` 从 v1.7 接口适配到 v1.9（`driver/` 包，来源 `v3.0` 分支）所需改动。

## 一、v1.7 → v1.9 接口差异

| 层面 | v1.7（旧 plugins/driver） | v1.9（新 driver/rust ringslot 库） |
|---|---|---|
| 事件读取 | `File::open("/proc/elkeid-endpoint")` + `BufReader::split(0x17)` | `ringslot::RingSlot::new(RING_KMOD_V1_9, "/sys/module/elkeid/parameters/control_trace")` + `read_record()` |
| 白名单控制 | 写 `/dev/hids_driver_allowlist`（`Y/path`、`m/argv`） | `ringslot::SmithControl`：`ac_add_allow_exe/argv()`（AL_TYPE_EXE/ARGV） |
| HIPS 阻断 | ❌ 无 | `ac_set_block_exe_argv()`（BL_JSON_EXE）、`ac_set_block_md5()`（BL_JSON_MD5）、`ac_set_block_dns()`（BL_JSON_DNS） |
| 自保护 | ❌ 无 | `self_protection_enable/disable()`（protector_switch） |
| 端口扫描 PSAD | 仅模块参数 | `psad_enable()` + `psad_add_allowlist_ipv4/6()` + `psad_set_flag()` |
| eBPF | ❌ 无 | `EBPFConsumer/EBPFLoader/EBPFControl`（AL_EBPF_EXE/ARGV） |
| **事件格式** | v1.7 文本记录使用 `\x17` / `\x1e` 分隔 | 内核 ring 内部是二进制 `sd_event`；C 层 `sd_unpack` 后，Rust `RingSlot::read_record()` 收到 NUL 分隔文本 |

## 二、已完成 / 可交付部分（I/O + 控制层）

以下文件已按 ringslot 库重写：

- `Cargo.toml`：新增 `ringslot = { path = "../../driver/rust" }` 依赖
- `src/config.rs`：更新控制路径 + ringslot 常量
- `src/kmod.rs`：改为封装 `ringslot::SmithControl`（白名单/HIPS 阻断/自保护/PSAD）
- `src/main.rs`：改为用 `ringslot::RingSlot` 读事件 + `SmithControl` 下发规则

## 三、事件解析（已澄清：无需写二进制解析器）

**重要澄清**：v1.9 的事件反序列化**已在 C 层完成**。
`driver/ring/kmod.c` 的 `tb_read_kmod_v1_9` 内部调用 `sd_unpack(..., sd_query_event_v1_9)`（`driver/xfer/xfer.c`），把二进制 `sd_event` 反序列化为 **`\0` 分隔的文本字段**后返回。

因此 `ringslot::RingSlot::read_record()` 返回的是**文本**（字段间 `\0` 分隔），Rust 插件只需：

1. `rec.split(|c| *c == 0)` 切分字段；
2. 第一个字段为 data_type（xid）；
3. 按 schema 顺序把字段名映射成 `plugins::Record` 的 fields。

字段顺序由 `driver/LKM/include/kprobe_print.h` + `anti_rootkit_print.h` 的 `SD_XFER_DEFINE(... XFER(...))` 决定（含 `ENTRY_COMMON` 公共头）。

> 注意：v1.9 字段名与 v1.7 `schema.rs` 有差异（如 `exe`→`exe_path`、`sessionid`→`epoch`、`pns`→`mntns_id`、`root_pns`→`root_mntns_id`），需同步更新服务端数据字典。

已实现：`src/event.rs`（文本切分 + schema 映射）。

## 四、构建约束

- `ringslot` crate 依赖 `driver/ring` + `driver/xfer`（C，build.rs 用 `cc` 编译）+ `libbpf-sys`
- LKM 在 `driver/LKM` 用 `make` 编译，模块名 `elkeid`
- 依赖：Rust + 内核头 + `pkg-config` + `libelf-dev` + `zlib1g-dev`（构建期）

## 五、编译与运行时验证结果（Ubuntu 22.04 / 内核 5.15.0-203）

| 组件 | 结果 |
|---|---|
| driver LKM（elkeid.ko，v3.0.0.7） | ✅ gcc 编译通过；insmod 成功，kprobe 钩子全部注册 |
| ringslot 库（driver/rust） | ✅ cargo 编译通过（libbpf-sys vendored libbpf + 系统 libelf/zlib） |
| driver 插件（plugins/driver，GNU） | ✅ cargo 编译通过（仅无害警告） |
| 事件格式（运行时） | ✅ 首字段 = data_type；字段 `\0` 分隔；公共头字段顺序正确 |
| 插件运行时依赖 | ✅ 仅 glibc（ldd 无 libelf/zlib，libbpf 已静态编入） |
| musl 静态构建 | ⚠️ libbpf-sys 用 musl-gcc 编 libbpf 失败（缺 musl 版 UAPI 头 + libelf/zlib），需官方 Docker 构建镜像 |

**结论**：GNU 构建的插件对 Ubuntu 22.04 离线部署已足够（仅依赖 glibc）；musl 静态仅在跨发行版/无 glibc 环境部署时才需要。

## 六、剩余待办

1. 已将当前 LKM 的 51 个 `SD_XFER_DEFINE` schema block 与 Rust 字段表静态对照；本轮修正了 DNS IPv6（data_type 601）缺少 dip/sip 时的字段偏移。该修正尚未重新编译或回放事件，仍需覆盖所有事件 ID、缺失字段和实际后端字段字典。
2. `Record.timestamp` 以插件接收时间（Unix 秒）填写，不是内核事件发生时间；若需精确排序，应由内核事件格式提供时间戳并联调。
3. 插件处理 9001–9009 本地任务码；需补齐 Manager/Console/Agent 的策略生成、鉴权、下发与审计链路。
4. `Kmod` 只连接已加载模块；需提供与 v3.0.0.7 LKM 匹配的构建、签名、发布和安装流程。当前 driver workflow 引用的旧构建目录不在导入子树中。
5. 目前有 Ubuntu 22.04 / kernel 5.15.0-203 的单点验证记录；仍需做发行版、内核、x86_64/aarch64 矩阵验证。
6. musl 静态构建（跨发行版部署需要）。
