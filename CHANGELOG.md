# Changelog

本文件记录 `net2817/Elkeid`（bytedance/Elkeid 二次开发 fork）的发布历史。

## v1.9.1-driver-adapted（2026-11-23）

基于上游 `main`（`c906c512`）+ 精选企业版分支整合，发布驱动 v1.9 与插件适配。

### 新增 / 整合（来源分支）

| 模块 | 来源分支 | 内容 |
|---|---|---|
| `driver/` | `bytedance:v3.0` | driver v1.9：HIPS 执行阻断（exe/argv → -EPERM）、tracepoint 迁移、Rust 用户态（ringslot）、eBPF（BPF/ebpf/libbpf）、ring buffer；接口改为 `/sys/module/elkeid/parameters/control_trace` |
| `server/agent_center/` | `bytedance:2.2.3/ac` | 连接限流、配置指纹热更新、`Enhanced` 防护等级字段、zstd 压缩、心跳批量 |

### 插件适配（`plugins/driver/`）

| 文件 | 改动 |
|---|---|
| `Cargo.toml` | 新增 `ringslot` 依赖；移除 7 个无用依赖（nix/lru-cache/twox-hash/ttl_cache/walkdir/governor/users） |
| `src/config.rs` | 重写：v1.9 常量（`CONTROL_PATH`、`RING_KMOD_V1_9`、`AL_TYPE_*`/`BL_JSON_*`、模块名 `elkeid`） |
| `src/kmod.rs` | 重写：封装 `ringslot::SmithControl`（白名单放行 / HIPS 阻断 / 自保护 / PSAD） |
| `src/main.rs` | 重写：`ringslot::RingSlot` 读事件 + 控制任务处理（data_type 9001–9009）+ `event::parse_record` 上报 |
| `src/event.rs` | 新增：`\0` 文本映射器（C 层已完成 sd_event 反序列化），`has_common_header()` 处理 607/612/700-703 无公共头事件 |
| `src/lib.rs` | 移除不兼容的 v1.7 `transformer`，新增 `event` 模块 |
| `V19_ADAPTATION.md` | 新增：接口差异 + 编译/运行验证结论 + 待办 |

### 验证结果（Ubuntu 22.04 / 内核 5.15.0-203）

- ✅ driver LKM（`elkeid.ko`，v3.0.0.7）编译通过，insmod 成功，kprobe 钩子全部注册
- ✅ ringslot 库、driver 插件（GNU）编译通过
- ✅ 运行时事件采集验证：首字段 = data_type，字段 `\0` 分隔，公共头字段顺序正确
- ✅ 插件运行时仅依赖 glibc（libbpf 已静态编入）
- ⚠️ musl 静态构建受阻于 libbpf-sys 的 musl sysroot（需官方 Docker 构建镜像）

### 编译产物

- `driver/LKM/elkeid.ko` — sha256 `abb86e7784705545db809cb45a144c4b183ddd20d1db3e445c2e035a1fcbc62b`
- `plugins/driver/target/release/driver`（driver.plg）— sha256 `fbeb7cb86ac21e7393ff5d17ecd34074d774ab043ae19d884e37ffaf3b60670f`

### 待办

1. `kmod.rs` 模块加载逻辑（`elkeid.ko` 下载 + `finit_module`；离线场景 `install.sh` 已直接 insmod）
2. 服务端数据字典字段名同步（`exe`→`exe_path`、`sessionid`→`epoch`、`pns`→`mntns_id` 等）
3. musl 静态构建（跨发行版部署才需要）
