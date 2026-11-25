# HUB 告警误报风暴排查与修复

> 记录一次 Elkeid HUB 单条规则产生万余条误报的完整排查过程、根因与修复方法。
> 适用于社区版 v1.9.1（all-in-one 容器 `elkeid_community`）。

## 一、现象

主机心跳、服务状态均正常，但告警数量异常暴涨：

| 时间点 | `hub_alarm_v1` 总量 |
|---|---|
| 基线 | 184 |
| 异常后 | 13789 → 16261（持续增长） |

按规则与主机聚合后，确认是单条规则贡献了绝大部分：

```
12475  10-11-69-16  curated_ldpreload_set_detect   LD_PRELOAD set on system binary
   82  test3        curated_ldpreload_set_detect   LD_PRELOAD set on system binary
```

实测增速：**约 28 条/分钟**，且全部来自这一条规则。

## 二、排查过程

### 2.1 确认告警的进程分布

误报覆盖的 `exe_path` 全部是系统/云平台/容器网络组件：

| 数量 | exe_path | 用途 |
|---|---|---|
| 3935 | `/sbin/tc` | 虚拟机带宽限速 |
| 3117 | `/bin/busybox` | 容器内工具 |
| 1301 | `/usr/sbin/xtables-legacy-multi` | iptables（kube-proxy） |
| 1196 | `/sbin/xtables-nft-multi` | iptables-nft |
| 924 | `/usr/bin/ovs-ofctl` | Open vSwitch 流表 |
| 593 | `/usr/sbin/ethtool` | 网卡信息 |
| 560 | `/usr/bin/grep` | 文本处理 |
| 474 | `/usr/bin/ovs-vsctl` | OVS 管理 |
| 418 | `/usr/bin/dash` | shell |
| 415 | `/usr/sbin/ipset` | 防火墙集合 |
| 260 | `/usr/bin/ps` | 进程查看 |
| 251 | `/usr/bin/kmod` | 内核模块 |
| 196 | `/usr/sbin/ip` | 网络配置 |
| 185 | `/usr/bin/uname` | 系统信息 |
| 172 | `/usr/bin/calico-node` | calico 网络 |
| 134 | `/usr/bin/ovn-sbctl` | OVN 管理 |
| 93 | `/usr/sbin/smartctl` | 磁盘巡检 |

### 2.2 关键证据：`ld_preload` 字段全为占位符

```javascript
db.hub_alarm_v1.aggregate([
  {$match: {"SMITH_ALERT_DATA.RULE_INFO.RuleID": "curated_ldpreload_set_detect"}},
  {$group: {_id: "$ld_preload", n: {$sum: 1}}}
])
// 结果：仅一个分组  {"_id": "-5", "n": 14620}
```

再验证是否存在真实共享库：

```javascript
db.hub_alarm_v1.count({
  "SMITH_ALERT_DATA.RULE_INFO.RuleID": "curated_ldpreload_set_detect",
  ld_preload: /\.so/
})
// 结果：0
```

**结论：14620 条告警中，`ld_preload` 100% 都是占位符 `-5`，没有一条包含真实 `.so` 路径。**

### 2.3 规则原始定义

```javascript
var r = db.hub_ruleset_stable_elkeid_hub.findOne({RuleSetID:"curated_detect"});
r.Json.Rules.forEach(function(x){
  if(x.RuleId === "curated_ldpreload_set_detect") printjson(x.CheckList.CheckNodes);
});
```

```
Filter: data_type = 59                （execve 事件）
node[0]: ld_preload  NOTNULL  ""      ← 问题所在
node[1]: exe         REGEX    "^/(usr/)?(s?bin)/.+$"
```

## 三、根因（三层）

### 根因 1：`NOTNULL` 判定被占位符绕过

Elkeid agent 在字段无值时不会留空，而是填空值占位符：

- `data_type=59`（execve）事件：`ld_preload` = `-1`
- 落库到告警记录后：`ld_preload` = `-5`

`NOTNULL` 运算符把 `-5` 判定为"非空"，因此**所有** execve 事件都被认为带 LD_PRELOAD，产生全量误报。

### 根因 2：规则集是 `Json` + `Xml` 双份存储

`hub_ruleset_*_elkeid_hub` 文档结构：

```javascript
["_id", "Encrypted", "CipherText", "RuleSetID", "Json", "Xml"]
```

HUB **实际加载的是 `Xml` 字段**。只修改 `Json` 不会生效。

### 根因 3：运行时有 stable / cache 两份规则集

| 集合 | 作用 |
|---|---|
| `hub_ruleset_stable_elkeid_hub` | 持久化源 |
| `hub_ruleset_cache_elkeid_hub` | **HUB 运行时读取** |

而且 HUB 启动时会把规则**导出为文件**：

```
/elkeid/hub/config/ruleset/<RuleSetID>.xml
/elkeid/hub/config/project/*.xml
```

日志可见 `PROJECT READY TO START`，说明启动阶段完成导出与加载。

**只改 stable、或只改 Json、或不重启，三者任一都会导致修改不生效。**

## 四、修复

### 4.1 修改判定条件

把"存在即告警"改为"必须是真实共享库"：

```
旧：<check_node type="NOTNULL" part="ld_preload"><![CDATA[]]></check_node>
新：<check_node type="REGEX" part="ld_preload"><![CDATA[\.so]]></check_node>
```

### 4.2 必须同步修改 4 个位置

| # | 集合 | 字段 |
|---|---|---|
| 1 | `hub_ruleset_stable_elkeid_hub` | `Json` |
| 2 | `hub_ruleset_stable_elkeid_hub` | `Xml` |
| 3 | `hub_ruleset_cache_elkeid_hub` | `Json` |
| 4 | `hub_ruleset_cache_elkeid_hub` | `Xml` |

一次性完成 4 处修改的脚本见 `scripts/hub-fix-rule.js`。

### 4.3 重启 HUB 使规则重新导出

```bash
docker exec ab26241257bb systemctl restart elkeid_hub
```

### 4.4 验证导出的 XML 已是新规则

```bash
docker exec ab26241257bb grep -o -E 'check_node type="[A-Z]+" part="ld_preload">' \
  /elkeid/hub/config/ruleset/curated_detect.xml
# 期望输出：check_node type="REGEX" part="ld_preload">
```

## 五、验证效果

修复前后对比（`ObjectId` 内嵌时间戳比 `time` 字符串字段更可靠）：

```javascript
var cutoff = ObjectId((Math.floor(Date.now()/1000)-180).toString(16)+"0000000000000000");
print("last3min="      + db.hub_alarm_v1.count({_id:{$gt:cutoff}}));
print("ldp_last3min="  + db.hub_alarm_v1.count({
  "SMITH_ALERT_DATA.RULE_INFO.RuleID":"curated_ldpreload_set_detect", _id:{$gt:cutoff}}));
```

| 阶段 | 3 分钟新增 ldpreload 告警 |
|---|---|
| 修复前 | +84（≈28 条/分钟） |
| **修复后** | **+0** ✅ |

修复后 3 分钟窗口内告警总量降至 9 条，全部来自其他 Sigma 规则。

## 六、为什么不加白名单

最初考虑用 `hids_filter` 白名单屏蔽这些 `exe_path`，但白名单方案有明显缺陷：

- 白名单按 `exe_path` 匹配，**真实的 LD_PRELOAD 攻击如果通过 `/usr/bin/*` 落地就会被一起放过**
- 本次误报的根因是判定条件错误，不是"这些进程不该被监控"
- 修正判定条件后，**检测能力完整保留**：任何 `ld_preload` 含 `.so` 的系统二进制执行仍会告警

因此选择修规则而非加白名单。

## 七、经验教训

1. **改 HUB 规则必须同时改 `Json` 和 `Xml`**，且必须同时覆盖 `stable` 和 `cache` 两个集合
2. **必须重启 `elkeid_hub`**，否则内存中的规则不会更新
3. **Elkeid 用负数占位符表示字段缺失**（`-1` / `-5` 等），规则里用 `NOTNULL` 判断"字段存在"会失效；应改用 `REGEX` 等能校验内容形态的运算符
4. **统计告警时间窗口要用 `ObjectId`**，`time` 字段是字符串，范围比较会出错
5. **定位前先做聚合**（按 RuleID + hostname + exe_path），能快速锁定是单条规则还是系统性误报

## 附：排查常用命令

```bash
# 进入容器
docker exec -it ab26241257bb bash

# mongo 连接
docker exec ab26241257bb /elkeid/mongodb/mongodb_4.2/bin/mongo \
  "mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid" --quiet

# 告警按规则+主机聚合（需写入 js 文件后执行，避免 shell 引号问题）
docker cp /tmp/dist.js ab26241257bb:/tmp/dist.js
docker exec ab26241257bb /elkeid/mongodb/mongodb_4.2/bin/mongo \
  "mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid" --quiet /tmp/dist.js
```

> 注意：聚合语句里的 `$group`/`$match` 中的 `$` 会被 shell 展开，**必须写成 js 文件再执行**，不能直接用 `--eval`。
