// hub-alarm-stats.js
// ---------------------------------------------------------------------------
// HUB 告警统计辅助脚本。
//
// 重要：告警文档的 time 字段是「字符串」，直接做范围比较会得到错误结果。
//       统计时间窗口请用 ObjectId 内嵌的时间戳（本脚本已实现）。
//
// 执行方式：
//   docker cp hub-alarm-stats.js ab26241257bb:/tmp/hub-alarm-stats.js
//   docker exec ab26241257bb /elkeid/mongodb/mongodb_4.2/bin/mongo \
//     "mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid" \
//     --quiet /tmp/hub-alarm-stats.js
// ---------------------------------------------------------------------------

var WINDOW_MIN = 5; // 统计最近 N 分钟

var now = Math.floor(Date.now() / 1000);
var cutoff = ObjectId((now - WINDOW_MIN * 60).toString(16) + "0000000000000000");

print("=== 总量 ===");
print("alarms_total      = " + db.hub_alarm_v1.count());
print("ruleset_total     = " + db.hub_ruleset_stable_elkeid_hub.count());
print("agents_total      = " + db.agent_heartbeat.count());

print("");
print("=== 最近 " + WINDOW_MIN + " 分钟：按 主机 + 规则 聚合 ===");
var c = {};
db.hub_alarm_v1.find(
  { _id: { $gt: cutoff } },
  { hostname: 1, "SMITH_ALERT_DATA.RULE_INFO.RuleID": 1, _id: 0 }
).forEach(function (d) {
  var r = (d.SMITH_ALERT_DATA && d.SMITH_ALERT_DATA.RULE_INFO) || {};
  var k = (d.hostname || "?") + " | " + (r.RuleID || "?");
  c[k] = (c[k] || 0) + 1;
});

var keys = Object.keys(c).sort(function (a, b) { return c[b] - c[a]; });
if (keys.length === 0) {
  print("  (无新增告警)");
} else {
  keys.slice(0, 20).forEach(function (k) { print("  " + c[k] + "  " + k); });
}

print("");
print("=== 最近 " + WINDOW_MIN + " 分钟：总量 ===");
print("alarms_in_window  = " + db.hub_alarm_v1.count({ _id: { $gt: cutoff } }));

print("");
print("=== 历史累积：按 规则 聚合 Top 10 ===");
var h = {};
db.hub_alarm_v1.find(
  {},
  { "SMITH_ALERT_DATA.RULE_INFO.RuleID": 1, _id: 0 }
).forEach(function (d) {
  var r = (d.SMITH_ALERT_DATA && d.SMITH_ALERT_DATA.RULE_INFO) || {};
  var k = r.RuleID || "?";
  h[k] = (h[k] || 0) + 1;
});
Object.keys(h).sort(function (a, b) { return h[b] - h[a]; })
  .slice(0, 10)
  .forEach(function (k) { print("  " + h[k] + "  " + k); });
