// hub-fix-rule.js
// ---------------------------------------------------------------------------
// 修正 Elkeid HUB 规则：curated_ldpreload_set_detect
//   NOTNULL(ld_preload)  ->  REGEX(ld_preload, \.so)
//
// 原因：Elkeid 用负数占位符(-1/-5)表示字段缺失，NOTNULL 判定会把占位符
//       当成"有值"，导致所有 execve 事件误报。
//
// 必须同时更新 4 个位置，否则不生效：
//   1. hub_ruleset_stable_elkeid_hub  .Json
//   2. hub_ruleset_stable_elkeid_hub  .Xml    <- HUB 实际加载的是 Xml
//   3. hub_ruleset_cache_elkeid_hub   .Json   <- HUB 运行时读的是 cache
//   4. hub_ruleset_cache_elkeid_hub   .Xml
//
// 执行方式：
//   docker cp hub-fix-rule.js ab26241257bb:/tmp/hub-fix-rule.js
//   docker exec ab26241257bb /elkeid/mongodb/mongodb_4.2/bin/mongo \
//     "mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid" \
//     --quiet /tmp/hub-fix-rule.js
//   docker exec ab26241257bb systemctl restart elkeid_hub
// ---------------------------------------------------------------------------

var RULESET = "curated_detect";
var RULEID  = "curated_ldpreload_set_detect";
var COLLECTIONS = ["hub_ruleset_stable_elkeid_hub", "hub_ruleset_cache_elkeid_hub"];

var OLD_XML = '<check_node type="NOTNULL" part="ld_preload"><![CDATA[]]></check_node>';
var NEW_XML = '<check_node type="REGEX" part="ld_preload"><![CDATA[\\.so]]></check_node>';

COLLECTIONS.forEach(function (col) {
  var r = db.getCollection(col).findOne({ RuleSetID: RULESET });
  if (!r) {
    print(col + ": ruleset '" + RULESET + "' not found, skipped");
    return;
  }

  // ---- Json 字段 ----
  var jsonNodes = 0;
  var rules = (r.Json && r.Json.Rules) || [];
  rules.forEach(function (x) {
    if (x.RuleId !== RULEID || !x.CheckList || !x.CheckList.CheckNodes) return;
    x.CheckList.CheckNodes.forEach(function (n) {
      if (n.Part === "ld_preload" && n.Type === "NOTNULL") {
        n.Type = "REGEX";
        n.Value = "\\.so";
        jsonNodes++;
      }
    });
  });

  // ---- Xml 字段 ----
  var xml = r.Xml || "";
  var xmlChanged = 0;
  if (xml.indexOf(OLD_XML) >= 0) {
    xml = xml.split(OLD_XML).join(NEW_XML);
    xmlChanged = 1;
  }

  if (jsonNodes === 0 && xmlChanged === 0) {
    print(col + ": already fixed, no change");
    return;
  }

  db.getCollection(col).update(
    { RuleSetID: RULESET },
    { $set: { Json: r.Json, Xml: xml } }
  );
  print(col + ": json_nodes=" + jsonNodes + " xml=" + xmlChanged + " -> UPDATED");
});

// ---- 校验 ----
print("=== verify ===");
COLLECTIONS.forEach(function (col) {
  var r = db.getCollection(col).findOne({ RuleSetID: RULESET });
  if (!r) return;
  var rules = (r.Json && r.Json.Rules) || [];
  rules.forEach(function (x) {
    if (x.RuleId !== RULEID) return;
    var parts = [];
    x.CheckList.CheckNodes.forEach(function (n) {
      parts.push(n.Part + ":" + n.Type + "=" + n.Value);
    });
    print("  " + col + " [Json] " + parts.join(" && "));
  });
  var xml = r.Xml || "";
  var i = xml.indexOf("ld_preload");
  if (i >= 0) {
    print("  " + col + " [Xml ] " + xml.substring(i - 40, i + 40).replace(/\n/g, " ").trim());
  }
});
