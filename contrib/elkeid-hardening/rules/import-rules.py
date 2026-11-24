import subprocess, json, time
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

def mknode(part, vtype, value):
    return {"CheckDataType":"static","Value":value,"Part":part,"Group":"","Type":vtype,"Extra":{},"Separator":"","LogicType":""}

def mkrule(rule_id, rule_name, harm, regex_part, regex_val, desc, attack_id, suggestion):
    return {
        "RuleId": rule_id, "RuleName": rule_name, "CEP": "", "AlertData": True, "Del": "",
        "Action": {"Extra": {}, "Persistent": False, "Name": ""},
        "Append": [
            {"RelyPart":"","AppendFieldName":"alert_type_us","ConnID":"","CacheTTL":"","Extra":{},"Value":"execution","Type":"STATIC"},
            {"CacheTTL":"","Extra":{},"Value":attack_id,"Type":"STATIC","RelyPart":"","AppendFieldName":"attack_id_list","ConnID":""},
            {"RelyPart":"","AppendFieldName":"suggestion","ConnID":"","CacheTTL":"","Extra":{},"Value":suggestion,"Type":"STATIC"},
        ],
        "Filter": {"Value":"59","Part":"data_type","Type":""},
        "Search": None,
        "CheckList": {"CheckNodes":[mknode(regex_part,"REGEX",regex_val)],"ForEach":"","CEP":""},
        "Desc": {"KillChainID":"persistent","Value":desc,"AffectedTarget":"host_process"},
        "Threshold": None, "Type": "Detection", "NodeDesignate": {"Nodes": []},
        "HarmLevel": harm, "AlertEmail": "", "Author": "community", "Modify": {"Extra": {}, "Name": ""}
    }

rules = [
    mkrule("sensitive_file_read_detect", "Sensitive file read", "high", "argv",
           "(?:/etc/shadow|/root/.ssh/|/etc/sudoers|/etc/passwd)",
           "Read sensitive files", "T1005", "check the process reading sensitive files"),
    mkrule("crypto_miner_detect", "Crypto miner process", "critical", "exe",
           "(?:xmrig|minerd|cpuminer|kdevtmpfsi|kinsing)",
           "Crypto miner process executed", "T1496", "kill the mining process and clean persistence"),
    mkrule("suspicious_binary_download_detect", "Suspicious binary download", "medium", "argv",
           "(?:(?:curl|wget)\\b.*(?:http://|https://).*\\.(?:sh|py|elf|bin|out))",
           "Suspicious binary download via curl/wget", "T1105", "check the download source"),
]

# build ruleset Json + Xml
def to_xml(rules):
    parts = ['<root ruleset_id="community_extra_detect" ruleset_name="community_extra_detect" type="Rule" undetected_discard="true">']
    for r in rules:
        parts.append('  <rule rule_id="%s" type="Detection" author="community">' % r['RuleId'])
        parts.append('    <rule_name>%s</rule_name>' % r['RuleName'])
        parts.append('    <harm_level>%s</harm_level>' % r['HarmLevel'])
        parts.append('    <filter part="data_type">59</filter>')
        parts.append('    <check_list>')
        for n in r['CheckList']['CheckNodes']:
            parts.append('      <check_node part="%s" type="REGEX" check_data_type="static">%s</check_node>' % (n['Part'], n['Value']))
        parts.append('    </check_list>')
        parts.append('    <alert_data>true</alert_data>')
        parts.append('    <modify></modify><del></del><action></action>')
        parts.append('    <desc affected_target="host_process">%s</desc>' % r['Desc']['Value'])
        parts.append('  </rule>')
    parts.append('</root>')
    return '\n'.join(parts)

ruleset = {
    "Encrypted": False, "CipherText": "", "RuleSetID": "community_extra_detect",
    "Json": {
        "Type":"Rule","TaskID":"","EnableCompressIndex":False,"RulesetName":"community_extra_detect",
        "Version":"","Debug":False,"RulesetId":"community_extra_detect","FullCollectRules":"",
        "Rules": rules, "CompressConf":{}, "UndetectedDiscard": True
    },
    "Xml": to_xml(rules)
}

js = json.dumps(ruleset)
# write to file then import via mongo (avoid huge --eval)
open('/tmp/ruleset.json','w').write(js)

ev = ('var j=JSON.parse(cat("/tmp/ruleset.json")); '
      'db.hub_ruleset_stable_elkeid_hub.deleteOne({RuleSetID:"community_extra_detect"}); '
      'db.hub_ruleset_stable_elkeid_hub.insertOne(j); '
      'db.hub_ruleset_cache_elkeid_hub.deleteOne({RuleSetID:"community_extra_detect"}); '
      'db.hub_ruleset_cache_elkeid_hub.insertOne(j); '
      'print("inserted community_extra_detect, total rules="+j.Json.Rules.length)')

# run inside container
print(run(['docker','cp','/tmp/ruleset.json','ab26241257bb:/tmp/ruleset.json']))
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','print("stable="+db.hub_ruleset_stable_elkeid_hub.count()+", cache="+db.hub_ruleset_cache_elkeid_hub.count())']))
