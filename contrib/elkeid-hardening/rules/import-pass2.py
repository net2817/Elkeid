import json, subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

def mknode(part, vtype, value):
    return {"CheckDataType":"static","Value":value,"Part":part,"Group":"","Type":vtype,"Extra":{},"Separator":"","LogicType":""}

def mkrule(rule_id, name, harm, dtype, nodes, attack_id, desc):
    return {
        "RuleId": rule_id, "RuleName": name, "CEP": "", "AlertData": True, "Del": "",
        "Action": {"Extra": {}, "Persistent": False, "Name": ""},
        "Append": [
            {"RelyPart":"","AppendFieldName":"alert_type_us","ConnID":"","CacheTTL":"","Extra":{},"Value":"execution","Type":"STATIC"},
            {"CacheTTL":"","Extra":{},"Value":attack_id,"Type":"STATIC","RelyPart":"","AppendFieldName":"attack_id_list","ConnID":""},
            {"RelyPart":"","AppendFieldName":"suggestion","ConnID":"","CacheTTL":"","Extra":{},"Value":desc,"Type":"STATIC"},
        ],
        "Filter": {"Value":str(dtype),"Part":"data_type","Type":""},
        "Search": None,
        "CheckList": {"CheckNodes":nodes,"ForEach":"","CEP":""},
        "Desc": {"KillChainID":"persistent","Value":desc,"AffectedTarget":"host_process"},
        "Threshold": None, "Type": "Detection", "NodeDesignate": {"Nodes": []},
        "HarmLevel": harm, "AlertEmail": "", "Author": "falco-pass2", "Modify": {"Extra": {}, "Name": ""}
    }

rules = [
    mkrule("ptrace_attached", "PTRACE attached to process", "high", 101, [], "T1055", "PTRACE attached to a process (potential process injection)"),
    mkrule("linux_kernel_module_injection", "Linux Kernel Module Injection", "critical", 603, [], "TA0003", "Kernel module loaded (potential rootkit)"),
    mkrule("miner_pool_connection", "Outbound connection to miner pool", "critical", 42,
           [mknode("dport","REGEX","(?:3333|4444|5555|7777|8332|8333|14433|14444|2222|3334|3357|4443|5588|5730|6099|6666|8008|8118|8899|9332|9999|45560)")],
           "T1496", "Outbound connection to known crypto miner pool port"),
    mkrule("chmod_setuid_setgid", "Set Setuid or Setgid bit", "high", 90, [], "T1548", "chmod with setuid/setgid bit (potential privilege escalation)"),
    mkrule("symlink_hardlink_sensitive", "Symlink/Hardlink over sensitive files", "medium", 86, [], "T1021", "Create symlink or hardlink over sensitive files"),
]

ruleset = {
    "Encrypted": False, "CipherText": "", "RuleSetID": "falco_pass2_detect",
    "Json": {"Type":"Rule","TaskID":"","EnableCompressIndex":False,"RulesetName":"falco_pass2_detect",
             "Version":"","Debug":False,"RulesetId":"falco_pass2_detect","FullCollectRules":"",
             "Rules":rules, "CompressConf":{}, "UndetectedDiscard": True},
    "Xml": "<root ruleset_id=\"falco_pass2_detect\" ruleset_name=\"falco_pass2_detect\" type=\"Rule\" undetected_discard=\"true\"></root>"
}

js = json.dumps(ruleset)
open('/tmp/pass2.json','w').write(js)
print(run(['docker','cp','/tmp/pass2.json','ab26241257bb:/tmp/pass2.json']))
ev = ('var j=JSON.parse(cat("/tmp/pass2.json")); '
      'db.hub_ruleset_stable_elkeid_hub.deleteOne({RuleSetID:"falco_pass2_detect"}); db.hub_ruleset_stable_elkeid_hub.insertOne(j); '
      'db.hub_ruleset_cache_elkeid_hub.deleteOne({RuleSetID:"falco_pass2_detect"}); db.hub_ruleset_cache_elkeid_hub.insertOne(j); '
      'print("falco_pass2 inserted, rules="+j.Json.Rules.length+", total="+db.hub_ruleset_stable_elkeid_hub.count())')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))
