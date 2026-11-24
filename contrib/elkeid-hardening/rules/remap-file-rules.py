import json, subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

rules_in = json.load(open('/tmp/falco_file_rules.json'))
# remap: 609(read)->2(open), 608(write)->1(write)
for c in rules_in:
    if c['dtype'] == '609':
        c['dtype'] = '2'
    elif c['dtype'] == '608':
        c['dtype'] = '1'

def mknode(part, vtype, value):
    return {"CheckDataType":"static","Value":value,"Part":part,"Group":"","Type":vtype,"Extra":{},"Separator":"","LogicType":""}

rules = []
for c in rules_in:
    rules.append({
        "RuleId": c['rule_id'], "RuleName": c['name'], "CEP": "", "AlertData": True, "Del": "",
        "Action": {"Extra": {}, "Persistent": False, "Name": ""},
        "Append": [
            {"RelyPart":"","AppendFieldName":"alert_type_us","ConnID":"","CacheTTL":"","Extra":{},"Value":"file_integrity","Type":"STATIC"},
            {"CacheTTL":"","Extra":{},"Value":"TA0005","Type":"STATIC","RelyPart":"","AppendFieldName":"attack_id_list","ConnID":""},
            {"RelyPart":"","AppendFieldName":"suggestion","ConnID":"","CacheTTL":"","Extra":{},"Value":c['desc'],"Type":"STATIC"},
        ],
        "Filter": {"Value":c['dtype'],"Part":"data_type","Type":""},
        "Search": None,
        "CheckList": {"CheckNodes":[mknode("file","REGEX",c['path_re'])],"ForEach":"","CEP":""},
        "Desc": {"KillChainID":"persistent","Value":c['desc'],"AffectedTarget":"host_file"},
        "Threshold": None, "Type": "Detection", "NodeDesignate": {"Nodes": []},
        "HarmLevel": "medium", "AlertEmail": "", "Author": "falco-file", "Modify": {"Extra": {}, "Name": ""}
    })

ruleset = {
    "Encrypted": False, "CipherText": "", "RuleSetID": "falco_file_detect",
    "Json": {"Type":"Rule","TaskID":"","EnableCompressIndex":False,"RulesetName":"falco_file_detect",
             "Version":"","Debug":False,"RulesetId":"falco_file_detect","FullCollectRules":"",
             "Rules":rules, "CompressConf":{}, "UndetectedDiscard": True},
    "Xml": "<root ruleset_id=\"falco_file_detect\" ruleset_name=\"falco_file_detect\" type=\"Rule\" undetected_discard=\"true\"></root>"
}
json.dump(ruleset, open('/tmp/file_ruleset2.json','w'))
print(run(['docker','cp','/tmp/file_ruleset2.json','ab26241257bb:/tmp/file_ruleset2.json']))
ev = ('var j=JSON.parse(cat("/tmp/file_ruleset2.json")); '
      'db.hub_ruleset_stable_elkeid_hub.deleteOne({RuleSetID:"falco_file_detect"}); db.hub_ruleset_stable_elkeid_hub.insertOne(j); '
      'db.hub_ruleset_cache_elkeid_hub.deleteOne({RuleSetID:"falco_file_detect"}); db.hub_ruleset_cache_elkeid_hub.insertOne(j); '
      'print("remapped to open(2)/write(1), rules="+j.Json.Rules.length+", total="+db.hub_ruleset_stable_elkeid_hub.count())')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))
