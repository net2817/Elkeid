import json, subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

converted = json.load(open('/tmp/falco_converted.json'))

def mknode(part, vtype, value):
    return {"CheckDataType":"static","Value":value,"Part":part,"Group":"","Type":vtype,"Extra":{},"Separator":"","LogicType":""}

rules = []
for c in converted:
    nodes = []
    if c['exe_re']:
        nodes.append(mknode('exe','REGEX',c['exe_re']))
    if c['argv_re']:
        nodes.append(mknode('argv','REGEX',c['argv_re']))
    if not nodes:
        continue
    rule = {
        "RuleId": c['rule_id'], "RuleName": c['name'], "CEP": "", "AlertData": True, "Del": "",
        "Action": {"Extra": {}, "Persistent": False, "Name": ""},
        "Append": [
            {"RelyPart":"","AppendFieldName":"alert_type_us","ConnID":"","CacheTTL":"","Extra":{},"Value":"execution","Type":"STATIC"},
            {"CacheTTL":"","Extra":{},"Value":c['attack_id'],"Type":"STATIC","RelyPart":"","AppendFieldName":"attack_id_list","ConnID":""},
            {"RelyPart":"","AppendFieldName":"suggestion","ConnID":"","CacheTTL":"","Extra":{},"Value":c['desc'],"Type":"STATIC"},
        ],
        "Filter": {"Value":"59","Part":"data_type","Type":""},
        "Search": None,
        "CheckList": {"CheckNodes":nodes,"ForEach":"","CEP":""},
        "Desc": {"KillChainID":"persistent","Value":c['desc'],"AffectedTarget":"host_process"},
        "Threshold": None, "Type": "Detection", "NodeDesignate": {"Nodes": []},
        "HarmLevel": c['harm'], "AlertEmail": "", "Author": "falco", "Modify": {"Extra": {}, "Name": ""}
    }
    rules.append(rule)

ruleset = {
    "Encrypted": False, "CipherText": "", "RuleSetID": "falco_full_detect",
    "Json": {"Type":"Rule","TaskID":"","EnableCompressIndex":False,"RulesetName":"falco_full_detect",
             "Version":"","Debug":False,"RulesetId":"falco_full_detect","FullCollectRules":"",
             "Rules":rules, "CompressConf":{}, "UndetectedDiscard": True},
    "Xml": "<root ruleset_id=\"falco_full_detect\" ruleset_name=\"falco_full_detect\" type=\"Rule\" undetected_discard=\"true\"></root>"
}

js = json.dumps(ruleset)
open('/tmp/falco_ruleset.json','w').write(js)
print('rules:', len(rules))
# copy to 249 + container
run(['sshpass','-p','Admin@123456','scp','-o','StrictHostKeyChecking=no','/tmp/falco_ruleset.json','root@10.255.255.249:/tmp/falco_ruleset.json'])
print('copied to 249')
