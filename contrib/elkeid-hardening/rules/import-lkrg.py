import subprocess, json
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

def mknode(part, vtype, value):
    return {"CheckDataType":"static","Value":value,"Part":part,"Group":"","Type":vtype,"Extra":{},"Separator":"","LogicType":""}

rule = {
    "RuleId": "lkrg_alert_detect", "RuleName": "LKRG kernel integrity alert", "CEP": "", "AlertData": True, "Del": "",
    "Action": {"Extra": {}, "Persistent": False, "Name": ""},
    "Append": [
        {"RelyPart":"","AppendFieldName":"alert_type_us","ConnID":"","CacheTTL":"","Extra":{},"Value":"kernel_integrity","Type":"STATIC"},
        {"CacheTTL":"","Extra":{},"Value":"TA0005","Type":"STATIC","RelyPart":"","AppendFieldName":"attack_id_list","ConnID":""},
        {"RelyPart":"","AppendFieldName":"suggestion","ConnID":"","CacheTTL":"","Extra":{},"Value":"LKRG detected kernel integrity violation, investigate the host immediately","Type":"STATIC"},
    ],
    "Filter": {"Value":"4000","Part":"data_type","Type":""},
    "Search": None,
    "CheckList": {"CheckNodes":[mknode("rawlog","REGEX","(?:LKRG:\\s*(?:ALERT|EXPLOIT|KINT|PCFI|PINT|SMEP|SMAP))")],"ForEach":"","CEP":""},
    "Desc": {"KillChainID":"persistent","Value":"LKRG kernel integrity / exploit detection","AffectedTarget":"host"},
    "Threshold": None, "Type": "Detection", "NodeDesignate": {"Nodes": []},
    "HarmLevel": "critical", "AlertEmail": "", "Author": "lkrg", "Modify": {"Extra": {}, "Name": ""}
}

ruleset = {
    "Encrypted": False, "CipherText": "", "RuleSetID": "lkrg_detect",
    "Json": {"Type":"Rule","TaskID":"","EnableCompressIndex":False,"RulesetName":"lkrg_detect",
             "Version":"","Debug":False,"RulesetId":"lkrg_detect","FullCollectRules":"",
             "Rules":[rule], "CompressConf":{}, "UndetectedDiscard": True},
    "Xml": '<root ruleset_id="lkrg_detect" ruleset_name="lkrg_detect" type="Rule" undetected_discard="true"><rule rule_id="lkrg_alert_detect" type="Detection" author="lkrg"><rule_name>LKRG kernel integrity alert</rule_name><harm_level>critical</harm_level><filter part="data_type">4000</filter><check_list><check_node part="rawlog" type="REGEX" check_data_type="static">(?:LKRG:\\s*(?:ALERT|EXPLOIT|KINT|PCFI|PINT|SMEP|SMAP))</check_node></check_list><alert_data>true</alert_data><modify></modify><del></del><action></action><desc affected_target="host">LKRG kernel integrity / exploit detection</desc></rule></root>'
}

js = json.dumps(ruleset)
open('/tmp/ruleset.json','w').write(js)
print(run(['docker','cp','/tmp/ruleset.json','ab26241257bb:/tmp/ruleset.json']))
ev = ('var j=JSON.parse(cat("/tmp/ruleset.json")); '
      'db.hub_ruleset_stable_elkeid_hub.deleteOne({RuleSetID:"lkrg_detect"}); db.hub_ruleset_stable_elkeid_hub.insertOne(j); '
      'db.hub_ruleset_cache_elkeid_hub.deleteOne({RuleSetID:"lkrg_detect"}); db.hub_ruleset_cache_elkeid_hub.insertOne(j); '
      'print("inserted lkrg_detect, total rulesets="+db.hub_ruleset_stable_elkeid_hub.count())')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))
