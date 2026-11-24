import json, subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

# read hids_detect ruleset
out = run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','JSON.stringify(db.hub_ruleset_stable_elkeid_hub.findOne({RuleSetID:"hids_detect"}).Json)'])
# out is bytes; strip
try:
    js = out.decode('utf-8', 'ignore').strip()
    hids = json.loads(js)
except Exception as e:
    print('parse err', e); print(out[:300]); raise SystemExit(1)

print('hids_detect rules before:', len(hids['Rules']))

# load file rules
rules_in = json.load(open('/tmp/falco_file_rules.json'))
def mknode(part, vtype, value):
    return {"CheckDataType":"static","Value":value,"Part":part,"Group":"","Type":vtype,"Extra":{},"Separator":"","LogicType":""}

existing_ids = set(r['RuleId'] for r in hids['Rules'])
added = 0
for c in rules_in:
    if c['rule_id'] in existing_ids:
        continue
    hids['Rules'].append({
        "RuleId": c['rule_id'], "RuleName": c['name'], "CEP": "", "AlertData": True, "Del": "",
        "Action": {"Extra": {}, "Persistent": False, "Name": ""},
        "Append": [
            {"RelyPart":"","AppendFieldName":"alert_type_us","ConnID":"","CacheTTL":"","Extra":{},"Value":"file_integrity","Type":"STATIC"},
            {"CacheTTL":"","Extra":{},"Value":"TA0005","Type":"STATIC","RelyPart":"","AppendFieldName":"attack_id_list","ConnID":""},
            {"RelyPart":"","AppendFieldName":"suggestion","ConnID":"","CacheTTL":"","Extra":{},"Value":c['desc'],"Type":"STATIC"},
        ],
        "Filter": {"Value":"2","Part":"data_type","Type":""},
        "Search": None,
        "CheckList": {"CheckNodes":[mknode("filename","REGEX",c['path_re'])],"ForEach":"","CEP":""},
        "Desc": {"KillChainID":"persistent","Value":c['desc'],"AffectedTarget":"host_file"},
        "Threshold": None, "Type": "Detection", "NodeDesignate": {"Nodes": []},
        "HarmLevel": "medium", "AlertEmail": "", "Author": "falco-file", "Modify": {"Extra": {}, "Name": ""}
    })
    added += 1
print('added:', added, 'total now:', len(hids['Rules']))

open('/tmp/hids_detect_new.json','w').write(json.dumps(hids))
print(run(['docker','cp','/tmp/hids_detect_new.json','ab26241257bb:/tmp/hids_detect_new.json']))
ev = ('var j=JSON.parse(cat("/tmp/hids_detect_new.json")); '
      'db.hub_ruleset_stable_elkeid_hub.updateOne({RuleSetID:"hids_detect"},{$set:{Json:j}}); '
      'db.hub_ruleset_cache_elkeid_hub.updateOne({RuleSetID:"hids_detect"},{$set:{Json:j}}); '
      'print("hids_detect updated, rules="+j.Rules.length)')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))
print(run(['docker','exec','ab26241257bb','systemctl','restart','elkeid_hub']))
