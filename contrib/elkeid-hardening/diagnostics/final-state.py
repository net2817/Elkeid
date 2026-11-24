import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

print('=== data counts ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',
    'print("rulesets="+db.hub_ruleset_stable_elkeid_hub.count()'
    '+" vuln_info="+db.vuln_info.count()'
    '+" baseline_info="+db.baseline_info.count()'
    '+" cpe_info="+db.cpe_info.count()'
    '+" agent_heartbeat="+db.agent_heartbeat.count()'
    '+" hub_alarm="+db.hub_alarm_v1.count())']))
print('=== hids_detect rule count ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',
    'var r=db.hub_ruleset_stable_elkeid_hub.findOne({RuleSetID:"hids_detect"}); print("hids_detect rules="+(r&&r.Json?r.Json.Rules.length:0))']))
print('=== file rules inside hids_detect ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',
    'var r=db.hub_ruleset_stable_elkeid_hub.findOne({RuleSetID:"hids_detect"}); if(r&&r.Json){r.Json.Rules.forEach(function(x){if(x.Author=="falco-file")print("  "+x.RuleName)})}']))
print('=== baseline_config files ===')
print(run(['docker','exec','ab26241257bb','bash','-c','ls /elkeid/manager/conf/baseline_config/']))
