import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

print('=== final: rulesets + test3 alarm + file rules ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','print("rulesets="+db.hub_ruleset_stable_elkeid_hub.count()); print("test3 alarms="+db.hub_alarm_v1.count({hostname:"test3"})); print("falco_file_detect loaded="+(db.hub_ruleset_cache_elkeid_hub.findOne({RuleSetID:"falco_file_detect"})?"YES":"NO")); print("probes="+db.hub_ruleset_stable_elkeid_hub.count({RuleSetID:{$in:["open_probe","filename_probe"]}}))']))
