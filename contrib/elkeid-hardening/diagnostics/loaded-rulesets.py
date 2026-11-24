import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

print('=== loaded rulesets (cache) ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','db.hub_ruleset_cache_elkeid_hub.find({},{RuleSetID:1,"Json.RulesetName":1}).forEach(function(r){print(r.RuleSetID+" | "+(r.Json&&r.Json.RulesetName))})']))
