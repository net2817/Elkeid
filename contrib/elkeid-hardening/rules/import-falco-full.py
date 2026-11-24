import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

print(run(['docker','cp','/tmp/falco_ruleset.json','ab26241257bb:/tmp/falco_ruleset.json']))
ev = ('var j=JSON.parse(cat("/tmp/falco_ruleset.json")); '
      'db.hub_ruleset_stable_elkeid_hub.deleteOne({RuleSetID:"falco_full_detect"}); db.hub_ruleset_stable_elkeid_hub.insertOne(j); '
      'db.hub_ruleset_cache_elkeid_hub.deleteOne({RuleSetID:"falco_full_detect"}); db.hub_ruleset_cache_elkeid_hub.insertOne(j); '
      'print("falco_full_detect inserted, rules="+j.Json.Rules.length+", total rulesets="+db.hub_ruleset_stable_elkeid_hub.count())')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))
