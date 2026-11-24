import subprocess, time
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

print('=== restart HUB ===')
print(run(['docker','exec','ab26241257bb','systemctl','restart','elkeid_hub']))
time.sleep(8)
print('=== agents heartbeat ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','db.agent_heartbeat.find({},{hostname:1,state:1,last_heartbeat_time_format:1}).forEach(function(a){print(a.hostname+" "+a.state+" "+a.last_heartbeat_time_format)})']))
print('=== driver plugin tx ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','db.agent_heartbeat.find({"plugins.name":"driver"}).forEach(function(a){a.plugins.forEach(function(p){if(p.name=="driver")print(a.hostname+" tx_tps="+p.tx_tps)})})']))
print('=== ruleset count ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','print(db.hub_ruleset_stable_elkeid_hub.count())']))
