import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

ev = 'db.agent_heartbeat.find({},{hostname:1,host_id:1,in_ipv4_list:1,state:1,last_heartbeat_time:1}).forEach(function(a){print(a.hostname+" | id="+a.host_id+" | ip="+a.in_ipv4_list+" | "+a.state+" | last="+a.last_heartbeat_time)})'
print('=== all agents ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))
