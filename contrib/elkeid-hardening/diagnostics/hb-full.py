import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

ev = ('var a=db.agent_heartbeat.findOne({hostname:"test3"}); '
      'print("state="+a.state+" start_time="+a.start_time+" last_heartbeat_time="+a.last_heartbeat_time); '
      'print("now="+Math.floor(Date.now()/1000)); '
      'print("update_time="+a.update_time)')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))

ev2 = 'db.agent_heartbeat.find({hostname:"test3"}).forEach(function(a){a.plugins.forEach(function(p){if(p.name=="driver")print("driver state="+p.state+" tx="+p.tx_tps+" rx="+p.rx_tps)})})'
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev2]))
