import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

print('=== alarm rule name distribution ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','db.hub_alarm_v1.aggregate([{$group:{_id:"$rule_name",c:{$sum:1}}},{$sort:{c:-1}}]).forEach(function(x){print(x.c+" | "+x._id)})']))
print('=== test3 all alarms ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','db.hub_alarm_v1.find({hostname:"test3"}).forEach(function(a){print(a._id.getTimestamp()+" | "+a.rule_name+" | type="+a.data_type)})']))
