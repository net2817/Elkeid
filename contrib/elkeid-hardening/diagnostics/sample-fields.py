import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

print('=== samples containing filename/flags ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','print("total samples="+db.hub_sample_elkeid_hub.count()); print("with filename="+db.hub_sample_elkeid_hub.count({sample_data:/filename/})); print("with flags="+db.hub_sample_elkeid_hub.count({sample_data:/flags/}))']))
print('=== sample with filename (if any) ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','var a=db.hub_sample_elkeid_hub.findOne({sample_data:/filename/}); if(a){print(a.sample_data.substring(0,500))}else{print("NONE")}']))
print('=== all distinct index fields in samples ===')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval','var a=db.hub_sample_elkeid_hub.findOne({}); print(a.index.substring(0,400))']))
