import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

MONGO = '/elkeid/mongodb/mongodb_4.2/bin/mongo'
URI = 'mongodb://elkeid:190f54c6ddq10r3k6k@127.0.0.1:27017/elkeid?authSource=elkeid'

print(run(['docker','cp','/tmp/cisa_kev_converted.json','ab26241257bb:/tmp/cisa_kev_converted.json']))
ev = ('var a=JSON.parse(cat("/tmp/cisa_kev_converted.json")); '
      'var n=0; a.forEach(function(x){db.vuln_info.updateOne({cve:x.cve},{$setOnInsert:x},{upsert:true}); n++;}); '
      'print("imported="+n+", total vuln_info="+db.vuln_info.count())')
print(run(['docker','exec','ab26241257bb',MONGO,URI,'--quiet','--eval',ev]))
