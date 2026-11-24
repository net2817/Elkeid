import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

print('t1 whoami:', run(['docker','exec','ab26241257bb','whoami']))
print('t2 /bin/echo:', run(['docker','exec','ab26241257bb','/bin/echo','HELLO']))
print('t3 ls /tmp:', run(['docker','exec','ab26241257bb','ls','/tmp']))
print('t4 mongo path:', run(['docker','exec','ab26241257bb','ls','-la','/elkeid/mongodb/mongodb_4.2/bin/mongo']))
