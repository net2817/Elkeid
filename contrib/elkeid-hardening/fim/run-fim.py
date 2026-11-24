import subprocess, time
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

# compile
print('=== compile ===')
print(run(['bash','-c','gcc -o /tmp/fim_monitor /tmp/fim_monitor.c 2>&1 && echo COMPILED']))

# start monitor in background
print('=== start monitor ===')
p = subprocess.Popen(['/tmp/fim_monitor','/tmp/fim_test'],
                     stdout=open('/tmp/fim_out.txt','w'), stderr=subprocess.STDOUT)
print('monitor pid:', p.pid)
time.sleep(2)

# trigger file events
print('=== trigger events ===')
run(['bash','-c','echo hello > /tmp/fim_test/a.txt; echo world >> /tmp/fim_test/a.txt; mv /tmp/fim_test/a.txt /tmp/fim_test/b.txt; rm -f /tmp/fim_test/b.txt; echo done'])
time.sleep(3)

# report
print('=== monitor output ===')
print(run(['bash','-c','cat /tmp/fim_out.txt']))
p.terminate()
