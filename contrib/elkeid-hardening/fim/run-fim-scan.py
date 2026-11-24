import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

print('=== setup test dir ===')
print(run(['bash','-c','rm -rf /tmp/fimdemo; mkdir -p /tmp/fimdemo; echo aaa > /tmp/fimdemo/a.txt; echo bbb > /tmp/fimdemo/b.txt']))

print('=== init baseline ===')
print(run(['python','/tmp/fim.py','init','/tmp/fimdemo','/tmp/fimdemo.base']))

print('=== modify + add + delete ===')
print(run(['bash','-c','echo aaa2 > /tmp/fimdemo/a.txt; echo ccc > /tmp/fimdemo/c.txt; rm -f /tmp/fimdemo/b.txt; echo CHANGED']))

print('=== check (change detection + reconciliation) ===')
print(run(['python','/tmp/fim.py','check','/tmp/fimdemo','/tmp/fimdemo.base']))
