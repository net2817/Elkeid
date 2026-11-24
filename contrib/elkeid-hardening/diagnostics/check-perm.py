import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

print('=== param permissions ===')
print(run(['bash','-c','ls -la /sys/module/elkeid/parameters/OPEN_HOOK /sys/module/elkeid/parameters/WRITE_HOOK /sys/module/elkeid/parameters/protector_switch 2>&1']))
print('=== test protector_switch write ===')
print(run(['bash','-c','echo N > /sys/module/elkeid/parameters/protector_switch 2>&1 && echo PROTECTOR_N_OK || echo PROTECTOR_N_FAIL; cat /sys/module/elkeid/parameters/protector_switch']))
print('=== then try OPEN_HOOK ===')
print(run(['bash','-c','echo 1 > /sys/module/elkeid/parameters/OPEN_HOOK 2>&1 && echo OPEN_OK || echo OPEN_FAIL; cat /sys/module/elkeid/parameters/OPEN_HOOK']))
