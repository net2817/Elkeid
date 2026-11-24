import subprocess, time
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

print('=== 1. stop agent ===')
print(run(['bash','-c','systemctl stop elkeid-agent 2>&1; sleep 2; echo STOPPED']))
print('=== 2. rmmod ===')
print(run(['bash','-c','rmmod elkeid 2>&1; echo RMMOD_RC=$?; lsmod | grep elkeid || echo MODULE_GONE']))
print('=== 3. insmod with params ===')
print(run(['bash','-c','insmod /tmp/LKM/elkeid.ko OPEN_HOOK=1 WRITE_HOOK=1 2>&1; echo INSMOD_RC=$?; lsmod | grep elkeid']))
print('=== 4. verify params ===')
print(run(['bash','-c','echo OPEN=$(cat /sys/module/elkeid/parameters/OPEN_HOOK) WRITE=$(cat /sys/module/elkeid/parameters/WRITE_HOOK)']))
print('=== 5. start agent ===')
print(run(['bash','-c','systemctl start elkeid-agent 2>&1; sleep 8; systemctl is-active elkeid-agent']))
print('=== 6. params after agent start ===')
print(run(['bash','-c','echo OPEN=$(cat /sys/module/elkeid/parameters/OPEN_HOOK) WRITE=$(cat /sys/module/elkeid/parameters/WRITE_HOOK) 2>&1']))
