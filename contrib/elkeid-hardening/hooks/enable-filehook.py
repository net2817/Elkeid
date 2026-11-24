import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

print('=== before ===')
print(run(['bash','-c','echo OPEN=$(cat /sys/module/elkeid/parameters/OPEN_HOOK) WRITE=$(cat /sys/module/elkeid/parameters/WRITE_HOOK)']))
print('=== enable ===')
print(run(['bash','-c','echo 1 > /sys/module/elkeid/parameters/OPEN_HOOK; echo 1 > /sys/module/elkeid/parameters/WRITE_HOOK; echo OPEN=$(cat /sys/module/elkeid/parameters/OPEN_HOOK) WRITE=$(cat /sys/module/elkeid/parameters/WRITE_HOOK)']))
print('=== trigger file ops ===')
print(run(['bash','-c','echo testdata > /tmp/fim_fw_test.txt; cat /tmp/fim_fw_test.txt >/dev/null; echo appended >> /tmp/fim_fw_test.txt; rm -f /tmp/fim_fw_test.txt; echo TRIGGERED']))
