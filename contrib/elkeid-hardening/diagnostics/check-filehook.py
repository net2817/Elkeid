import subprocess
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

print('=== driver params (file/read/write related) ===')
print(run(['bash','-c','ls /sys/module/elkeid/parameters/ 2>/dev/null | grep -iE "file|read|write|open|fmonitor|watch"']))
print('=== values ===')
print(run(['bash','-c','for p in /sys/module/elkeid/parameters/*READ* /sys/module/elkeid/parameters/*WRITE* /sys/module/elkeid/parameters/*FILE* /sys/module/elkeid/parameters/*OPEN*; do [ -f "$p" ] && echo "$(basename $p)=$(cat $p)"; done']))
