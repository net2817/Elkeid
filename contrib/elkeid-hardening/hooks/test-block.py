import subprocess, time
def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except Exception as e:
        return 'ERR ' + str(e)

# start rst in background (sets blocklist + allowlist, then reads events)
p = subprocess.Popen(['./target/release/rst'], cwd='/root/driver',
                     stdout=open('/tmp/rst_out.txt','w'), stderr=subprocess.STDOUT)
print('rst pid:', p.pid)
time.sleep(4)

print('=== test blocking ===')
for name in ['curl','wget','nc','ls','cat']:
    r = subprocess.call(['bash','-c','%s --version >/dev/null 2>&1' % name])
    print('%s exit=%d' % (name, r))

# check rst output (any blocklist setup errors)
print('=== rst output ===')
print(run(['bash','-c','head -20 /tmp/rst_out.txt']))
p.terminate()
