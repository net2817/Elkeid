import yaml, json

rules = []
for f in ['falco_rules.yaml', 'falco_incubating.yaml', 'falco_sandbox.yaml']:
    try:
        data = yaml.safe_load(open('/root/'+f))
        for item in data:
            if isinstance(item, dict) and 'rule' in item:
                item['_file'] = f
                rules.append(item)
    except Exception as e:
        print('parse err', f, e)

print('total rules:', len(rules))
# show the execve-based rules (contain spawned_process or evt.type=execve)
print('=== execve-based rules ===')
n = 0
for r in rules:
    cond = str(r.get('condition',''))
    if 'spawned_process' in cond or 'execve' in cond:
        n += 1
        print('--- %s [%s]' % (r['rule'], r.get('priority','')))
        print('  cond: %s' % cond.replace('\n',' ')[:200])
print('execve-based count:', n)

# also count network (connect) rules
m = 0
for r in rules:
    cond = str(r.get('condition',''))
    if 'connect' in cond or 'evt.type' in cond and ('connect' in cond):
        m += 1
print('connect-related count:', m)
