import yaml, json, re

# 1. parse all 3 files
lists = {}
rules = []
for f in ['falco_rules.yaml', 'falco_incubating.yaml', 'falco_sandbox.yaml']:
    try:
        data = yaml.safe_load(open('/root/'+f))
        for item in data:
            if not isinstance(item, dict):
                continue
            if 'list' in item and 'items' in item:
                lists[item['list']] = item['items']
            elif 'rule' in item:
                item['_file'] = f
                rules.append(item)
    except Exception as e:
        print('parse err', f, e)

print('lists:', len(lists), 'rules:', len(rules))

def resolve_list(name):
    return lists.get(name, [])

def esc(s):
    return re.escape(s)

# map falco priority -> elkeid harm level
harm_map = {'CRITICAL':'critical','ERROR':'high','WARNING':'medium','NOTICE':'low','INFO':'low'}

converted = []
skipped = []

for r in rules:
    cond = str(r.get('condition',''))
    # only handle spawned_process (execve) rules
    if 'spawned_process' not in cond and 'execve' not in cond:
        skipped.append((r['rule'], 'non-execve'))
        continue

    exe_pats = []
    argv_pats = []

    # proc.name = "X" or proc.name=X
    for m in re.finditer(r'proc\.name\s*=\s*"([^"]+)"', cond):
        exe_pats.append(esc(m.group(1)))
    for m in re.finditer(r'proc\.name\s*=\s*(\w+)', cond):
        v = m.group(1)
        if v not in ('in',) and not v.startswith('proc'):
            if v in lists:
                exe_pats += [esc(x) for x in lists[v]]
            else:
                exe_pats.append(esc(v))

    # proc.name in (X, Y) or proc.name in (list_name)
    for m in re.finditer(r'proc\.name\s+in\s+\(([^)]+)\)', cond):
        for x in re.findall(r'"([^"]+)"|\'([^\']+)\'', m.group(1)):
            v = x[0] if x[0] else x[1]
            exe_pats.append(esc(v))
        for x in re.findall(r'([\w_]+)', m.group(1)):
            if x in lists and x not in ('or','and','not'):
                exe_pats += [esc(y) for y in lists[x]]

    # proc.exe startswith / contains
    for m in re.finditer(r'proc\.exe\s+(?:startswith|contains)\s+"([^"]+)"', cond):
        exe_pats.append(esc(m.group(1)))

    # proc.args contains "X" / proc.cmdline contains "X"
    for m in re.finditer(r'proc\.(?:args|cmdline)\s+(?:contains|icontains|startswith|endswith)\s+"([^"]+)"', cond):
        argv_pats.append(esc(m.group(1)))

    # proc.args startswith etc with = 
    for m in re.finditer(r'proc\.(?:args|cmdline)\s*=\s*\'?([^\'\s]+)\'?', cond):
        argv_pats.append(esc(m.group(1)))

    if not exe_pats and not argv_pats:
        skipped.append((r['rule'], 'no exe/argv pattern'))
        continue

    # dedupe + build regex
    exe_re = '(?:' + '|'.join(sorted(set(exe_pats))) + ')' if exe_pats else ''
    argv_re = '(?:' + '|'.join(sorted(set(argv_pats))) + ')' if argv_pats else ''

    rule_id = re.sub(r'[^a-z0-9]+', '_', r['rule'].lower()).strip('_')
    harm = harm_map.get(r.get('priority','INFO'), 'low')

    # tags -> attack id
    attack_id = 'T1059'
    for t in r.get('tags', []):
        if re.match(r'^T\d', t):
            attack_id = t
            break

    converted.append({
        'rule_id': rule_id,
        'name': r['rule'],
        'desc': str(r.get('desc',''))[:200],
        'harm': harm,
        'exe_re': exe_re,
        'argv_re': argv_re,
        'attack_id': attack_id,
    })

print('converted:', len(converted), 'skipped:', len(skipped))
for s in skipped[:20]:
    print('  skip:', s[0], '-', s[1])

# save for next step
json.dump(converted, open('/tmp/falco_converted.json','w'))
print('saved /tmp/falco_converted.json')
