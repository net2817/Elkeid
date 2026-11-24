import yaml, json, re

lists = {}
macros = {}
rules = []
for f in ['falco_rules.yaml', 'falco_incubating.yaml', 'falco_sandbox.yaml']:
    data = yaml.safe_load(open('/root/'+f))
    for item in data:
        if not isinstance(item, dict):
            continue
        if 'list' in item and 'items' in item:
            lists[item['list']] = item['items']
        elif 'macro' in item and 'condition' in item:
            macros[item['macro']] = str(item['condition'])
        elif 'rule' in item:
            item['_file'] = f
            rules.append(item)

def expand(cond, depth=0):
    if depth > 5:
        return cond
    for name, mcond in macros.items():
        # replace the macro name (word boundary) with its condition
        cond = re.sub(r'\b%s\b' % re.escape(name), '(' + mcond + ')', cond)
    return cond

harm_map = {'CRITICAL':'critical','ERROR':'high','WARNING':'medium','NOTICE':'low','INFO':'low'}
esc = re.escape

converted = []
skipped = []

for r in rules:
    cond = expand(str(r.get('condition','')))
    if 'spawned_process' not in cond and 'execve' not in cond:
        skipped.append((r['rule'], 'non-execve'))
        continue

    exe_pats = []
    argv_pats = []

    # proc.name = "X" / = X
    for m in re.finditer(r'proc\.name\s*=\s*"([^"]+)"', cond):
        exe_pats.append(esc(m.group(1)))
    for m in re.finditer(r'proc\.name\s*=\s*([\w.]+)', cond):
        v = m.group(1)
        if v in ('in',):
            continue
        if v in lists:
            exe_pats += [esc(x) for x in lists[v]]
        elif v not in macros:
            exe_pats.append(esc(v))

    # proc.name in (...)  -- resolve list refs inside
    for m in re.finditer(r'proc\.name\s+in\s+\(([^)]+)\)', cond):
        inner = m.group(1)
        for x in re.findall(r'"([^"]+)"', inner):
            exe_pats.append(esc(x))
        for x in re.findall(r'([\w.]+)', inner):
            if x in lists and x not in ('or','and','not'):
                exe_pats += [esc(y) for y in lists[x]]

    # proc.pname in (...) / = (parent name -> use as exe? use argv/comm)
    for m in re.finditer(r'proc\.pname\s+in\s+\(([^)]+)\)', cond):
        for x in re.findall(r'([\w.]+)', m.group(1)):
            if x in lists and x not in ('or','and','not'):
                argv_pats += [esc(y) for y in lists[x]]

    # proc.exe startswith/contains
    for m in re.finditer(r'proc\.exe\s+(?:startswith|contains)\s+"([^"]+)"', cond):
        exe_pats.append(esc(m.group(1)))

    # proc.args / proc.cmdline contains / startswith / endswith
    for m in re.finditer(r'proc\.(?:args|cmdline)\s+(?:contains|icontains|startswith|endswith)\s+"([^"]+)"', cond):
        argv_pats.append(esc(m.group(1)))
    # proc.args = '...' 
    for m in re.finditer(r'proc\.(?:args|cmdline)\s*=\s*\'([^\']+)\'', cond):
        argv_pats.append(esc(m.group(1)))
    # proc.cwd startswith
    for m in re.finditer(r'proc\.cwd\s+startswith\s+"([^"]+)"', cond):
        argv_pats.append(esc(m.group(1)))

    if not exe_pats and not argv_pats:
        skipped.append((r['rule'], 'no pattern'))
        continue

    exe_re = '(?:' + '|'.join(sorted(set(exe_pats))) + ')' if exe_pats else ''
    argv_re = '(?:' + '|'.join(sorted(set(argv_pats))) + ')' if argv_pats else ''

    rule_id = re.sub(r'[^a-z0-9]+', '_', r['rule'].lower()).strip('_')
    harm = harm_map.get(r.get('priority','INFO'), 'low')
    attack_id = 'T1059'
    for t in r.get('tags', []):
        if re.match(r'^T\d', t):
            attack_id = t
            break

    converted.append({
        'rule_id': rule_id, 'name': r['rule'], 'desc': str(r.get('desc',''))[:200],
        'harm': harm, 'exe_re': exe_re, 'argv_re': argv_re, 'attack_id': attack_id,
    })

print('converted:', len(converted), 'skipped:', len(skipped))
for s in skipped:
    print('  skip:', s[0], '-', s[1])
json.dump(converted, open('/tmp/falco_converted.json','w'))
print('saved')
