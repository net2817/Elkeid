import yaml, re, json

lists = {}
rules = []
for f in ['falco_rules.yaml', 'falco_incubating.yaml', 'falco_sandbox.yaml']:
    data = yaml.safe_load(open('/root/'+f))
    for item in data:
        if not isinstance(item, dict):
            continue
        if 'list' in item and 'items' in item:
            lists[item['list']] = item['items']
        elif 'rule' in item:
            item['_file'] = f
            rules.append(item)

def esc(s):
    return re.escape(str(s))

# file-based rules: open/open_write/fd.name/fd.directory patterns
converted = []
for r in rules:
    cond = str(r.get('condition',''))
    if not any(k in cond for k in ['open_write','is_open_write','is_open_read','fd.name','fd.directory','open_dir','open_read']):
        continue
    # determine read vs write
    is_write = ('open_write' in cond) or ('is_open_write' in cond)
    dtype = '608' if is_write else '609'

    path_pats = []
    # fd.name in (list) -> resolve
    for m in re.finditer(r'fd\.name\s+in\s+\(([^)]+)\)', cond):
        for x in re.findall(r'([\w.]+)', m.group(1)):
            if x in lists:
                path_pats += [esc(p) for p in lists[x]]
    # fd.directory in (list)
    for m in re.finditer(r'fd\.directory\s+in\s+\(([^)]+)\)', cond):
        for x in re.findall(r'([\w.]+)', m.group(1)):
            if x in lists:
                path_pats += [esc(p) for p in lists[x]]
    # fd.name startswith / contains
    for m in re.finditer(r'fd\.name\s+(?:startswith|contains)\s+"([^"]+)"', cond):
        path_pats.append(esc(m.group(1)))
    # direct fd.name = "X"
    for m in re.finditer(r'fd\.name\s*=\s*"([^"]+)"', cond):
        path_pats.append(esc(m.group(1)))

    if not path_pats:
        continue

    rule_id = re.sub(r'[^a-z0-9]+', '_', r['rule'].lower()).strip('_')
    converted.append({
        'rule_id': rule_id, 'name': r['rule'], 'desc': str(r.get('desc',''))[:150],
        'dtype': dtype, 'path_re': '(?:' + '|'.join(sorted(set(path_pats))) + ')',
    })

print('file rules converted:', len(converted))
for c in converted:
    print('  [%s] %s -> %s' % (c['dtype'], c['name'], c['path_re'][:100]))
json.dump(converted, open('/tmp/falco_file_rules.json','w'))
print('saved')
