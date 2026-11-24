import yaml, re

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
    if depth > 5: return cond
    for name, mcond in macros.items():
        cond = re.sub(r'\b%s\b' % re.escape(name), '(' + mcond + ')', cond)
    return cond

cats = {'network':[], 'ptrace':[], 'kernel_module':[], 'file':[], 'execve_argv':[], 'container':[], 'other':[]}
for r in rules:
    cond = expand(str(r.get('condition','')))
    if 'spawned_process' in cond or 'execve' in cond:
        continue  # already handled
    rule = r['rule']
    if 'ptrace' in cond or 'PTRACE' in cond:
        cats['ptrace'].append((rule, cond))
    elif 'init_module' in cond or 'module' in cond.lower():
        cats['kernel_module'].append((rule, cond))
    elif any(k in cond for k in ['connect','udp','tcp','network','socket','inbound','outbound','ssh_connection']):
        cats['network'].append((rule, cond))
    elif any(k in cond for k in ['open_write','open_read','fd.name','fd.type','write below','Read ','read ']):
        cats['file'].append((rule, cond))
    elif 'container' in cond or 'k8s' in cond or 'K8S' in cond or 'privileged' in cond or 'user.uid' in cond:
        cats['container'].append((rule, cond))
    elif 'proc.name' in cond or 'proc.args' in cond:
        cats['execve_argv'].append((rule, cond))
    else:
        cats['other'].append((rule, cond))

for cat, items in cats.items():
    print('=== %s (%d) ===' % (cat, len(items)))
    for rule, cond in items:
        print('  - %s :: %s' % (rule, cond.replace('\n',' ')[:130]))
