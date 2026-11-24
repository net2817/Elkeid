#!/usr/bin/env python
# minimal FIM: baseline + change detection + reconciliation (periodic full hash scan)
import os, sys, hashlib, json

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def scan(directory):
    result = {}
    for root, dirs, files in os.walk(directory):
        for f in files:
            path = os.path.join(root, f)
            try:
                result[os.path.relpath(path, directory)] = sha256_file(path)
            except Exception:
                pass
    return result

def cmd_init(directory, baseline_path):
    baseline = scan(directory)
    with open(baseline_path, 'w') as fp:
        json.dump(baseline, fp)
    print('baseline saved: %s (%d files)' % (baseline_path, len(baseline)))

def cmd_check(directory, baseline_path):
    with open(baseline_path) as fp:
        baseline = json.load(fp)
    current = scan(directory)
    added = set(current) - set(baseline)
    deleted = set(baseline) - set(current)
    modified = [f for f in set(current) & set(baseline) if current[f] != baseline[f]]
    print('=== FIM check: %s ===' % directory)
    print('added   : %d' % len(added))
    for f in sorted(added):
        print('  [+] %s sha256=%s' % (f, current[f][:16]))
    print('deleted : %d' % len(deleted))
    for f in sorted(deleted):
        print('  [-] %s' % f)
    print('modified: %d' % len(modified))
    for f in sorted(modified):
        print('  [~] %s  %s -> %s' % (f, baseline[f][:16], current[f][:16]))
    print('total changed: %d' % (len(added) + len(deleted) + len(modified)))

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('usage: fim.py init|check <dir> [baseline_path]')
        sys.exit(1)
    action, directory = sys.argv[1], sys.argv[2]
    baseline_path = sys.argv[3] if len(sys.argv) > 3 else directory.rstrip('/') + '.baseline.json'
    if action == 'init':
        cmd_init(directory, baseline_path)
    elif action == 'check':
        cmd_check(directory, baseline_path)
