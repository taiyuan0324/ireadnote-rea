#!/usr/bin/env python3
"""Full network-surface sweep across an unpacked .app bundle.

Walks main binary + Frameworks + PlugIns + resources, harvests:
  - http(s) URLs
  - bare hostnames
  - API-like paths (/v1/, /api/, /member, /vip, /order, /pay ...)
  - CloudKit record types / zone hints
  - StoreKit product-id-like literals
Then classifies membership-relevant hits.
"""
import os, re, sys, json

ROOT = sys.argv[1]
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.getcwd(), 'network_sweep')

os.makedirs(OUT, exist_ok=True)

TEXT_EXT = {'.plist', '.strings', '.json', '.xml', '.txt', '.js', '.css', '.html',
            '.htm', '.xcprivacy', '.entitlements', '.mobileprovision'}

def iter_files(root):
    for dp, dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            try:
                if os.path.getsize(p) > 200 * 1024 * 1024:
                    continue
            except OSError:
                continue
            yield p

url_re = re.compile(rb'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]{4,}')
host_re = re.compile(rb'(?<![A-Za-z0-9@._-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|cn|net|org|io|app|dev|me|co|cc|tv|xyz|top|site|info|link|vip)(?![A-Za-z0-9.-])')
path_re = re.compile(rb'(/(?:api|v\d+|member|vip|user|order|pay|purchase|subscri|entitle|receipt|verify|auth|login|account|device|config|ad|reward)[A-Za-z0-9_/{}\-.?=&%:@]{0,80})')
cktype_re = re.compile(rb'\b(?:CKRecord|recordType|RecordType|zoneID|ZoneID|zoneName)[A-Za-z0-9_.]*')
pid_re = re.compile(rb'\b(?:[a-z]{2,8}\.){1,4}(?:vip|pro|premium|member|lifetime|monthly|yearly|quarterly|sub|subs|purchase)[A-Za-z0-9_.]{0,40}')

def harvest(path):
    try:
        data = open(path, 'rb').read()
    except OSError:
        return None
    urls = sorted({m.group().decode('latin-1', 'ignore') for m in url_re.finditer(data)})
    hosts = sorted({m.group().decode('latin-1', 'ignore') for m in host_re.finditer(data)})
    paths = sorted({m.group().decode('latin-1', 'ignore') for m in path_re.finditer(data)})
    ck = sorted({m.group().decode('latin-1', 'ignore') for m in cktype_re.finditer(data)})
    pids = sorted({m.group().decode('latin-1', 'ignore') for m in pid_re.finditer(data)})
    return data, urls, hosts, paths, ck, pids

all_urls, all_hosts, all_paths, all_ck, all_pids = {}, {}, {}, {}, {}
per_file = {}
for p in iter_files(ROOT):
    r = harvest(p)
    if not r:
        continue
    data, urls, hosts, paths, ck, pids = r
    rel = os.path.relpath(p, ROOT)
    if urls or hosts or paths:
        per_file[rel] = {'urls': urls, 'hosts': hosts, 'paths': paths,
                         'cloudkit': ck, 'product_ids': pids, 'size': len(data)}
    for u in urls: all_urls.setdefault(u, set()).add(rel)
    for h in hosts: all_hosts.setdefault(h, set()).add(rel)
    for pa in paths: all_paths.setdefault(pa, set()).add(rel)
    for c in ck: all_ck.setdefault(c, set()).add(rel)
    for pid in pids: all_pids.setdefault(pid, set()).add(rel)

def write(name, mapping):
    with open(os.path.join(OUT, name), 'w', encoding='utf-8') as f:
        for k in sorted(mapping):
            f.write(k + '\n')

write('all_urls.txt', all_urls)
write('all_hosts.txt', all_hosts)
write('all_paths.txt', all_paths)
write('cloudkit_tokens.txt', all_ck)
write('product_ids.txt', all_pids)

with open(os.path.join(OUT, 'per_file.json'), 'w', encoding='utf-8') as f:
    json.dump(per_file, f, ensure_ascii=False, indent=2)

# membership-relevant classification
biz = re.compile(r'jxd|ireadnote|member|vip|subscri|purchase|entitle|receipt|pay|order|cloudkit|icloud', re.I)
biz_hosts = {h: sorted(v) for h, v in all_hosts.items() if biz.search(h)}
biz_urls = {u: sorted(v) for u, v in all_urls.items() if biz.search(u)}

print('files scanned      :', len(per_file))
print('unique urls        :', len(all_urls))
print('unique hosts       :', len(all_hosts))
print('unique api paths   :', len(all_paths))
print('unique product ids :', len(all_pids))
print('biz hosts          :', len(biz_hosts))
print('biz urls           :', len(biz_urls))
print('\n--- biz hosts ---')
for h in sorted(biz_hosts): print(' ', h, '<-', ', '.join(biz_hosts[h])[:80])
print('\n--- biz urls ---')
for u in sorted(biz_urls): print(' ', u[:150])
print('\n--- product ids ---')
for p in sorted(all_pids):
    if len(p) < 80: print(' ', p)
