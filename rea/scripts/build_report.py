#!/usr/bin/env python3
"""Assemble a human-readable REPORT.txt from recon outputs."""
import argparse, json, os, glob

def read(p, limit=None):
    if not os.path.isfile(p):
        return ''
    with open(p, encoding='utf-8', errors='ignore') as f:
        lines = f.read().splitlines()
    return '\n'.join(lines[:limit] if limit else lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    out = args.out

    s = {}
    sp = os.path.join(out, 'summary.json')
    if os.path.isfile(sp):
        s = json.load(open(sp, encoding='utf-8'))

    lines = []
    A = lines.append
    A('=' * 72)
    A('iReadNote 5.3.0 IPA — 静态逆向分析产物报告')
    A('=' * 72)
    A('')
    A('[1] 目标身份')
    A(f"  bundle_id : {s.get('bundle_id')}")
    A(f"  version   : {s.get('version')}")
    A(f"  build     : {s.get('build')}")
    m = s.get('macho', {})
    A(f"  arch      : {m.get('arch')}")
    A(f"  cryptid   : {m.get('cryptid')}  (0=已解密, 可静态分析)")
    A(f"  bin_sha256: {m.get('sha256')}")
    A('')
    A('[2] 产物文件清单')
    for root, dirs, files in os.walk(out):
        for fn in sorted(files):
            rel = os.path.relpath(os.path.join(root, fn), out)
            if rel == 'REPORT.txt': continue
            sz = os.path.getsize(os.path.join(root, fn))
            A(f'  {rel:<48} {sz:>10} B')
    A('')
    A('[3] Info.plist 关键配置')
    A(read(os.path.join(out, 'info_plist.txt'), 40))
    A('')
    A('[4] 业务关键字符串 — 本地化文案（会员/广告/爱阅点规则）')
    A(read(os.path.join(out, 'hits', 'localizable_hits.txt'), 60))
    A('')
    A('[5] 业务关键字符串 — ObjC 类名')
    A(read(os.path.join(out, 'hits', 'objc_classname_hits.txt'), 60))
    A('')
    A('[6] 业务关键字符串 — ObjC 方法 (selector)')
    A(read(os.path.join(out, 'hits', 'objc_methname_hits.txt'), 80))
    A('')
    A('[7] 网络端点')
    A(read(os.path.join(out, 'network_endpoints.txt'), 60))
    A('')
    A('[8] 反编译导出')
    idx = os.path.join(out, 'decompiled', 'index.csv')
    if os.path.isfile(idx):
        rows = open(idx, encoding='utf-8', errors='ignore').read().splitlines()
        A(f'  functions total/matched rows: {len(rows)-1}')
        A('\n'.join('  ' + r for r in rows[:40]))
    else:
        A('  (no decompile index; Ghidra step skipped or failed)')
    A('')
    A('注：反编译产物为 Ghidra 伪代码，非原始源码；结论需结合动态验证。')

    txt = '\n'.join(lines) + '\n'
    with open(os.path.join(out, 'REPORT.txt'), 'w', encoding='utf-8') as f:
        f.write(txt)
    print('wrote', os.path.join(out, 'REPORT.txt'))
    print(txt)

if __name__ == '__main__':
    main()
