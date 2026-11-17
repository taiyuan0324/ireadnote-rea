#!/usr/bin/env python3
"""
Portable static recon for an unpacked iOS .app bundle.
Cross-platform: stdlib only, no macOS tools required.

Produces in --out:
  summary.json          machine-readable identity / crypto / counts
  info_plist.txt        key Info.plist fields
  objc_classname.txt    full __objc_classname inventory
  objc_methname.txt     full __objc_methname inventory
  cstring.txt           full __cstring inventory
  strings_ascii.txt     whole-binary ASCII strings
  localizable_zh.txt    parsed zh-Hans Localizable.strings
  hits/                 business-keyword filtered views per source
  network_endpoints.txt URLs / hosts harvested from all strings
"""
import argparse, json, os, plistlib, re, struct, sys

BIZ_PATTERNS = [
    # membership / entitlement
    'vip', 'member', 'premium', 'subscribe', 'subscription', 'purchase', 'iap',
    'storekit', 'receipt', 'entitle', 'restore', 'ownership', 'product_id',
    'fetchCurEntitlements', 'appTransaction', 'buyProduct', 'preparePurchase',
    '会员', '永久', '买断', '订阅', '付费', '权益', '内购', '恢复购买', '领取',
    # advertising / reward points
    'reward', 'advert', '\\bad\\b', 'rewarded', '爱阅点', '广告', '激励', '奖励',
    '免费', '签到', '任务', '推荐', 'referral', 'lmsg_biz', 'paidReward',
    'BuRewardAds', 'GgRewardAds', 'AdManager', 'VADateInfo', 'BizAdDateInfo',
    # validation / signing
    'token', 'signature', 'sign', 'verify', 'validate', 'check', 'is_member',
    'isVip', 'vip_type', 'memberReward', 'ownershipType', 'salt', 'secret',
]

def compile_patterns(extra_file=None):
    pats = list(BIZ_PATTERNS)
    if extra_file and os.path.isfile(extra_file):
        for line in open(extra_file, encoding='utf-8', errors='ignore'):
            line = line.strip()
            if line and not line.startswith('#'):
                # strip leading inline global flags; re.I is applied at compile time
                line = re.sub(r'^\(\?[a-zA-Z]+\)', '', line)
                if line:
                    pats.append(line)
    return re.compile('|'.join('(?:%s)' % p for p in pats), re.I)


def write(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        if isinstance(lines, str):
            f.write(lines)
        else:
            f.write('\n'.join(str(x) for x in lines))
            f.write('\n')


def parse_macho_sections(path):
    data = open(path, 'rb').read()
    result = {'size': len(data), 'format': None, 'arch': None}
    slices = []

    magic = data[:4]
    if magic == b'\xca\xfe\xba\xbe':      # FAT, big-endian
        result['format'] = 'fat'
        nfat = struct.unpack('>I', data[4:8])[0]
        for i in range(nfat):
            off = 8 + i * 20
            cputype, cpusub, foff, fsize, align = struct.unpack('>IIIII', data[off:off+20])
            slices.append((cputype, foff, fsize))
    elif magic == b'\xbe\xbaf\xca':       # FAT reversed
        result['format'] = 'fat-le'
        nfat = struct.unpack('<I', data[4:8])[0]
        for i in range(nfat):
            off = 8 + i * 20
            cputype, cpusub, foff, fsize, align = struct.unpack('<IIIII', data[off:off+20])
            slices.append((cputype, foff, fsize))
    else:
        slices.append((None, 0, len(data)))

    # pick the arm64 / largest slice
    cputype, base, size = max(slices, key=lambda s: (1 if (s[0] or 0) & 0x1000000 else 0, s[2]))
    result['arch'] = 'arm64' if (cputype or 0) & 0x1000000 else hex(cputype or 0)
    view = data[base:base+size]

    if view[:4] != b'\xcf\xfa\xed\xfe':
        result['error'] = 'not a thin LE macho64 slice'
        return result, view

    _, ct, cs, ft, ncmds, sizeofcmds, flags, reserved = struct.unpack_from('<IiiIIIII', view, 0)
    result['cputype'] = hex(ct)
    if (ct or 0) & 0x1000000:
        result['arch'] = 'arm64'
    elif (ct or 0) & 0x1000007:
        result['arch'] = 'arm (32)'
    elif ct == 7:
        result['arch'] = 'x86'
    elif ct == 0x01000007:
        result['arch'] = 'x86_64'
    result['filetype'] = ft
    result['ncmds'] = ncmds

    sections = {}
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(view): break
        cmd, cmdsize = struct.unpack_from('<II', view, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = view[off+8:off+24].rstrip(b'\x00').decode('ascii', 'ignore')
            nsects = struct.unpack_from('<I', view, off+64)[0]
            so = off + 72
            for si in range(nsects):
                if so + 80 > len(view): break
                sectname = view[so:so+16].rstrip(b'\x00').decode('ascii', 'ignore')
                segn = view[so+16:so+32].rstrip(b'\x00').decode('ascii', 'ignore')
                addr, ssz = struct.unpack_from('<QQ', view, so+32)
                foff = struct.unpack_from('<I', view, so+48)[0]
                sections[(segn, sectname)] = (foff, ssz, addr)
                so += 80
        elif cmd == 0x2C:  # LC_ENCRYPTION_INFO_64
            cryptoff, cryptsize, cryptid = struct.unpack_from('<III', view, off+8)
            result['cryptid'] = cryptid
            result['cryptoff'] = hex(cryptoff)
            result['cryptsize'] = hex(cryptsize)
        off += cmdsize
        if cmdsize == 0: break
    result['section_count'] = len(sections)
    result['sections'] = {f'{s[0]},{s[1]}': {'fileoff': hex(v[0]), 'size': hex(v[1]), 'addr': hex(v[2])}
                          for s, v in sections.items()}
    return result, view, sections


def cstrings_from(blob):
    out = []
    for part in blob.split(b'\x00'):
        if len(part) < 3: continue
        try:
            s = part.decode('utf-8')
        except UnicodeDecodeError:
            s = part.decode('latin-1', 'ignore')
        out.append(s)
    return out


def ascii_strings(data, minlen=5):
    return re.findall(rb'[\x20-\x7e]{%d,}' % minlen, data)


def parse_localizable(app):
    results = []
    for root, dirs, files in os.walk(app):
        for fn in files:
            if fn == 'Localizable.strings':
                p = os.path.join(root, fn)
                lang = os.path.basename(os.path.dirname(root)) or os.path.basename(os.path.dirname(p))
                d = None
                try:
                    raw = open(p, 'rb').read()
                except OSError:
                    continue
                try:
                    d = plistlib.loads(raw)
                    kind = 'bplist'
                except Exception:
                    # old-style text .strings
                    try:
                        txt = raw.decode('utf-16')
                    except Exception:
                        txt = raw.decode('utf-8', 'ignore')
                    d = {}
                    for m in re.finditer(r'"((?:\\.|[^"\\])*)"\s*=\s*"((?:\\.|[^"\\])*)"\s*;', txt):
                        d[m.group(1)] = m.group(2)
                    kind = 'text'
                if isinstance(d, dict):
                    results.append((lang, kind, d))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--app', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--patterns')
    args = ap.parse_args()

    app = args.app
    out = args.out
    os.makedirs(out, exist_ok=True)
    rx = compile_patterns(args.patterns)

    summary = {'app_path': app}
    info = {}
    ipath = os.path.join(app, 'Info.plist')
    if os.path.isfile(ipath):
        pl = plistlib.load(open(ipath, 'rb'))
        keys = ['CFBundleIdentifier', 'CFBundleShortVersionString', 'CFBundleVersion',
                'CFBundleExecutable', 'CFBundleName', 'CFBundleDisplayName',
                'MinimumOSVersion', 'UIRequiredDeviceCapabilities', 'CFBundleURLTypes',
                'LSApplicationQueriesSchemes', 'NSAppTransportSecurity']
        info = {k: pl.get(k) for k in keys}
        info['all_usage_descriptions'] = {k: v for k, v in pl.items()
                                          if k.startswith('NS') and 'UsageDescription' in k}
        summary['bundle_id'] = pl.get('CFBundleIdentifier')
        summary['version'] = pl.get('CFBundleShortVersionString')
        summary['build'] = pl.get('CFBundleVersion')
    write(os.path.join(out, 'info_plist.txt'),
          '\n'.join(f'{k} = {v}' for k, v in info.items()))

    bin_name = info.get('CFBundleExecutable') or 'iReadNote'
    bin_path = os.path.join(app, bin_name)
    macho = {'path': bin_path}
    view = None
    sections = {}
    if os.path.isfile(bin_path):
        macho, view, sections = parse_macho_sections(bin_path)
        macho['sha256'] = __import__('hashlib').sha256(open(bin_path, 'rb').read()).hexdigest()
    summary['macho'] = macho

    dump_map = {}
    for key, fname in [
        (('__TEXT', '__objc_classname'), 'objc_classname.txt'),
        (('__TEXT', '__objc_methname'), 'objc_methname.txt'),
        (('__TEXT', '__cstring'), 'cstring.txt'),
    ]:
        if key in sections:
            foff, ssz, _ = sections[key]
            lines = cstrings_from(view[foff:foff+ssz])
        else:
            lines = []
        write(os.path.join(out, fname), lines)
        dump_map[fname] = lines

    if view is not None:
        s = [x.decode('utf-8', 'ignore') for x in ascii_strings(view)]
        write(os.path.join(out, 'strings_ascii.txt'), s)
        dump_map['strings_ascii.txt'] = s

    # localizable
    loc_lines = []
    loc_all = []
    for lang, kind, d in parse_localizable(app):
        for k, v in sorted(d.items()):
            line = f'[{lang}/{kind}] {k} = {str(v)[:400]}'
            loc_all.append(line)
            if rx.search(k) or rx.search(str(v)):
                loc_lines.append(line)
    write(os.path.join(out, 'localizable_all.txt'), loc_all)
    write(os.path.join(out, 'localizable_zh.txt'),
          [x for x in loc_all if '[zh-Hans' in x])
    dump_map['localizable_all.txt'] = loc_all
    write(os.path.join(out, 'hits', 'localizable_hits.txt'), loc_lines)

    # filtered business hits per source
    for fname, lines in dump_map.items():
        hits = [x for x in lines if rx.search(x)]
        write(os.path.join(out, 'hits', fname.replace('.txt', '') + '_hits.txt'), hits)

    # network endpoints from all harvested strings
    pool = []
    for lines in dump_map.values():
        pool.extend(lines)
    urls = sorted(set(re.findall(r'https?://[^\s"\'<>]{4,}', '\n'.join(pool))))
    hosts = sorted(set(re.findall(r'(?<![@\w])(?:[a-z0-9-]+\.)+(?:com|cn|net|org|io|app|dev)(?:/[^\s]*)?', '\n'.join(pool), re.I)))
    write(os.path.join(out, 'network_endpoints.txt'), ['# URLs'] + urls + ['', '# HOSTS'] + hosts)

    summary['counts'] = {k: len(v) for k, v in dump_map.items()}
    summary['counts']['localizable_hits'] = len(loc_lines)
    summary['counts']['urls'] = len(urls)
    write(os.path.join(out, 'summary.json'), json.dumps(summary, ensure_ascii=False, indent=2))

    print('=== REA static recon summary ===')
    print(json.dumps({'bundle_id': summary.get('bundle_id'),
                      'version': summary.get('version'),
                      'cryptid': macho.get('cryptid'),
                      'arch': macho.get('arch'),
                      'counts': summary['counts']}, ensure_ascii=False, indent=2))
    return 0

if __name__ == '__main__':
    sys.exit(main())
