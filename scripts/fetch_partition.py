#!/usr/bin/env python3
"""Take one partition out of the payload.bin in a Xiaomi OTA, over HTTPS.

Only the bytes of that partition are fetched: one range request for the
compressed operations it is made of. ZIP64, the big-endian payload header
and the operation types a full package uses are all handled.

Usage:
  fetch_partition.py --config devices/enuma.toml --partition boot --out stock/boot.img

The partition's SHA-256 is checked against the one the configuration names
(`recovery` in [stock]), so a truncated download never reaches the packer.
"""
import argparse
import bz2
import hashlib
import lzma
import os
import struct
import sys
import tomllib
import urllib.request

UA = {'User-Agent': 'skyward-pack-fetch'}


def get(url, start, end, tries=5):
    last = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(url, headers={'Range': 'bytes=%d-%d' % (start, end), **UA})
            with urllib.request.urlopen(req, timeout=300) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            last = e
    raise last


def head_size(url):
    req = urllib.request.Request(url, method='HEAD', headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r:
        return int(r.headers['Content-Length'])


def varint(buf, i):
    shift = 0
    val = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7f) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def fields(buf):
    i, n = 0, len(buf)
    while i < n:
        key, i = varint(buf, i)
        num, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(buf, i)
            yield num, wt, v
        elif wt == 2:
            ln, i = varint(buf, i)
            yield num, wt, buf[i:i + ln]
            i += ln
        elif wt == 5:
            yield num, wt, struct.unpack_from('<I', buf, i)[0]
            i += 4
        elif wt == 1:
            yield num, wt, struct.unpack_from('<Q', buf, i)[0]
            i += 8
        else:
            raise ValueError('wire type %d' % wt)


def zip64_extra(extra):
    i = 0
    while i + 4 <= len(extra):
        hid, hsz = struct.unpack_from('<HH', extra, i)
        if hid == 1:
            body = extra[i + 4:i + 4 + hsz]
            return [struct.unpack_from('<Q', body, j)[0] for j in range(0, len(body) - 7, 8)]
        i += 4 + hsz
    return []


def payload_offset(url):
    total = head_size(url)
    tail = get(url, total - (1 << 18), total - 1)
    eocd = tail.rfind(b'PK\x05\x06')
    if eocd < 0:
        raise SystemExit('the package is not a zip')
    cd_size, cd_off = struct.unpack_from('<II', tail, eocd + 12)
    if cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        loc = tail.rfind(b'PK\x06\x07')
        z64 = struct.unpack_from('<Q', tail, loc + 8)[0]
        z = get(url, z64, z64 + 55)
        cd_size, cd_off = struct.unpack_from('<QQ', z, 40)
    cd = get(url, cd_off, cd_off + cd_size - 1)
    i = 0
    while i + 46 <= len(cd):
        if cd[i:i + 4] != b'PK\x01\x02':
            i += 1
            continue
        nlen, elen, _ = struct.unpack_from('<HHH', cd, i + 28)
        csz, usz = struct.unpack_from('<II', cd, i + 20)
        lho = struct.unpack_from('<I', cd, i + 42)[0]
        name = cd[i + 46:i + 46 + nlen].decode('utf-8', 'replace')
        if 0xFFFFFFFF in (csz, usz, lho):
            v = zip64_extra(cd[i + 46 + nlen:i + 46 + nlen + elen])
            if usz == 0xFFFFFFFF and v:
                usz = v.pop(0)
            if csz == 0xFFFFFFFF and v:
                csz = v.pop(0)
            if lho == 0xFFFFFFFF and v:
                lho = v.pop(0)
        if name.endswith('payload.bin'):
            lh = get(url, lho, lho + 63)
            nlen2, elen2 = struct.unpack_from('<HH', lh, 26)
            return lho + 30 + nlen2 + elen2
        i += 46 + nlen + elen
    raise SystemExit('the package holds no payload.bin')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', required=True)
    ap.add_argument('--partition', default='boot')
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    cfg = tomllib.load(open(args.config, 'rb'))
    stock = cfg['stock']
    url, want = stock['package'], args.partition

    data_off = payload_offset(url)
    hdr = get(url, data_off, data_off + 23)
    if hdr[:4] != b'CrAU':
        raise SystemExit('not a payload')
    version = struct.unpack_from('>Q', hdr, 4)[0]
    msize = struct.unpack_from('>Q', hdr, 12)[0]
    sigsz = struct.unpack_from('>I', hdr, 20)[0] if version >= 2 else 0
    print('payload v%d, manifest %d bytes, signature %d bytes' % (version, msize, sigsz))
    manifest = get(url, data_off + 24, data_off + 24 + msize - 1)
    blob = data_off + 24 + msize + sigsz

    target = None
    names = []
    for p in (v for n, w, v in fields(manifest) if n == 13 and w == 2):
        name = None
        for n, w, v in fields(p):
            if n == 1 and w == 2:
                name = v.decode()
        names.append(name)
        if name == want:
            target = p
    if target is None:
        print('the package holds: %s' % ', '.join(names))
        raise SystemExit('%s is not in this package' % want)

    size = digest = None
    ops = []
    for n, w, v in fields(target):
        if n == 7 and w == 2:
            for n2, w2, v2 in fields(v):
                if n2 == 1 and w2 == 0:
                    size = v2
                elif n2 == 2 and w2 == 2:
                    digest = v2.hex()
        elif n == 8 and w == 2:
            ops.append(v)
    print('%s: %d bytes in %d operations' % (want, size, len(ops)))

    parsed = []
    lo = hi = None
    for op in ops:
        otype = doff = dlen = None
        extents = []
        for n, w, v in fields(op):
            if n == 1 and w == 0:
                otype = v
            elif n == 2 and w == 0:
                doff = v
            elif n == 3 and w == 0:
                dlen = v
            elif n == 6 and w == 2:
                start = num = None
                for n2, w2, v2 in fields(v):
                    if n2 == 1 and w2 == 0:
                        start = v2
                    elif n2 == 2 and w2 == 0:
                        num = v2
                extents.append((start, num))
        parsed.append((otype, doff, dlen, extents))
        if dlen:
            lo = doff if lo is None else min(lo, doff)
            hi = doff + dlen if hi is None else max(hi, doff + dlen)

    print('fetching %.1f MiB in one request' % ((hi - lo) / 1048576), flush=True)
    blob_data = get(url, blob + lo, blob + hi - 1)
    print('downloaded %d bytes' % len(blob_data), flush=True)

    image = bytearray(size)
    for i, (otype, doff, dlen, extents) in enumerate(parsed, 1):
        if otype in (0, 1, 8):
            raw = blob_data[doff - lo:doff - lo + dlen]
            if otype == 8:
                raw = lzma.decompress(raw)
            elif otype == 1:
                raw = bz2.decompress(raw)
        elif otype == 6:
            raw = b''
        else:
            raise SystemExit('operation %d has type %d, which needs the old image' % (i, otype))
        pos = 0
        for start, num in extents:
            image[start:start + num] = raw[pos:pos + num] if raw else b'\x00' * num
            pos += num

    got = hashlib.sha256(image).hexdigest()
    print('sha256 %s' % got)
    expected = stock.get('recovery') if want == 'boot' else None
    if expected and got != expected:
        raise SystemExit('SHA-256 is %s, where the configuration names %s' % (got, expected))
    if digest and got != digest:
        raise SystemExit('SHA-256 %s does not match the manifest\'s %s' % (got, digest))

    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    with open(args.out, 'wb') as f:
        f.write(image)
    print('wrote %s (%d bytes), tail %s' % (args.out, len(image), bytes(image[-64:-60])))


if __name__ == '__main__':
    sys.exit(main())
