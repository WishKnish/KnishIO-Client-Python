#!/usr/bin/env python3
"""Download one libkcore build from the pinned KnishIO-Crypto-Core Release (stdlib only).

usage: python scripts/fetch_kcore.py (--target <t> | --host) [--dest knishioclient/_kcore]
                                     [--pins scripts/kcore-pins.json]

The release tarball must match its sha256 pin, and the library inside must match the package's
own SHAKE256SUMS line. The library is written to <dest>/<name> (the only file there afterwards)
next to <dest>/TARGET, which setup.py reads when building a platform wheel. Prints
"FETCH_KCORE ok <target> <dest>/<name>", or "FETCH_KCORE FAIL <reason>" and exits non-zero.
"""
import argparse
import hashlib
import json
import platform
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parent.parent


def fail(reason: str, code: int = 1) -> NoReturn:
    print(f'FETCH_KCORE FAIL {reason}')
    sys.exit(code)


def host_target() -> str:
    machine = platform.machine().lower()
    if sys.platform.startswith('linux'):
        arch = {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine)
        if arch is not None:
            libc = 'gnu' if platform.libc_ver()[0] == 'glibc' else 'musl'
            return f'linux-{arch}-{libc}'
    elif sys.platform == 'darwin':
        return 'darwin-universal'
    elif sys.platform == 'win32' and machine == 'amd64':
        return 'windows-x64'
    fail(f'no kcore target for {sys.platform}/{platform.machine()}', 2)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for block in iter(lambda: fh.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--target')
    group.add_argument('--host', action='store_true')
    ap.add_argument('--dest', default=str(ROOT / 'knishioclient' / '_kcore'))
    ap.add_argument('--pins', default=str(ROOT / 'scripts' / 'kcore-pins.json'))
    opts = ap.parse_args()

    pins = json.loads(Path(opts.pins).read_text('utf-8'))
    target = host_target() if opts.host else opts.target
    entry = pins['targets'].get(target)
    if entry is None:
        fail(f'unknown target {target}', 2)
    version = pins['version']
    url = pins['url'].format(version=version, target=target)
    package = f'knishio-crypto-core-{version}-{target}'

    cache = ROOT / 'build' / 'kcore-cache' / f'{package}.tar.gz'
    if not cache.is_file():
        cache.parent.mkdir(parents=True, exist_ok=True)
        partial = cache.with_suffix('.part')
        try:
            with urllib.request.urlopen(url) as resp, open(partial, 'wb') as out:
                while block := resp.read(1 << 20):
                    out.write(block)
        except OSError as e:
            partial.unlink(missing_ok=True)
            fail(f'download {url}: {e}')
        partial.replace(cache)
    if sha256_file(cache) != entry['sha256']:
        fail(f'sha256 {cache.name}')

    with tarfile.open(cache, 'r:gz') as tar:
        def member(rel: str) -> bytes:
            try:
                fh = tar.extractfile(f'{package}/{rel}')
            except KeyError:
                fh = None
            if fh is None:
                fail(f'{rel} missing from {cache.name}')
            return fh.read()

        data = member(entry['member'])
        sums = member('SHAKE256SUMS').decode('utf-8')
    listed = {path: digest for digest, path in (line.split('  ', 1) for line in sums.splitlines() if line)}
    if listed.get(entry['member']) != hashlib.shake_256(data).hexdigest(32):
        fail(f"shake256 {entry['member']}")

    dest = Path(opts.dest)
    dest.mkdir(parents=True, exist_ok=True)
    for old in dest.iterdir():
        if old.is_file():
            old.unlink()
    (dest / entry['name']).write_bytes(data)
    (dest / 'TARGET').write_text(target + '\n', 'utf-8')
    print(f"FETCH_KCORE ok {target} {dest / entry['name']}")


if __name__ == '__main__':
    main()
