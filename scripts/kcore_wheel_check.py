#!/usr/bin/env python3
"""Check an INSTALLED knishioclient wheel's libkcore path against the cross-platform vectors.

usage: python scripts/kcore_wheel_check.py --mode {lib,full,fallback} --vectors <cross-platform-test-vectors.json>

Run it from a directory outside the checkout, so the installed package (not the source tree) is
what gets imported.

  lib       loads knishioclient/libraries/kcore.py by file path (no knishioclient import, so no
            libnacl/libsodium) with KNISHIO_KCORE=require and checks the WOTS+ address, the
            ML-KEM-1024 and ML-KEM-768 keygen KATs, both encaps/decaps round trips and a chain walk
  full      lib, then the SDK itself with KNISHIO_KCORE=require: wallet addresses and ML-KEM keygen
            and decrypt vectors at both parameter sets
  fallback  the pure py3-none-any wheel: libkcore absent, the same SDK ML-KEM vectors through the
            Node bridge

Prints "KCORE_WHEEL ok mode=<mode> lib=<path>" or "KCORE_WHEEL FAIL <step>" and exits 1.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import NoReturn


def fail(step: str) -> NoReturn:
    print(f'KCORE_WHEEL FAIL {step}')
    sys.exit(1)


def check(cond, step: str) -> None:
    if not cond:
        fail(step)


def shake_hex(data: bytes, n: int) -> str:
    return hashlib.shake_256(data).hexdigest(n)


def is_hex(s: str) -> bool:
    return len(s) > 0 and all(c in "0123456789abcdefABCDEF" for c in s)


# Copied from sdks/KnishIO-Crypto-Core/tests/gen_vectors.py (a port of the JS Wallet.generateKey).
def generate_key(secret: str, token: str, position: str) -> str:
    secret_hex = secret if is_hex(secret) else shake_hex(secret.encode("utf-8"), 128)
    position_hex = position if is_hex(position) else shake_hex(position.encode("utf-8"), 32)
    indexed = int(secret_hex, 16) + int(position_hex, 16)
    intermediate = shake_hex((format(indexed, "x") + (token or "")).encode("utf-8"), 1024)
    return shake_hex(intermediate.encode("ascii"), 1024)


def load_kcore(pkg: Path):
    spec = importlib.util.spec_from_file_location('kcore_wheel_check_kcore', pkg / 'libraries' / 'kcore.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def lib_checks(kcore, pkg: Path, vectors: dict) -> str:
    try:
        check(kcore.available(), 'available')
    except kcore.KcoreUnavailable as e:
        fail(f'available: {e}')
    path = kcore.library_path()
    check(path is not None and Path(path).resolve().parent == (pkg / '_kcore').resolve(), f'library-path {path}')

    for t in vectors['wallet_generation']['tests']:
        key = generate_key(t['secret'], t['token'], t['position'])
        check(kcore.wots_address(key) == t['expectedAddress'], f"wots_address {t['name']}")

    for param_set, keypair, encaps, decaps in (
        (1024, kcore.mlkem1024_keypair, kcore.mlkem1024_encaps, kcore.mlkem1024_decaps),
        (768, kcore.mlkem768_keypair, kcore.mlkem768_encaps, kcore.mlkem768_decaps),
    ):
        kg = vectors[f'mlkem{param_set}']['keygen']
        key = generate_key(kg['secret'], kg['token'], kg['position'])
        pk, sk = keypair(hashlib.shake_256(key.encode()).digest(64))
        check(pk == base64.b64decode(kg['expectedPubkey']), f'mlkem{param_set} keygen KAT')
        ct, ss = encaps(pk)
        check(decaps(ct, sk) == ss, f'mlkem{param_set} round trip')

    k = hashlib.shake_256(b'kcore-wheel-check').hexdigest(1024)
    reference = ''
    for i in range(16):
        chunk = k[128 * i:128 * (i + 1)]
        for _ in range(i):
            chunk = hashlib.shake_256(chunk.encode('ascii')).hexdigest(64)
        reference += chunk
    check(kcore.chains_hex(k, list(range(16))) == reference, 'chains_hex')
    return path


def sdk_mlkem_checks(vectors: dict) -> None:
    import knishioclient
    from knishioclient.models import Wallet
    check('site-packages' in knishioclient.__file__, f'sdk-not-installed {knishioclient.__file__}')
    for param_set in (1024, 768):
        kg = vectors[f'mlkem{param_set}']['keygen']
        w = Wallet(secret=kg['secret'], token=kg['token'], position=kg['position'], mlkem_param_set=param_set)
        check(w.pubkey == kg['expectedPubkey'], f'sdk mlkem{param_set} keygen')
        d = vectors[f'mlkem{param_set}']['decrypt']
        w = Wallet(secret=d['secret'], token=d['token'], position=d['position'], mlkem_param_set=param_set)
        plain = w.decrypt_message({'cipherText': d['cipherText'], 'encryptedMessage': d['encryptedMessage']})
        check(plain == d['expectedPlaintext'], f'sdk mlkem{param_set} decrypt')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', required=True, choices=('lib', 'full', 'fallback'))
    ap.add_argument('--vectors', required=True)
    opts = ap.parse_args()
    vectors = json.loads(Path(opts.vectors).read_text('utf-8'))['vectors']

    spec = importlib.util.find_spec('knishioclient')
    check(spec is not None and spec.origin is not None, 'not-installed')
    pkg = Path(spec.origin).parent
    check('site-packages' in str(pkg), f'not-installed {pkg}')

    os.environ['KNISHIO_KCORE'] = 'auto' if opts.mode == 'fallback' else 'require'
    kcore = load_kcore(pkg)
    if opts.mode == 'fallback':
        check(not kcore.available() and kcore.library_path() is None, 'library-present-in-pure-wheel')
        path = None
    else:
        path = lib_checks(kcore, pkg, vectors)

    if opts.mode in ('full', 'fallback'):
        sdk_mlkem_checks(vectors)
        if opts.mode == 'full':
            from knishioclient.models import Wallet
            for t in vectors['wallet_generation']['tests']:
                w = Wallet(secret=t['secret'], token=t['token'], position=t['position'])
                check(w.address == t['expectedAddress'], f"sdk address {t['name']}")
            from knishioclient.libraries import kcore as sdk_kcore
            check(sdk_kcore.library_path() == path, 'sdk-loaded-a-different-library')

    print(f'KCORE_WHEEL ok mode={opts.mode} lib={path}')


if __name__ == '__main__':
    main()
