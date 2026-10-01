# -*- coding: utf-8 -*-
"""Optional native crypto core: libkcore (KnishIO-Crypto-Core) through cffi in ABI mode.

Platform wheels bundle ``knishioclient/_kcore/<libkcore>``; the sdist and the ``py3-none-any``
wheel do not. Every function returns ``None`` when the library is not in use, when the input is
not one kcore handles, or when the C call rejects it; callers then run their pure-Python or Node
bridge path, so results never depend on whether the library is present.

``KNISHIO_KCORE``: ``auto`` (default: use the library when it loads), ``off`` (never load it) or
``require`` (raise :class:`KcoreUnavailable` when it cannot be loaded). ``KNISHIO_KCORE_LIB``
overrides the library path. Both are read on first use.

Only stdlib and cffi are imported, and nothing package-relative, so the module can also be loaded
by file path without importing ``knishioclient``.
"""
import os
import sys
from pathlib import Path
from typing import Any

ABI_VERSION = 1

_CDEF = """
int kcore_abi_version(void);
int kcore_shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);
int kcore_chains_hex(char *chunks, const int *counts, size_t n, int ways);
int kcore_wots_address(const char *key_hex2048, char *address_hex64);
int kcore_mlkem1024_keypair(const uint8_t seed[64], uint8_t pk[1568], uint8_t sk[3168]);
int kcore_mlkem1024_encaps(const uint8_t pk[1568], const uint8_t coins[32], uint8_t ct[1568], uint8_t ss[32]);
int kcore_mlkem1024_decaps(const uint8_t ct[1568], const uint8_t sk[3168], uint8_t ss[32]);
int kcore_mlkem768_keypair(const uint8_t seed[64], uint8_t pk[1184], uint8_t sk[2400]);
int kcore_mlkem768_encaps(const uint8_t pk[1184], const uint8_t coins[32], uint8_t ct[1088], uint8_t ss[32]);
int kcore_mlkem768_decaps(const uint8_t ct[1088], const uint8_t sk[2400], uint8_t ss[32]);
"""

_NAMES = {'linux': 'libkcore.so', 'darwin': 'libkcore.dylib', 'win32': 'kcore.dll'}

# (public key, secret key, ciphertext) sizes per ML-KEM parameter set.
_MLKEM_SIZES = {1024: (1568, 3168, 1568), 768: (1184, 2400, 1088)}
_SEED_BYTES = 64
_COINS_BYTES = 32
_SS_BYTES = 32

# Load result, filled by _ensure(): _state is None (not attempted), 'off', 'ok' or 'failed'.
_state: str | None = None
_ffi: Any = None
_lib: Any = None
_path: str | None = None
_reason: str | None = None
_mode_seen: str = 'auto'


class KcoreUnavailable(RuntimeError):
    """``KNISHIO_KCORE=require`` and libkcore could not be loaded."""


def _mode() -> str:
    mode = os.environ.get('KNISHIO_KCORE', 'auto').lower()
    if mode not in ('auto', 'off', 'require'):
        raise ValueError(f"KNISHIO_KCORE must be auto, off or require, got '{mode}'")
    return mode


def _default_path() -> Path | None:
    key = 'linux' if sys.platform.startswith('linux') else sys.platform
    name = _NAMES.get(key)
    if name is None:
        return None
    return Path(__file__).resolve().parent.parent / '_kcore' / name


def _load(path: Path | None) -> str | None:
    """Loads the library into _ffi/_lib; returns None on success or the failure reason."""
    global _ffi, _lib
    try:
        import cffi
    except ImportError:
        return 'cffi is not installed'
    if path is None or not path.is_file():
        return 'library file not found'
    ffi = cffi.FFI()
    ffi.cdef(_CDEF)
    try:
        lib: Any = ffi.dlopen(str(path))
    except OSError as e:
        return f'dlopen failed: {e}'
    abi = lib.kcore_abi_version()
    if abi != ABI_VERSION:
        return f'ABI version {abi}, expected {ABI_VERSION}'
    _ffi, _lib = ffi, lib
    return None


def _ensure() -> bool:
    """True when libkcore is loaded. In ``require`` mode a failed load raises on every call."""
    global _state, _path, _reason, _mode_seen
    if _state is None:
        _mode_seen = _mode()
        if _mode_seen == 'off':
            _state = 'off'
        else:
            override = os.environ.get('KNISHIO_KCORE_LIB')
            path = Path(override) if override else _default_path()
            _path = str(path) if path is not None else None
            _reason = _load(path)
            _state = 'ok' if _reason is None else 'failed'
    if _state == 'failed' and _mode_seen == 'require':
        raise KcoreUnavailable(f'libkcore unavailable: {_reason} ({_path})')
    return _state == 'ok'


def _reset() -> None:
    """Forget the load result so the next call re-reads the environment (tests only)."""
    global _state, _ffi, _lib, _path, _reason
    _state = _ffi = _lib = _path = _reason = None


def available() -> bool:
    return _ensure()


def library_path() -> str | None:
    return _path if _ensure() else None


def _zero(ffi, buf) -> None:
    ffi.memmove(buf, bytes(len(ffi.buffer(buf))), len(ffi.buffer(buf)))


def wots_address(key) -> str | None:
    """WOTS+ address of a 2048-hex key (``Wallet.generate_address``)."""
    if not isinstance(key, str) or len(key) != 2048 or not key.isascii() or not _ensure():
        return None
    ffi, lib = _ffi, _lib
    out = ffi.new('char[64]')
    if lib.kcore_wots_address(ffi.new('char[]', key.encode('ascii')), out) != 0:
        return None
    return ffi.buffer(out, 64)[:].decode('ascii')


def chains_hex(chunks, counts) -> str | None:
    """Advances ``len(counts)`` WOTS+ chains of 128 hex characters each (4-lane Keccak)."""
    n = len(counts)
    if not isinstance(chunks, str) or not 1 <= n <= 64 or len(chunks) != 128 * n or not chunks.isascii():
        return None
    if any(type(c) is not int or not 0 <= c <= 64 for c in counts):
        return None
    if not _ensure():
        return None
    ffi, lib = _ffi, _lib
    buf = ffi.new('char[]', chunks.encode('ascii'))
    if lib.kcore_chains_hex(buf, ffi.new('int[]', list(counts)), n, 4) != 0:
        return None
    return ffi.buffer(buf, 128 * n)[:].decode('ascii')


def _keypair(param_set: int, seed) -> tuple[bytes, bytes] | None:
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != _SEED_BYTES or not _ensure():
        return None
    ffi, lib = _ffi, _lib
    pk_len, sk_len, _ = _MLKEM_SIZES[param_set]
    fn = lib.kcore_mlkem1024_keypair if param_set == 1024 else lib.kcore_mlkem768_keypair
    pk = ffi.new(f'uint8_t[{pk_len}]')
    sk = ffi.new(f'uint8_t[{sk_len}]')
    try:
        if fn(bytes(seed), pk, sk) != 0:
            return None
        return bytes(ffi.buffer(pk)), bytes(ffi.buffer(sk))
    finally:
        _zero(ffi, sk)


def _encaps(param_set: int, pk) -> tuple[bytes, bytes] | None:
    pk_len, _, ct_len = _MLKEM_SIZES[param_set]
    if not isinstance(pk, (bytes, bytearray)) or len(pk) != pk_len or not _ensure():
        return None
    ffi, lib = _ffi, _lib
    fn = lib.kcore_mlkem1024_encaps if param_set == 1024 else lib.kcore_mlkem768_encaps
    # Fresh coins on every call: repeating them against one key repeats ct and ss.
    coins = ffi.new(f'uint8_t[{_COINS_BYTES}]', os.urandom(_COINS_BYTES))
    ct = ffi.new(f'uint8_t[{ct_len}]')
    ss = ffi.new(f'uint8_t[{_SS_BYTES}]')
    try:
        if fn(bytes(pk), coins, ct, ss) != 0:
            return None
        return bytes(ffi.buffer(ct)), bytes(ffi.buffer(ss))
    finally:
        _zero(ffi, coins)
        _zero(ffi, ss)


def _decaps(param_set: int, ct, sk) -> bytes | None:
    _, sk_len, ct_len = _MLKEM_SIZES[param_set]
    if (not isinstance(ct, (bytes, bytearray)) or not isinstance(sk, (bytes, bytearray))
            or len(ct) != ct_len or len(sk) != sk_len or not _ensure()):
        return None
    ffi, lib = _ffi, _lib
    fn = lib.kcore_mlkem1024_decaps if param_set == 1024 else lib.kcore_mlkem768_decaps
    skb = ffi.new(f'uint8_t[{sk_len}]', bytes(sk))
    ss = ffi.new(f'uint8_t[{_SS_BYTES}]')
    try:
        if fn(bytes(ct), skb, ss) != 0:
            return None
        return bytes(ffi.buffer(ss))
    finally:
        _zero(ffi, skb)
        _zero(ffi, ss)


def mlkem1024_keypair(seed) -> tuple[bytes, bytes] | None:
    return _keypair(1024, seed)


def mlkem1024_encaps(pk) -> tuple[bytes, bytes] | None:
    return _encaps(1024, pk)


def mlkem1024_decaps(ct, sk) -> bytes | None:
    return _decaps(1024, ct, sk)


def mlkem768_keypair(seed) -> tuple[bytes, bytes] | None:
    return _keypair(768, seed)


def mlkem768_encaps(pk) -> tuple[bytes, bytes] | None:
    return _encaps(768, pk)


def mlkem768_decaps(ct, sk) -> bytes | None:
    return _decaps(768, ct, sk)
