# -*- coding: utf-8 -*-
from . import strings
from .Base58 import Base58
from .Soda import Soda
from .NobleMLKEMBridge import NobleMLKEMBridge
from . import kcore
import hmac
from typing import List, Dict, Tuple, TypeVar, Any, Callable, Union
from hashlib import shake_256 as shake


CHARACTERS = 'GMP'
T = TypeVar('T')

def generate_bundle_hash(secret: str) -> str:
    """
    Hashes the user secret to produce a bundle hash

    :param secret: str
    :return: str
    """
    sponge = shake()
    sponge.update(strings.encode(secret))

    return sponge.hexdigest(32)


def generate_enc_private_key(key: str) -> bytes:
    """
    Derives a private key for encrypting data with the given key

    :param key: str
    :return: str
    """
    return Soda(CHARACTERS).generate_private_key(key)


def generate_enc_public_key(key: str | bytes) -> bytes:
    """
    Derives a public key for encrypting data for this wallet's consumption

    :param key: str
    :return: str
    """
    return Soda(CHARACTERS).generate_public_key(key)


def set_characters(characters: str = None):
    global CHARACTERS
    CHARACTERS = characters if characters in Base58.__dict__['__annotations__'] else 'GMP'


def get_characters():
    return CHARACTERS


def hash_share(key):
    return strings.decode(Soda(CHARACTERS).short_hash(key))


def encrypt_message(message: List | Dict | None, key: str) -> str:
    """Classical NaCl ``crypto_box_seal`` message encryption via :class:`Soda` (non-PQ).

    A general-purpose classical-crypto utility, NOT the SDK's canonical message envelope and
    not used by the SDK's own transport. The canonical **post-quantum ML-KEM** envelope
    (``{cipherText, encryptedMessage}``) is ``Wallet.encrypt_message``.
    """
    return strings.decode(Soda(CHARACTERS).encrypt(message, key))


def decrypt_message(message: str, private_key, public_key) -> List | Dict | None:
    """Classical NaCl ``crypto_box_seal_open`` message decryption via :class:`Soda` (non-PQ).

    The classical counterpart to :func:`encrypt_message`. The canonical post-quantum
    ML-KEM envelope is ``Wallet.decrypt_message``.
    """
    return Soda(CHARACTERS).decrypt(message, private_key, public_key)


def generate_batch_id(molecular_hash: str = None, index=None) -> str:
    """
    :return: str
    """
    if molecular_hash is not None and index is not None:
        return generate_bundle_hash(f"{str(molecular_hash)}{str(index)}")

    return strings.random_string(64)


def generate_secret(seed: str | bytes | None = None, length: int = 2048):
    if seed:
        sponge = shake(strings.encode(seed))
        return sponge.hexdigest(length // 2)
    return strings.random_string(length)


def keypair_from_seed(seed: str, param_set: int | str = 1024) -> Tuple[bytes, bytes]:
    """
    Generate an ML-KEM key pair deterministically from a seed.

    libkcore (the shared KnishIO crypto core) handles ML-KEM-1024 and ML-KEM-768 when it is
    bundled; otherwise the Node.js bridge to @noble/post-quantum does. Both derive the same keys,
    byte for byte, as every other KnishIO SDK.

    Args:
        seed: Seed string for deterministic key generation
        param_set: ML-KEM parameter set (1024 or 768)

    Returns:
        Tuple of (public_key, secret_key) as bytes
    """
    # 64-byte (128 hex char) FIPS 203 seed d || z
    seed_hex = generate_secret(seed, 128)  # 128 hex chars = 64 bytes

    param_num = int(param_set)
    pair = None
    if param_num == 1024:
        pair = kcore.mlkem1024_keypair(bytes.fromhex(seed_hex))
    elif param_num == 768:
        pair = kcore.mlkem768_keypair(bytes.fromhex(seed_hex))
    if pair is not None:
        return pair

    public_key, secret_key = NobleMLKEMBridge.generate_keypair_from_seed(seed_hex, param_set)
    return public_key, secret_key


def noble_bridge_encaps(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate to an ML-KEM public key (the parameter set follows from its length).

    libkcore handles 1568-byte (ML-KEM-1024) and 1184-byte (ML-KEM-768) keys with fresh random
    coins per call; without it, or for any other length, the @noble/post-quantum bridge does.

    Args:
        public_key: Public key bytes

    Returns:
        Tuple of (ciphertext, shared_secret) as bytes
    """
    result = kcore.mlkem1024_encaps(public_key) or kcore.mlkem768_encaps(public_key)
    if result is not None:
        return result
    return NobleMLKEMBridge.encapsulate(public_key)


def noble_bridge_decaps(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Decapsulate an ML-KEM ciphertext (the parameter set follows from the lengths).

    libkcore handles (1568, 3168)-byte ML-KEM-1024 and (1088, 2400)-byte ML-KEM-768 pairs;
    without it, or for any other lengths, the @noble/post-quantum bridge does.

    Args:
        ciphertext: Ciphertext bytes
        secret_key: Secret key bytes

    Returns:
        Shared secret as bytes
    """
    shared = kcore.mlkem1024_decaps(ciphertext, secret_key) or kcore.mlkem768_decaps(ciphertext, secret_key)
    if shared is not None:
        return shared
    return NobleMLKEMBridge.decapsulate(ciphertext, secret_key)


def shake256(input_data: str, output_length: int) -> str:
    """
    SHAKE256 hash function
    
    :param input_data: The input string to hash
    :param output_length: The desired output length in bits
    :return: The hex-encoded hash
    """
    sponge = shake()
    sponge.update(strings.encode(input_data))
    # output_length is in bits, hexdigest expects bytes
    return sponge.hexdigest(output_length // 8)



def zeroize(b: Any) -> None:
    """
    Overwrites bytearray, list, or mutable sequence with zeros in-place.
    """
    if isinstance(b, bytearray):
        for i in range(len(b)):
            b[i] = 0
    elif isinstance(b, list):
        for i in range(len(b)):
            b[i] = 0


def constant_time_compare(val1: Union[str, bytes, bytearray], val2: Union[str, bytes, bytearray]) -> bool:
    """
    Constant-time comparison of two strings or byte sequences to prevent timing attacks.
    """
    if isinstance(val1, str):
        val1 = val1.encode('utf-8')
    if isinstance(val2, str):
        val2 = val2.encode('utf-8')
    return hmac.compare_digest(bytes(val1), bytes(val2))


def with_secure_bytes(b: bytearray, fn: Callable[[bytearray], T]) -> T:
    """
    Executes a callback with a mutable bytearray and ensures it is zeroized on exit.
    """
    try:
        return fn(b)
    finally:
        zeroize(b)


def with_secure_string(s: str, fn: Callable[[str], T]) -> T:
    """
    Executes a callback with a secret string.
    """
    return fn(s)
