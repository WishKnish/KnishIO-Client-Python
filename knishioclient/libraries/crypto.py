# -*- coding: utf-8 -*-
from . import strings
from .Base58 import Base58
from .Soda import Soda
from .NobleMLKEMBridge import NobleMLKEMBridge
from typing import List, Dict, Tuple, TypeVar
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
    return strings.decode(Soda(CHARACTERS).encrypt(message, key))


def decrypt_message(message: str, private_key, public_key) -> List | Dict | None:
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


def keypair_from_seed(seed: str) -> Tuple[bytes, bytes]:
    """
    Generate ML-KEM768 key pair from seed using @noble/post-quantum bridge.

    Ensures 100% cross-SDK compatibility by using the same implementation
    as JavaScript, TypeScript, Kotlin, PHP, Rust, C, and C++ SDKs.

    Args:
        seed: Seed string for deterministic key generation

    Returns:
        Tuple of (public_key, secret_key) as bytes
    """
    # @noble/post-quantum requires 64-byte (128 hex char) seed
    seed_hex = generate_secret(seed, 128)  # 128 hex chars = 64 bytes

    # Use Node.js bridge to @noble/post-quantum for guaranteed compatibility
    public_key, secret_key = NobleMLKEMBridge.generate_keypair_from_seed(seed_hex)
    return public_key, secret_key


def noble_bridge_encaps(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate using @noble/post-quantum bridge.

    Args:
        public_key: Public key bytes

    Returns:
        Tuple of (ciphertext, shared_secret) as bytes
    """
    return NobleMLKEMBridge.encapsulate(public_key)


def noble_bridge_decaps(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Decapsulate using @noble/post-quantum bridge.

    Args:
        ciphertext: Ciphertext bytes
        secret_key: Secret key bytes

    Returns:
        Shared secret as bytes
    """
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

