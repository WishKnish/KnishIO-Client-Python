# -*- coding: utf-8 -*-
from . import strings, Base58, Soda
from .kem import ml_kem768
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


def generate_secret(seed: str | bytes | None = None, length: int = 1024):
    if seed:
        sponge = shake(strings.encode(seed))
        return sponge.hexdigest(length)
    return strings.random_string(length * 2)


def keypair_from_seed(seed: str) -> Tuple[bytes, bytes]:
    seed_bytes = bytes.fromhex(generate_secret(seed, 16)) + b"\x00" * 16
    return ml_kem768.keygen(seed_bytes, b"\x00" * 32)

