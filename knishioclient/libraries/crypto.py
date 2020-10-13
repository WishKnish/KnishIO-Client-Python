# -*- coding: utf-8 -*-

from . import strings, Base58, Soda
from typing import Union, List, Dict
from hashlib import shake_256 as shake

_Message = Union[List, Dict, None]
_CHARACTERS = 'GMP'


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
    return Soda(_CHARACTERS).generate_private_key(key)


def generate_enc_public_key(key: Union[str, bytes]) -> bytes:
    """
    Derives a public key for encrypting data for this wallet's consumption

    :param key: str
    :return: str
    """
    return Soda(_CHARACTERS).generate_public_key(key)


def set_characters(characters: str = None):
    _CHARACTERS = characters if characters in Base58.__dict__['__annotations__'] else 'GMP'


def get_characters():
    return _CHARACTERS


def hash_share(key):
    return Soda(_CHARACTERS).short_hash(key)


def encrypt_message(message: _Message, key: str) -> str:
    return strings.decode(Soda(_CHARACTERS).encrypt(message, key))


def decrypt_message(message: str, private_key, public_key) -> _Message:
    return Soda(_CHARACTERS).decrypt(message, private_key, public_key)
