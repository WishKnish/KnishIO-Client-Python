# -*- coding: utf-8 -*-

from typing import Union
from json import dumps, loads
from . import strings
from hashlib import shake_256 as shake
from libnacl.public import SecretKey
from libnacl.encode import hex_decode
from libnacl import (crypto_box_seal, crypto_box_seal_open, crypto_box_SECRETKEYBYTES, CryptError)
from base58 import BITCOIN_ALPHABET, RIPPLE_ALPHABET, b58encode, b58decode, b58encode_int, b58decode_int


class Base58(object):
    GMP: bytes
    BITCOIN: bytes
    FLICKR: bytes
    RIPPLE: bytes
    IPFS: bytes
    chrset: str

    def __init__(self, chrset: str = 'GMP'):
        self.BITCOIN = BITCOIN_ALPHABET
        self.RIPPLE = RIPPLE_ALPHABET
        self.GMP = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv'
        self.FLICKR = b'123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
        self.IPFS = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        self.chrset = chrset or 'GMP'

    def __getattr__(self, attribute_name):
        if attribute_name in 'characters':
            return self.__dict__[self.chrset]
        raise AttributeError(f"<{self!r}.{attribute_name!r}>")

    def encode(self, data: Union[str, bytes]) -> bytes:
        """
        :param data: Union[str, bytes]
        :return: bytes
        """
        return b58encode(data, self.characters)

    def decode(self, data: Union[str, bytes]) -> bytes:
        """
        :param data: Union[str, bytes]
        :return: bytes
        """
        return b58decode(data, self.characters)

    def encode_integer(self, data: int) -> bytes:
        """
        :param data: int
        :return: bytes
        """
        return b58encode_int(i=data, alphabet=self.characters)

    def decode_integer(self, data: Union[str, bytes]) -> int:
        """
        :param data: Union[str, bytes]
        :return: int
        """
        return b58decode_int(data, alphabet=self.characters)


class Soda(object):
    encoder: Base58

    def __init__(self, characters: str = None):
        self.encoder = Base58(characters if characters in Base58.__dict__['__annotations__'] else 'GMP')

    def encrypt(self, message, key):
        return self.encode(
            crypto_box_seal(
                strings.encode(dumps(message)),
                self.decode(key)
            )
        )

    def decrypt(self, decrypted, private_key, public_key):
        try:
            decrypt = crypto_box_seal_open(
                self.decode(decrypted),
                self.decode(public_key),
                self.decode(private_key)
            )
        except CryptError:
            decrypt = None
        return None if decrypt is None else loads(decrypt)

    def generate_private_key(self, key):
        sponge = shake()
        sponge.update(strings.encode(key))
        return self.encode(hex_decode(SecretKey(sponge.digest(crypto_box_SECRETKEYBYTES)).hex_sk()))

    def generate_public_key(self, key):
        return self.encode(hex_decode(SecretKey(self.decode(key)).hex_pk()))

    def short_hash(self, key):
        sponge = shake()
        sponge.update(strings.encode(key))
        return self.encode(sponge.digest(8))

    def encode(self, data) -> bytes:
        return self.encoder.encode(data)

    def decode(self, data) -> bytes:
        return self.encoder.decode(data)
