# -*- coding: utf-8 -*-
from json import dumps, loads
from hashlib import shake_256 as shake
from libnacl.public import SecretKey
from libnacl.encode import hex_decode
from libnacl import (crypto_box_seal, crypto_box_seal_open, crypto_box_SECRETKEYBYTES, CryptError)
from . import strings
from .Base58 import Base58


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