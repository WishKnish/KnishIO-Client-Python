# -*- coding: utf-8 -*-
from json import dumps, loads
from hashlib import shake_256 as shake
from libnacl.public import SecretKey
from libnacl.encode import hex_decode
from libnacl import (crypto_box_seal, crypto_box_seal_open, crypto_box_SECRETKEYBYTES, CryptError)
from . import strings
from .Base58 import Base58


class Soda(object):
    """Classical NaCl public-key crypto utility (libsodium ``crypto_box_seal`` / ``crypto_box_seal_open``).

    This is the **classical, non-post-quantum** encryption lineage — a general-purpose sealed-box
    utility, NOT the canonical cross-SDK message envelope. The canonical **post-quantum ML-KEM768**
    envelope (``{cipherText, encryptedMessage}`` — the form the cross-platform vectors assert) is
    ``Wallet.encrypt_message`` / ``Wallet.decrypt_message`` (see ``knishioclient/models/Wallet.py``).
    """

    encoder: Base58

    def __init__(self, characters: str = None):
        self.encoder = Base58(characters if characters in Base58.__dict__['__annotations__'] else 'GMP')

    def encrypt(self, message, key):
        """Classical NaCl ``crypto_box_seal`` encryption (non-PQ). For the canonical
        post-quantum ML-KEM768 envelope, use ``Wallet.encrypt_message``."""
        return self.encode(
            crypto_box_seal(
                strings.encode(dumps(message)),
                self.decode(key)
            )
        )

    def decrypt(self, decrypted, private_key, public_key):
        """Classical NaCl ``crypto_box_seal_open`` decryption (non-PQ). For the canonical
        post-quantum ML-KEM768 envelope, use ``Wallet.decrypt_message``."""
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