# -*- coding: utf-8 -*-

import time
import logging
import math
import random
import json
import ctypes

from typing import Union, List, Dict, Any
from numpy import array, multiply, add, mod, floor_divide
from hashlib import shake_256 as shake
from libnacl.encode import hex_decode, hex_encode, base64_encode, base64_decode
from libnacl.public import SecretKey, Box
from libnacl import (crypto_box_SECRETKEYBYTES, crypto_scalarmult_curve25519_BYTES, crypto_box_PUBLICKEYBYTES,
                     crypto_box_NONCEBYTES, nacl, CryptError)

__all__ = (
    'Message',
    'Metas',
    'StrOrNone',
    'Strings',
    'Crypto',
)

Message = Union[List, Dict, None]
Metas = Union[List[Dict[str, Union[str, int, float]]], Dict[str, Union[str, int, float]]]
StrOrNone = Union[str, None]


class Strings(object):
    @classmethod
    def chunk_substr(cls, string: str, size: int) -> List[str]:
        """
        Chunks a string into array segments of equal size

        :param string: str
        :param size: int
        :return: List[str]
        """
        return [string[o:size + o] for o in
                [size * i for i in range(0, math.ceil(len(string) / size))]] if size > 0 else []

    @classmethod
    def random_string(cls, length: int = 256, alphabet: str = 'abcdef0123456789') -> str:
        """
        Generate a random string from a given character set of a given length

        :param length: int
        :param alphabet: str default 'abcdef0123456789'
        :return: str
        """
        return ''.join(random.choice(alphabet) for _ in range(length))

    @classmethod
    def charset_base_convert(cls, src: str, from_base: int, to_base: int, src_symbol_table: str = None,
                             dest_symbol_table: str = None) -> Union[bool, str, int]:
        """
        Convert charset between bases and alphabets

        :param src: str
        :param from_base: int
        :param to_base: int
        :param src_symbol_table: str default None
        :param dest_symbol_table: str default None
        :return: Union[bool, str, int]
        """

        base_symbols = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz~`!@#$%^&*()-_=+[{]}\\|;:\'",<.>/?¿¡'
        src_symbol_table = src_symbol_table or base_symbols
        dest_symbol_table = dest_symbol_table or src_symbol_table

        if from_base > len(src_symbol_table) or to_base > len(dest_symbol_table):
            logging.getLogger("charset_base_convert").error(
                'Can\'t convert %s to base %s greater than symbol table length. src-table: %s dest-table: %s' % (
                    src, to_base, len(src_symbol_table), len(dest_symbol_table)
                )
            )

        value, big_integer_zero, big_integer_to_base, big_integer_from_base = (array([0], dtype='object'),
                                                                               array([0], dtype='object'),
                                                                               array([to_base], dtype='object'),
                                                                               array([from_base], dtype='object'))
        for symbol in src:
            value = add(multiply(value, big_integer_from_base), array([src_symbol_table.index(symbol)], dtype='object'))

        if value[0] == 0:
            return 0

        condition, target = True, ''

        while condition:
            idx = mod(value, big_integer_to_base)
            target = '%s%s' % (dest_symbol_table[idx[0]], target)
            value = floor_divide(value, big_integer_to_base)
            condition = value[0] != 0

        return target

    @classmethod
    def current_time_millis(cls) -> str:
        """
        :return: str
        """
        return str(sum(map(lambda x: int(x), str(time.time() * 1000).split('.'))))

    @classmethod
    def compress(cls, string: str) -> str:
        """
        Compresses a given string for web sharing

        :param string: str
        :return: str
        """
        return Strings.decode(base64_encode(hex_decode(string)))

    @classmethod
    def decompress(cls, string: str) -> str:
        """
        Decompresses a compressed string

        :param string: str
        :return: str
        """
        return Strings.decode(hex_encode(base64_decode(string)))

    @classmethod
    def encode(cls, value: Any, code: str = 'utf-8') -> bytes:
        """
        :param value: Any
        :param code: str default 'utf-8'
        :return: bytes
        """
        return value.encode(code) if isinstance(value, str) else value

    @classmethod
    def decode(cls, value: Any, code: str = 'utf-8') -> str:
        """
        :param value: Any
        :param code: str
        :return:
        """
        return value.decode(code) if isinstance(value, bytes) else value

    @classmethod
    def number(cls, value: Union[float, int, str]) -> float:
        """
        Convert string to number

        :param value: Union[float, int, str]
        :return: Union[float, int]
        """
        var = str(value)
        try:
            return float(var)
        except ValueError:
            return 0.0


class Crypto(object):
    @classmethod
    def generate_bundle_hash(cls, secret: str) -> str:
        """
        Hashes the user secret to produce a bundle hash

        :param secret: str
        :return: str
        """
        sponge = shake()
        sponge.update(Strings.encode(secret))

        return sponge.hexdigest(32)

    @classmethod
    def generate_enc_private_key(cls, key: str) -> str:
        """
        Derives a private key for encrypting data with the given key

        :param key: str
        :return: str
        """
        sponge = shake()
        sponge.update(Strings.encode(key))
        return sponge.hexdigest(crypto_box_SECRETKEYBYTES)

    @classmethod
    def generate_enc_public_key(cls, key: str) -> str:
        """
        Derives a public key for encrypting data for this wallet's consumption

        :param key: str
        :return: str
        """

        sk = hex_decode(key)

        if len(sk) != crypto_box_SECRETKEYBYTES:
            raise ValueError('Invalid secret key')

        return Strings.decode(SecretKey(sk).hex_pk())

    @classmethod
    def generate_enc_shared_key(cls, private_key: str, other_public_key: str) -> str:
        """
        Creates a shared key by combining this wallet's private key and another wallet's public key

        :param private_key: str
        :param other_public_key: str
        :return: str
        """

        pk = hex_decode(other_public_key)
        sk = hex_decode(private_key)
        shk = ctypes.create_string_buffer(crypto_scalarmult_curve25519_BYTES)

        if len(pk) != crypto_box_PUBLICKEYBYTES:
            raise ValueError('Invalid public key')

        if len(sk) != crypto_box_SECRETKEYBYTES:
            raise ValueError('Invalid secret key')

        if nacl.crypto_scalarmult_curve25519(shk, sk, pk) == -1:
            raise CryptError('Failed to compute scalar product')

        return Strings.decode(hex_encode(shk))

    @classmethod
    def encrypt_message(cls, message: Message, recipient_private_key: str) -> str:
        """
        Encrypts the given message or data with the recipient's private key

        :param message: List or Dict
        :param recipient_private_key: str
        :return: str
        """

        if message is None:
            return ''

        public_key = Crypto.generate_enc_public_key(recipient_private_key)
        shared = Crypto.generate_enc_shared_key(recipient_private_key, public_key)
        nonce, noise = Box(hex_decode(shared), hex_decode(public_key)).encrypt(
            msg=Strings.encode(json.dumps(message)),
            pack_nonce=False
        )

        return ''.join([Strings.decode(hex_encode(nonce)), shared, Strings.decode(hex_encode(noise))])

    @classmethod
    def decrypt_message(cls, message: str, recipient_public_key: str) -> Message:
        """
        Uses the given private key to decrypt an encrypted message

        :param message: str
        :param recipient_public_key: str
        :return: List or Dict or None
        """
        cipher = hex_decode(message)
        crypto_box_len = crypto_box_NONCEBYTES + crypto_box_SECRETKEYBYTES

        if len(cipher) > crypto_box_len:
            try:
                payload = Box(cipher[crypto_box_NONCEBYTES:crypto_box_len], hex_decode(recipient_public_key)).decrypt(
                    cipher[crypto_box_len:],
                    cipher[:crypto_box_NONCEBYTES]
                )
            except CryptError:
                return None

            return json.loads(payload)

        return None
