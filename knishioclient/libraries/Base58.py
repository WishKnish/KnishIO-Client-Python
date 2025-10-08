# -*- coding: utf-8 -*-
from typing import Union
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