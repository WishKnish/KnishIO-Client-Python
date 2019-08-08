# -*- coding: utf-8 -*-
import time
import logging
import math
import random
import json
from numpy import array, multiply, add, mod, floor_divide
from lzstring import LZString
from knishioclient.Typing import Union, Any, List
from knishioclient import Client


def current_time_millis() -> str:
    """
    :return: str
    """
    return str(sum(map(lambda x: int(x), str(time.time() * 1000).split('.'))))


def charset_base_convert(src: str, from_base: int, to_base: int, src_symbol_table: str = None,
                         dest_symbol_table: str = None) -> Union[bool, str, int]:
    """
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


def chunk_substr(string: str, size: int) -> List[str]:
    """
    :param string: str
    :param size: int
    :return: List[str]
    """
    return [string[o:size + o] for o in [size*i for i in range(0, math.ceil(len(string) / size))]] if size > 0 else []


def random_string(length: int = 256, alphabet: str = 'abcdef0123456789') -> str:
    """
    Generate a random string from a given character set of a given length

    :param length: int
    :param alphabet: str default 'abcdef0123456789'
    :return: str
    """
    return ''.join(random.choice(alphabet) for _ in range(length))


def number(value: Union[float, int, str]) -> float:
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


def encode(value: Any, code: str = 'utf-8') -> bytes:
    """
    :param value: Any
    :param code: str default 'utf-8'
    :return: bytes
    """
    return str(value).encode(code)


def compress(string: str) -> str:
    """
    Compresses a given string for web sharing

    :param string: str
    :return: str
    """
    return LZString.compressToBase64(string)


def decompress(string: str) -> str:
    """
    Decompresses a compressed string

    :param string: str
    :return: str
    """
    return LZString.decompressFromBase64(string)


class Coder(json.JSONEncoder):
    def default(self, value: Any) -> Any:
        """
        :param value: Any
        :return: Any
        """
        if isinstance(value, Client.Atom):
            return {
                'position': value.position,
                'walletAddress': value.walletAddress,
                'isotope': value.isotope,
                'token': value.token,
                'value': value.value,
                'metaType': value.metaType,
                'metaId': value.metaId,
                'meta': value.meta,
                'otsFragment': value.otsFragment,
                'createdAt': value.createdAt,
            }

        if isinstance(value, Client.Molecule):
            return {
                'molecularHash': value.molecularHash,
                'cellSlug': value.cellSlug,
                'bundle': value.bundle,
                'status': value.status,
                'createdAt': value.createdAt,
                'atoms': value.atoms
            }

        return super().default(self, value)
