# -*- coding: utf-8 -*-

import time
import logging
import math
import secrets

from typing import List, Any
import numpy as np
from libnacl.encode import hex_decode, hex_encode, base64_encode, base64_decode


def chunk_substr(string: str, size: int) -> List[str]:
    """
    Chunks a string into array segments of equal size

    :param string: str
    :param size: int
    :return: List[str]
    """
    return [string[o:size + o] for o in
            [size * i for i in range(0, math.ceil(len(string) / size))]] if size > 0 else []


def random_string(length: int = 256, alphabet: str = 'abcdef0123456789') -> str:
    """
    Generate a random string from a given character set of a given length

    :param length: int
    :param alphabet: str default 'abcdef0123456789'
    :return: str
    """
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def charset_base_convert(src: str, from_base: int, to_base: int, src_symbol_table: str = None,
                         dest_symbol_table: str = None) -> bool | str | int:
    """
    Convert charset between bases and alphabets

    :param src: str
    :param from_base: int
    :param to_base: int
    :param src_symbol_table: str default None
    :param dest_symbol_table: str default None
    :return: bool | str | int
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

    value, big_integer_zero, big_integer_to_base, big_integer_from_base = (np.array([0], dtype='object'),
                                                                           np.array([0], dtype='object'),
                                                                           np.array([to_base], dtype='object'),
                                                                           np.array([from_base], dtype='object'))
    for symbol in src:
        value = np.add(np.multiply(value, big_integer_from_base), np.array([src_symbol_table.index(symbol)], dtype='object'))

    if value[0] <= 0:
        return 0

    condition, target = True, ''

    while condition:
        idx = np.mod(value, big_integer_to_base)
        target = '%s%s' % (dest_symbol_table[idx[0]], target)
        value = np.floor_divide(value, big_integer_to_base)
        condition = not np.equal(value, big_integer_zero)[0]

    return target


def current_time_millis() -> str:
    """
    :return: str
    """
    # Support deterministic testing with KNISHIO_FIXED_TIMESTAMP environment variable
    import os
    fixed_timestamp = os.getenv('KNISHIO_FIXED_TIMESTAMP')
    if fixed_timestamp:
        return str(int(fixed_timestamp) * 1000)  # Convert from seconds to milliseconds
    
    return str(sum(map(lambda x: int(x), str(time.time() * 1000).split('.'))))


def hex_to_base64(string: str) -> str:
    """
    Compresses a given string for web sharing

    :param string: str
    :return: str
    """
    return decode(base64_encode(hex_decode(string)))


def base64_to_hex(string: str) -> str:
    """
    Decompresses a compressed string

    :param string: str
    :return: str
    """
    return decode(hex_encode(base64_decode(string)))


def encode(value: Any, code: str = 'utf-8') -> bytes:
    """
    :param value: Any
    :param code: str default 'utf-8'
    :return: bytes
    """
    return value.encode(code) if isinstance(value, str) else value


def decode(value: Any, code: str = 'utf-8') -> str:
    """
    :param value: Any
    :param code: str
    :return:
    """
    return value.decode(code) if isinstance(value, bytes) else value


def number(value: float | int | str) -> float:
    """
    Convert string to number

    :param value: float | int | str
    :return: float
    """
    # Handle None, empty strings, and other invalid values gracefully
    if value is None or value == "" or value == "null":
        return 0.0
    
    var = str(value)
    try:
        return float(var)
    except (ValueError, TypeError):
        return 0.0