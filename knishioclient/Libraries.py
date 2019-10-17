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

from .Exception import *
from . import Client

__all__ = (
    'Message',
    'Metas',
    'StrOrNone',
    'Strings',
    'Crypto',
    'CheckMolecule',
)

Message = Union[List, Dict, None]
Metas = Union[List[Dict[str, Union[str, int, float]]], Dict[str, Union[str, int, float]]]
StrOrNone = Union[str, None]


class CheckMolecule(object):

    @classmethod
    def isotope_m(cls, molecule: 'Molecule') -> bool:
        """
        :param molecule: Molecule
        :return: bool
        """
        CheckMolecule.missing(molecule)

        for atom in CheckMolecule.isotope_filter('M', molecule.atoms):
            if len(atom.meta) < 1:
                raise MetaMissingException()

        return True

    @classmethod
    def isotope_v(cls, molecule: 'Molecule', sender: 'Wallet' = None) -> bool:
        """
        Verification of V-isotope molecules checks to make sure that:
        1. we're sending and receiving the same token
        2. we're only subtracting on the first atom

        :param molecule: Molecule
        :param sender: Wallet default None
        :return: bool
        :raises [MolecularHashMissingException, AtomsMissingException, TransferMismatchedException, TransferToSelfException, TransferUnbalancedException, TransferBalanceException, TransferRemainderException]:
        """
        CheckMolecule.missing(molecule)

        # No isotopes "V" unnecessary and verification
        if len(CheckMolecule.isotope_filter('V', molecule.atoms)) == 0:
            return True

        # Grabbing the first atom
        # Looping through each V-isotope atom
        amount, value, first_atom = 0, 0, molecule.atoms[0]

        for index, v_atom in enumerate(molecule.atoms):

            #  Not V? Next...
            if 'V' != v_atom.isotope:
                continue

            # Making sure we're in integer land
            value = Strings.number(v_atom.value)

            # Making sure all V atoms of the same token
            if v_atom.token != first_atom.token:
                raise TransferMismatchedException()

            # Checking non-primary atoms
            if index > 0:

                # Negative V atom in a non-primary position?
                if value < 0:
                    raise TransferMalformedException()

                # Cannot be sending and receiving from the same address
                if v_atom.walletAddress == first_atom.walletAddress:
                    raise TransferToSelfException()

            # Adding this Atom's value to the total sum
            amount += value

        # Does the total sum of all atoms equal the remainder atom's value? (all other atoms must add up to zero)
        if amount != value:
            raise TransferUnbalancedException()

        # If we're provided with a senderWallet argument, we can perform additional checks
        if sender is not None:
            remainder = sender.balance + Strings.number(first_atom.value)

            # Is there enough balance to send?
            if remainder < 0:
                raise TransferBalanceException()

            # Does the remainder match what should be there in the source wallet, if provided?
            if remainder != amount:
                raise TransferRemainderException()
        # No senderWallet, but have a remainder?
        elif amount != 0:
            raise TransferRemainderException()

        # Looks like we passed all the tests!
        return True

    @classmethod
    def index(cls, molecule: 'Molecule') -> bool:
        """
        :param molecule: Molecule
        :return: bool
        :raises [MolecularHashMissingException, AtomsMissingException, AtomIndexException]:
        """
        CheckMolecule.missing(molecule)

        if len([atom for atom in molecule.atoms if atom.index is None]) != 0:
            raise AtomIndexException()

        return True

    @classmethod
    def molecular_hash(cls, molecule: 'Molecule') -> bool:
        """
        Verifies if the hash of all the atoms matches the molecular hash to ensure content has not been messed with

        :param molecule: Molecule
        :return: bool
        :raises [MolecularHashMissingException, AtomsMissingException, MolecularHashMismatchException]:
        """

        CheckMolecule.missing(molecule)

        if molecule.molecularHash != Client.Atom.hash_atoms(molecule.atoms):
            raise MolecularHashMismatchException()

        return True

    @classmethod
    def ots(cls, molecule: 'Molecule') -> bool:
        """
        This section describes the function DecodeOtsFragments(Om, Hm), which is used to transform a collection
        of signature fragments Om and a molecular hash Hm into a single-use wallet address to be matched against
        the sender’s address.

        :param molecule: Molecule
        :return: bool
        :raises [MolecularHashMissingException, AtomsMissingException, SignatureMalformedException, SignatureMismatchException]:
        """

        CheckMolecule.missing(molecule)

        # Determine first atom
        first_atom, normalized_hash = molecule.atoms[0], CheckMolecule.normalized_hash(molecule.molecularHash)
        # Rebuilding OTS out of all the atoms
        ots, wallet_address = ''.join([atom.otsFragment for atom in molecule.atoms]), first_atom.walletAddress
        key_fragments = ''

        # Wrong size? Maybe it's compressed
        if 2048 != len(ots):
            # Attempt decompression
            ots = Strings.base64_to_hex(ots)
            # Still wrong? That's a failure
            if 2048 != len(ots):
                raise SignatureMalformedException()

        # Subdivide Kk into 16 segments of 256 bytes (128 characters) each
        for index, ots_chunk in enumerate(map(''.join, zip(*[iter(ots)] * 128))):
            working_chunk = ots_chunk

            for _ in range(8 + normalized_hash[index]):
                sponge = shake()
                sponge.update(Strings.encode(working_chunk))
                working_chunk = sponge.hexdigest(64)

            key_fragments = '%s%s' % (key_fragments, working_chunk)

        # Absorb the hashed Kk into the sponge to receive the digest Dk
        sponge = shake()
        sponge.update(Strings.encode(key_fragments))
        digest = sponge.hexdigest(1024)

        # Squeeze the sponge to retrieve a 128 byte (64 character) string that should match the sender’s
        # wallet address
        sponge = shake()
        sponge.update(Strings.encode(digest))
        address = sponge.hexdigest(32)

        if address != wallet_address:
            raise SignatureMismatchException()

        return True

    @classmethod
    def isotope_filter(cls, isotope: str, atoms: List) -> List:
        """
        :param isotope: str
        :param atoms: List
        :return: List
        """
        return [atom for atom in atoms if isotope == atom.isotope]

    @classmethod
    def normalized_hash(cls, hash0: str):
        """
        Convert Hm to numeric notation via EnumerateMolecule(Hm)

        :param hash0: str
        :return: List
        """
        return CheckMolecule.normalize(CheckMolecule.enumerate(hash0))

    @classmethod
    def enumerate(cls, hash0: str) -> List[int]:
        """
        This algorithm describes the function EnumerateMolecule(Hm), designed to accept a pseudo-hexadecimal string Hm,
        and output a collection of decimals representing each character.
        Molecular hash Hm is presented as a 128 byte (64-character) pseudo-hexadecimal string featuring numbers
        from 0 to 9 and characters from A to F - a total of 15 unique symbols.
        To ensure that Hm has an even number of symbols, convert it to Base 17 (adding G as a possible symbol).
        Map each symbol to integer values as follows:
        0   1    2   3   4   5   6   7   8  9  A   B   C   D   E   F   G
        -8  -7  -6  -5  -4  -3  -2  -1  0   1   2   3   4   5   6   7   8

        :param hash0: str
        :return: List[int]
        """
        mapped = {
            '0': -8, '1': -7, '2': -6, '3': -5, '4': -4, '5': -3, '6': -2, '7': -1,
            '8': 0, '9': 1, 'a': 2, 'b': 3, 'c': 4, 'd': 5, 'e': 6, 'f': 7, 'g': 8,
        }
        return [mapped[symbol.lower()] for symbol in hash0 if mapped.get(symbol.lower(), None) is not None]

    @classmethod
    def normalize(cls, mapped_hash_array: List[int]) -> List[int]:
        """
        Normalize Hm to ensure that the total sum of all symbols is exactly zero. This ensures that exactly 50% of
        the WOTS+ key is leaked with each usage, ensuring predictable key safety:
        The sum of each symbol within Hm shall be presented by m
        While m0 iterate across that set’s integers as Im:
        If m0 and Im>-8 , let Im=Im-1
        If m<0 and Im<8 , let Im=Im+1
        If m=0, stop the iteration

        :param mapped_hash_array: List[int]
        :return: List[int]
        """
        hash_array = mapped_hash_array.copy()
        total = sum(hash_array)
        total_condition = total < 0

        while total < 0 or total > 0:
            for key, value in enumerate(hash_array):
                condition = value < 8 if total_condition else value > -8

                if condition:
                    if total_condition:
                        hash_array[key] += 1
                        total += 1
                    else:
                        hash_array[key] -= 1
                        total -= 1
                    if 0 == total:
                        break

        return hash_array

    @classmethod
    def missing(cls, molecule: 'Molecule') -> None:
        """
        :param molecule: Molecule
        """
        # No molecular hash?
        if molecule.molecularHash is None:
            raise MolecularHashMissingException()

        # Do we even have atoms?
        if len(molecule.atoms) < 1:
            raise AtomsMissingException()


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
    def hex_to_base64(cls, string: str) -> str:
        """
        Compresses a given string for web sharing

        :param string: str
        :return: str
        """
        return Strings.decode(base64_encode(hex_decode(string)))

    @classmethod
    def base64_to_hex(cls, string: str) -> str:
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
