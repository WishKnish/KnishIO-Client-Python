# -*- coding: utf-8 -*-

from typing import List
from hashlib import shake_256 as shake
from ..libraries import strings, check
from .base import Base
from .Atom import Atom


class MoleculeStructure(Base):
    """class MoleculeStructure"""

    molecularHash: str | bytes | None
    cellSlug: str | bytes | None
    counterparty: str | bytes | None
    bundle: str | bytes | None
    status: str | bytes | None
    local: bool
    createdAt: str
    atoms: List[Atom]

    cellSlugOrigin: str | bytes | None

    def __init__(self, cell_slug: str | bytes | None = None):
        """
        :param cell_slug: str
        """
        self.local = False
        self.cellSlugOrigin = cell_slug
        self.cellSlug = cell_slug

    def __getattr__(self, key):
        if key in 'cellSlugDelimiter':
            return '.'
        raise AttributeError(f"<{self!r}.{key!r}>")

    def with_counterparty(self, counterparty: str = None):
        """
        :param counterparty: str
        :return: self
        """
        self.counterparty = counterparty
        return self

    def cell_slug_base(self):
        return False if self.cellSlug is None else self.cellSlug.split(MoleculeStructure.cellSlugDelimiter)

    def check(self, sender_wallet=None) -> bool:
        return check.verify(self, sender_wallet)

    def normalized_hash(self):
        return self.normalize(self.enumerate(self.molecularHash))

    def signature_fragments(self, key, encode: bool = True):

        key_fragments = ''
        normalized_hash = self.normalized_hash()

        # Subdivide Kk into 16 segments of 128 characters each
        for index, ots_chunk in enumerate(map(''.join, zip(*[iter(key)] * 128))):
            working_chunk = ots_chunk

            for _ in range(8 + normalized_hash[index] * (-1 if encode else 1)):
                sponge = shake()
                sponge.update(strings.encode(working_chunk))
                working_chunk = sponge.hexdigest(64)

            key_fragments = '%s%s' % (key_fragments, working_chunk)
        return key_fragments

    def set_property(self, attribute: str, value) -> None:
        feature = {'bundleHash': 'bundle', }.get(attribute, attribute)
        setattr(self, feature, value)

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
        While m0 iterate across that set's integers as Im:
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
    def to_object(cls, data):
        obj = cls.array_to_object(data)

        for key, atom_data in enumerate(obj.atoms):
            atom = Atom(atom_data['position'], atom_data['walletAddress'], atom_data['isotope'])
            obj.atoms[key] = Atom.array_to_object(atom_data, atom)

        obj.atoms = Atom.sort_atoms(obj.atoms)

        return obj