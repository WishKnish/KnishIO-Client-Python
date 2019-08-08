# -*- coding: utf-8 -*-
from hashlib import shake_256 as shake
from json import JSONDecoder
from numpy import array, add
from knishioclient.Libraries import (current_time_millis, encode, charset_base_convert, number, chunk_substr,
                                     random_string, compress, decompress, Coder)
from knishioclient.Typing import Union, List, Metas, Dict, StrOrNone


class _Base(object):
    def __str__(self) -> str:
        """
        :return: str
        """
        return self.json()

    def __repr__(self) -> str:
        """
        :return: str
        """
        return self.__str__()

    def json(self) -> str:
        """
        :return: str
        """
        return Coder().encode(self)


class Wallet(object):
    """class Wallet"""

    position: str
    token: str
    key: str
    address: str
    balance: Union[int, float]
    molecules: List
    bundle: str

    def __init__(self, secret: str, token: str = 'USER', position: str = None, salt_length: int = 64) -> None:
        self.position = position or random_string(salt_length)
        self.token = token
        self.key = Wallet.generate_key(secret, token, self.position)
        self.address = Wallet.generate_address(self.key)
        self.balance = 0
        self.molecules = []
        self.bundle = Wallet.generate_bundle_hash(secret)

    @classmethod
    def generate_bundle_hash(cls, secret: str) -> str:
        """
        :param secret: str
        :return: str
        """
        sponge = shake()
        sponge.update(encode(secret))

        return sponge.hexdigest(32)

    @classmethod
    def generate_address(cls, key: str) -> str:
        """
        :param key: str
        :return: str
        """
        digest_sponge = shake()

        for fragment in chunk_substr(key, 128):
            working_fragment = fragment

            for _ in range(16):
                working_sponge = shake()
                working_sponge.update(encode(working_fragment))
                working_fragment = working_sponge.hexdigest(64)

            digest_sponge.update(encode(working_fragment))

        sponge = shake()
        sponge.update(encode(digest_sponge.hexdigest(1024)))

        return sponge.hexdigest(32)

    @classmethod
    def generate_key(cls, secret: str, token: str, position: str) -> str:
        """
        :param secret: str
        :param token: str
        :param position: str
        :return: str
        """
        # Converting secret to bigInt
        # Adding new position to the user secret to produce the indexed key
        indexed_key = '%x' % add(array([int(secret, 16)], dtype='object'),
                                 array([int(position, 16)], dtype='object'))[0]
        # Hashing the indexed key to produce the intermediate key
        intermediate_key_sponge = shake()
        intermediate_key_sponge.update(indexed_key.encode('utf-8'))

        if token not in ['']:
            intermediate_key_sponge.update(token.encode('utf-8'))

        # Hashing the intermediate key to produce the private key
        sponge = shake()
        sponge.update(encode(intermediate_key_sponge.hexdigest(1024)))

        return sponge.hexdigest(1024)


class Atom(_Base):
    """class Atom"""

    position: str
    walletAddress: str
    isotope: str
    token: StrOrNone
    value: StrOrNone
    metaType: StrOrNone
    metaId: StrOrNone
    meta: List[Dict]
    otsFragment: StrOrNone
    createdAt: str

    def __init__(self, position: str, wallet_address: str, isotope: str, token: str = None,
                 value: Union[str, int, float] = None, meta_type: str = None, meta_id: str = None,
                 meta: Metas = None, ots_fragment: str = None) -> None:
        self.position = position
        self.walletAddress = wallet_address
        self.isotope = isotope
        self.token = token
        self.value = str(value) if not isinstance(value, str) and value is not None else value

        self.metaType = meta_type
        self.metaId = meta_id
        self.meta = Atom.normalize_meta(meta) if meta is not None else []

        self.otsFragment = ots_fragment
        self.createdAt = current_time_millis()

    @classmethod
    def json_to_object(cls, string: str) -> 'Atom':
        """
        :param string: str
        :return: Atom
        """
        target, stream = Atom('', '', ''), JSONDecoder().decode(string)

        for prop in target.__dict__.keys():
            if prop in stream:
                setattr(target, prop, stream[prop])

        return target

    @classmethod
    def hash_atoms(cls, atoms: List['Atom'], output: str = 'base17') -> Union[str, None, List]:
        """
        :param atoms: List["Atom"]
        :param output: str default 'base17'
        :return: Union[str, None, List]
        """
        atom_list = sorted([*atoms], key=lambda item: item.position)
        molecular_sponge = shake()
        number_of_atoms = encode(str(len(atom_list)))

        for atom in atom_list:
            molecular_sponge.update(number_of_atoms)

            for prop, value in atom.__dict__.items():
                if prop in ['otsFragment']:
                    continue
                elif prop in ['meta']:
                    atom.meta = Atom.normalize_meta(value)
                    for meta in atom.meta:
                        molecular_sponge.update(encode(meta['key']))
                        molecular_sponge.update(encode(meta['value']))
                elif prop in ['position', 'walletAddress', 'isotope'] or value is not None:
                    molecular_sponge.update(encode(value))

        target = None

        if output in ['hex']:
            target = molecular_sponge.hexdigest(32)
        elif output in ['array']:
            target = list(molecular_sponge.hexdigest(32))
        elif output in ['base17']:
            target = charset_base_convert(
                molecular_sponge.hexdigest(32), 16, 17, '0123456789abcdef', '0123456789abcdefg'
            )
            target = target.rjust(64, '0') if isinstance(target, str) else None

        return target

    @classmethod
    def normalize_meta(cls, meta: Union[List, Dict]) -> List[Dict]:
        """
        :param meta: Union[List, Dict]
        :return: List[Dict]
        """
        if isinstance(meta, dict):
            return [{"key": key, "value": value} for key, value in meta.items()]
        return meta


class Molecule(_Base):
    """class Molecule"""

    molecularHash: StrOrNone
    cellSlug: StrOrNone
    bundle: StrOrNone
    status: StrOrNone
    createdAt: str
    atoms: List[Atom]

    def __init__(self, cell_slug: str = None) -> None:
        self.molecularHash = None
        self.cellSlug = cell_slug
        self.bundle = None
        self.status = None
        self.createdAt = current_time_millis()
        self.atoms = []

    @classmethod
    def json_to_object(cls, string: str) -> 'Molecule':
        """
        :param string: str
        :return: Molecule
        """
        target, stream = Molecule(), JSONDecoder().decode(string)
        for prop in target.__dict__.keys():
            if prop in stream:
                if prop in ['atoms']:
                    if not isinstance(stream[prop], list):
                        raise TypeError('The atoms property must contain a list')
                    atoms = []
                    for item in stream[prop]:
                        atom = Atom.json_to_object(Coder().encode(item))
                        for key in ['position', 'walletAddress', 'isotope']:
                            if getattr(atom, key) in ['']:
                                raise TypeError('the %s property must not be empty' % key)
                        atoms.append(atom)
                    setattr(target, prop, atoms)
                    continue
                setattr(target, prop, stream[prop])
        return target

    def init_value(self, source: Wallet, recipient: Wallet, remainder: Wallet, value: Union[int, float]) -> List[Atom]:
        """
        Initialize a V-type molecule to transfer value from one wallet to another, with a third,
        regenerated wallet receiving the remainder

        :param source: Wallet
        :param recipient: Wallet
        :param remainder: Wallet
        :param value: Union[int, float]
        :return: List[Atom]
        """
        self.molecularHash = None
        position = int(source.position, 16)

        self.atoms.append(
            Atom(
                '%x' % position,
                source.address,
                'V',
                source.token,
                -value,
                'remainderWallet',
                remainder.address,
                {'remainderPosition': remainder.position},
                None
            )
        )

        position += 1

        self.atoms.append(
            Atom(
                '%x' % position,
                recipient.address,
                'V',
                source.token,
                value,
                'walletBundle',
                recipient.bundle,
                None,
                None
            )
        )

        return self.atoms

    def init_token_creation(self, source: Wallet, recipient: Wallet, amount: Union[int, float],
                            token_meta: Union[List, Dict]) -> List[Atom]:
        """
        Initialize a C-type molecule to issue a new type of token

        :param source: Wallet
        :param recipient: Wallet
        :param amount: Union[int, float]
        :param token_meta: Union[List, Dict]
        :return: List[Atom]
        """
        self.molecularHash = None
        metas = Atom.normalize_meta(token_meta)

        for key in ['walletAddress', 'walletPosition']:
            if 0 == len([meta for meta in metas if 'key' in meta and key == meta['key']]):
                metas.append({'key': key, 'value': getattr(recipient, key[6:].lower())})

        self.atoms.append(
            Atom(
                source.position,
                source.address,
                'C',
                source.token,
                amount,
                'token',
                recipient.token,
                metas,
                None
            )
        )

        return self.atoms

    def init_meta(self, wallet: Wallet, meta: Union[List, Dict], meta_type: str,
                  meta_id: Union[str, int]) -> List[Atom]:
        """
        Initialize an M-type molecule with the given data

        :param wallet: Wallet
        :param meta: Union[List, Dict]
        :param meta_type: str
        :param meta_id: Union[str, int]
        :return: List[Atom]
        """
        self.molecularHash = None
        self.atoms.append(
            Atom(
                wallet.position,
                wallet.address,
                'M',
                wallet.token,
                None,
                meta_type,
                meta_id,
                meta,
                None
            )
        )

        return self.atoms

    def sign(self, secret: str, anonymous: bool = False) -> StrOrNone:
        """
        Creates a one-time signature for a molecule and breaks it up across multiple atoms within that
        molecule. Resulting 4096 byte (2048 character) string is the one-time signature.

        :param secret: str
        :param anonymous: bool default False
        :return: StrOrNone
        :raise TypeError: The molecule does not contain atoms
        """
        if len(self.atoms) == 0 or len([atom for atom in self.atoms if not isinstance(atom, Atom)]) != 0:
            raise TypeError('The molecule does not contain atoms')

        if not anonymous:
            self.bundle = Wallet.generate_bundle_hash(secret)

        self.molecularHash = Atom.hash_atoms(self.atoms)
        first_atom, normalized_hash, signature_fragments = (self.atoms[0],
                                                            Molecule.normalize(Molecule.enumerate(self.molecularHash)),
                                                            '')
        for idx, chunk in enumerate(
                chunk_substr(Wallet.generate_key(secret, first_atom.token, first_atom.position), 128)):

            working_chunk = chunk

            for _ in range(8 - normalized_hash[idx]):
                sponge = shake()
                sponge.update(encode(working_chunk))
                working_chunk = sponge.hexdigest(64)

            signature_fragments = '%s%s' % (signature_fragments, working_chunk)

        # Compressing the OTS
        signature_fragments = compress(signature_fragments)
        last_position = None

        for chunk_count, signature in enumerate(chunk_substr(signature_fragments, round(
                len(signature_fragments) / len(self.atoms)))):
            atom = self.atoms[chunk_count]
            atom.otsFragment = signature
            last_position = atom.position

        return last_position

    def clear(self) -> 'Molecule':
        """
        Clears the instance of the data, leads the instance to a state equivalent to that after Molecule()

        :return: Molecule
        """

        self.__init__(self.cellSlug)
        return self

    @classmethod
    def verify_token_isotope_v(cls, molecule: 'Molecule') -> bool:
        """

        :param molecule: Molecule
        :return: bool
        """
        if molecule.molecularHash is not None and 0 < len(molecule.atoms):
            v_atoms = [atom for atom in molecule.atoms if 'V' == atom.isotope]
            for token in set(item.token for item in v_atoms):
                total = sum([number(atom.value) for atom in v_atoms if atom.token == token])
                if 0 != total:
                    return False
            return True
        return False

    @classmethod
    def verify(cls, molecule: 'Molecule') -> bool:
        """

        :param molecule: Molecule
        :return: bool
        """
        return Molecule.verify_molecular_hash(molecule) and Molecule.verify_ots(
            molecule) and Molecule.verify_token_isotope_v(molecule)

    @classmethod
    def verify_molecular_hash(cls, molecule: 'Molecule') -> bool:
        """
        Verifies if the hash of all the atoms matches the molecular hash to ensure content has not been messed with

        :param molecule: Molecule
        :return: bool
        """
        return molecule.molecularHash is not None and 0 < len(
            molecule.atoms) and molecule.molecularHash == Atom.hash_atoms(molecule.atoms)

    @classmethod
    def verify_ots(cls, molecule: 'Molecule') -> bool:
        """
        This section describes the function DecodeOtsFragments(Om, Hm), which is used to transform a collection
        of signature fragments Om and a molecular hash Hm into a single-use wallet address to be matched against
        the sender’s address.

        :param molecule: Molecule
        :return: bool
        """
        if molecule.molecularHash is not None and 0 < len(molecule.atoms):
            atoms = sorted([*molecule.atoms], key=lambda item: item.position)
            # Determine first atom
            first_atom, normalized_hash = atoms[0], Molecule.normalize(Molecule.enumerate(molecule.molecularHash))
            # Rebuilding OTS out of all the atoms
            ots, wallet_address = ''.join([atom.otsFragment for atom in atoms]), first_atom.walletAddress
            key_fragments = ''

            # Wrong size? Maybe it's compressed
            if 2048 != len(ots):
                # Attempt decompression
                ots = decompress(ots)
                # Still wrong? That's a failure
                if 2048 != len(ots):
                    return False

            # Subdivide Kk into 16 segments of 256 bytes (128 characters) each
            for index, ots_chunk in enumerate(map(''.join, zip(*[iter(ots)] * 128))):
                working_chunk = ots_chunk
                for _ in range(8 + normalized_hash[index]):
                    sponge = shake()
                    sponge.update(encode(working_chunk))
                    working_chunk = sponge.hexdigest(64)
                key_fragments = '%s%s' % (key_fragments, working_chunk)

            # Absorb the hashed Kk into the sponge to receive the digest Dk
            sponge = shake()
            sponge.update(encode(key_fragments))
            digest = sponge.hexdigest(1024)

            # Squeeze the sponge to retrieve a 128 byte (64 character) string that should match the sender’s
            # wallet address
            sponge = shake()
            sponge.update(encode(digest))
            address = sponge.hexdigest(32)

            return address == wallet_address

        return False

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
