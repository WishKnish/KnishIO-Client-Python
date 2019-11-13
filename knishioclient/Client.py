# -*- coding: utf-8 -*-

import math
from hashlib import shake_256 as shake
from json import JSONDecoder, JSONEncoder
from numpy import array, add
from typing import Union, List, Dict, Any

from .Exception import *
from .Libraries import *

__all__ = (
    'Meta',
    'Atom',
    'Wallet',
    'Molecule',
)


class Coder(JSONEncoder):
    """ class Coder """
    def default(self, value: Any) -> Any:
        """
        :param value: Any
        :return: Any
        """
        if isinstance(value, Atom):
            return {
                'position': value.position,
                'walletAddress': value.walletAddress,
                'isotope': value.isotope,
                'token': value.token,
                'value': value.value,
                'metaType': value.metaType,
                'metaId': value.metaId,
                'meta': value.meta,
                'index': value.index,
                'otsFragment': value.otsFragment,
                'createdAt': value.createdAt,
            }

        if isinstance(value, Molecule):
            return {
                'molecularHash': value.molecularHash,
                'cellSlug': value.cellSlug,
                'bundle': value.bundle,
                'status': value.status,
                'createdAt': value.createdAt,
                'atoms': value.atoms,
            }

        if isinstance(value, Meta):
            return {
                'modelType': value.modelType,
                'modelId': value.modelId,
                'meta': value.meta,
                'snapshotMolecule': value.snapshotMolecule,
                'createdAt': value.createdAt,
            }

        return super().default(self, value)


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


class Meta(_Base):
    """class Meta"""

    modelType: str
    modelId: str
    meta: Metas
    snapshotMolecule: str
    createdAt: str

    def __int__(self, model_type: str, model_id: str, meta: Metas, snapshot_molecule: str = None) -> None:
        """
        :param model_type: str
        :param model_id: str
        :param meta: Metas
        :param snapshot_molecule: str default None
        """
        self.modelType = model_type
        self.modelId = model_id
        self.meta = meta
        self.snapshotMolecule = snapshot_molecule
        self.createdAt = Strings.current_time_millis()

    @classmethod
    def normalize_meta(cls, metas: Union[List, Dict]) -> List[Dict]:
        """
        :param metas: Union[List, Dict]
        :return: List[Dict]
        """
        if isinstance(metas, dict):
            return [{"key": key, "value": value} for key, value in metas.items()]
        return metas

    @classmethod
    def aggregate_meta(cls, metas: List[Dict]) -> Dict:
        """
        :param metas: List[Dict]
        :return: Dict
        """
        aggregate = {}

        if len(metas) > 0:
            for meta in metas:
                aggregate.update(meta)

        return aggregate


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
    index: int
    otsFragment: StrOrNone
    createdAt: str

    def __init__(self, position: str, wallet_address: str, isotope: str, token: str = None,
                 value: Union[str, int, float] = None, meta_type: str = None, meta_id: str = None,
                 meta: Metas = None, ots_fragment: str = None, index: int = None) -> None:
        self.position = position
        self.walletAddress = wallet_address
        self.isotope = isotope
        self.token = token
        self.value = str(value) if not isinstance(value, str) and value is not None else value

        self.metaType = meta_type
        self.metaId = meta_id
        self.meta = Meta.normalize_meta(meta) if meta is not None else []

        self.index = index
        self.otsFragment = ots_fragment
        self.createdAt = Strings.current_time_millis()

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
        :param atoms: List[Atom]
        :param output: str default base17
        :return: Union[str, None, List]
        """
        atom_list = Atom.sort_atoms(atoms)
        molecular_sponge = shake()
        number_of_atoms = Strings.encode(str(len(atom_list)))

        for atom in atom_list:
            molecular_sponge.update(number_of_atoms)

            for prop, value in atom.__dict__.items():
                if prop in ['otsFragment', 'index']:
                    continue
                elif prop in ['meta']:
                    atom.meta = Meta.normalize_meta(value)
                    for meta in atom.meta:
                        molecular_sponge.update(Strings.encode(meta['key']))
                        molecular_sponge.update(Strings.encode(meta['value']))
                elif prop in ['position', 'walletAddress', 'isotope'] or value is not None:
                    molecular_sponge.update(Strings.encode(value))

        target = None

        if output in ['hex']:
            target = molecular_sponge.hexdigest(32)
        elif output in ['array']:
            target = list(molecular_sponge.hexdigest(32))
        elif output in ['base17']:
            target = Strings.charset_base_convert(
                molecular_sponge.hexdigest(32), 16, 17, '0123456789abcdef', '0123456789abcdefg'
            )
            target = target.rjust(64, '0') if isinstance(target, str) else None

        return target

    @classmethod
    def sort_atoms(cls, atoms: List['Atom']) -> List:
        """
        :param atoms: List[Atom]
        :return: List[Atom]
        """
        return sorted(atoms, key=lambda atom: atom.index)


class Wallet(object):
    """class Wallet"""

    position: str
    token: str
    key: str
    address: str
    balance: Union[int, float]
    molecules: List
    bundle: str
    privkey: str
    pubkey: str

    def __init__(self, secret: str = None, token: str = 'USER', position: str = None, salt_length: int = 64) -> None:
        """
        :param secret: str default None
        :param token: str default USER
        :param position: str default None
        :param salt_length: int default 64
        """
        self.position = position or Strings.random_string(salt_length)
        self.token = token
        self.balance = 0
        self.molecules = []

        if secret is not None:
            self.key = Wallet.generate_key(secret, token, self.position)
            self.address = Wallet.generate_address(self.key)
            self.bundle = Crypto.generate_bundle_hash(secret)
            self.privkey = self.get_my_enc_private_key()
            self.pubkey = self.get_my_enc_public_key()

    @classmethod
    def generate_address(cls, key: str) -> str:
        """
        :param key: str
        :return: str
        """
        digest_sponge = shake()

        for fragment in Strings.chunk_substr(key, 128):
            working_fragment = fragment

            for _ in range(16):
                working_sponge = shake()
                working_sponge.update(Strings.encode(working_fragment))
                working_fragment = working_sponge.hexdigest(64)

            digest_sponge.update(Strings.encode(working_fragment))

        sponge = shake()
        sponge.update(Strings.encode(digest_sponge.hexdigest(1024)))

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
        sponge.update(Strings.encode(intermediate_key_sponge.hexdigest(1024)))

        return sponge.hexdigest(1024)

    def get_my_enc_private_key(self) -> str:
        """
        Derives a private key for encrypting data with this wallet's key

        :return: str
        """
        return Crypto.generate_enc_private_key(self.key)

    def get_my_enc_public_key(self) -> str:
        """
        Dervies a public key for encrypting data for this wallet's consumption

        :return: str
        """
        return Crypto.generate_enc_public_key(self.get_my_enc_private_key())

    def get_my_enc_shared_key(self, other_public_key: str) -> str:
        """
        Creates a shared key by combining this wallet's private key and another wallet's public key

        :param other_public_key: str
        :return: str
        """
        return Crypto.generate_enc_shared_key(self.get_my_enc_private_key(), other_public_key)

    def decrypt_my_message(self, message: str, other_public_key: str = None) -> Message:
        """
        Uses the current wallet's private key to decrypt the given message

        :param message: str
        :param other_public_key: str default None
        :return: List or Dict or None
        """

        if other_public_key is None:
            target = Crypto.decrypt_message(message, self.get_my_enc_public_key())
        else:
            target = Crypto.decrypt_message(
                message,
                Crypto.generate_enc_public_key(self.get_my_enc_shared_key(other_public_key))
            )

            if target is None:
                target = Crypto.decrypt_message(message, other_public_key)

        return target


class Molecule(_Base):
    """class Molecule"""

    molecularHash: StrOrNone
    cellSlug: StrOrNone
    bundle: StrOrNone
    status: StrOrNone
    createdAt: str
    atoms: List[Atom]

    def __init__(self, cell_slug: str = None) -> None:
        """
        :param cell_slug: str default None
        """
        self.molecularHash = None
        self.cellSlug = cell_slug
        self.bundle = None
        self.status = None
        self.createdAt = Strings.current_time_millis()
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

    def init_value(self, source: Wallet, recipient: Wallet, remainder: Wallet, value: Union[int, float]) -> 'Molecule':
        """
        Initialize a V-type molecule to transfer value from one wallet to another, with a third,
        regenerated wallet receiving the remainder

        :param source: Wallet
        :param recipient: Wallet
        :param remainder: Wallet
        :param value: Union[int, float]
        :return: self
        """

        if (source.balance - value) < 0:
            raise BalanceInsufficientException()

        self.molecularHash = None

        self.atoms.append(
            Atom(
                source.position,
                source.address,
                'V',
                source.token,
                -value,
                None,
                None,
                None,
                None,
                self.generate_index()
            )
        )

        self.atoms.append(
            Atom(
                recipient.position,
                recipient.address,
                'V',
                source.token,
                value,
                'walletBundle',
                recipient.bundle,
                None,
                None,
                self.generate_index()
            )
        )

        self.atoms.append(
            Atom(
                remainder.position,
                remainder.address,
                'V',
                source.token,
                source.balance - value,
                'walletBundle',
                remainder.bundle,
                None,
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_identifier_creation(self, source_wallet: Wallet, source: str, type: str, code: str) -> 'Molecule':
        """
        Initialize a C-type molecule to issue a new type of identifier

        :param source_wallet: Wallet
        :param source: str
        :param type: str
        :param code: str
        :return: self
        """

        self.molecularHash = None

        source_hash = source.strip()

        self.atoms.append(
            Atom(
                source_wallet.position,
                source_wallet.address,
                'C',
                source_wallet.token,
                None,
                'identifier',
                type,
                [
                    {'key': 'code', 'value': code},
                    {'key': 'hash', 'value': Crypto.generate_bundle_hash(source_hash)}
                ],
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_token_creation(self, source: Wallet, recipient: Wallet, amount: Union[int, float],
                            token_meta: Union[List, Dict]) -> 'Molecule':
        """
        Initialize a C-type molecule to issue a new type of token

        :param source: Wallet
        :param recipient: Wallet
        :param amount: Union[int, float]
        :param token_meta: Union[List, Dict]
        :return: self
        """
        self.molecularHash = None

        metas = Meta.normalize_meta(token_meta)

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
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_meta(self, wallet: Wallet, meta: Union[List, Dict], meta_type: str,
                  meta_id: Union[str, int]) -> 'Molecule':
        """
        Initialize an M-type molecule with the given data

        :param wallet: Wallet
        :param meta: Union[List, Dict]
        :param meta_type: str
        :param meta_id: Union[str, int]
        :return: self
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
                Meta.normalize_meta(meta),
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def sign(self, secret: str, anonymous: bool = False, compressed: bool = True) -> StrOrNone:
        """
        Creates a one-time signature for a molecule and breaks it up across multiple atoms within that
        molecule. Resulting 4096 byte (2048 character) string is the one-time signature.

        :param secret: str
        :param anonymous: bool default False
        :param compressed: bool default True
        :return: StrOrNone
        :raise TypeError: The molecule does not contain atoms
        """
        if len(self.atoms) == 0 or len([atom for atom in self.atoms if not isinstance(atom, Atom)]) != 0:
            raise AtomsMissingException()

        if not anonymous:
            self.bundle = Crypto.generate_bundle_hash(secret)

        self.molecularHash = Atom.hash_atoms(self.atoms)
        first_atom, normalized_hash, signature_fragments = (self.atoms[0],
                                                            CheckMolecule.normalized_hash(self.molecularHash),
                                                            '')
        for idx, chunk in enumerate(
                Strings.chunk_substr(Wallet.generate_key(secret, first_atom.token, first_atom.position), 128)):

            working_chunk = chunk

            for _ in range(8 - normalized_hash[idx]):
                sponge = shake()
                sponge.update(Strings.encode(working_chunk))
                working_chunk = sponge.hexdigest(64)

            signature_fragments = '%s%s' % (signature_fragments, working_chunk)

        # Compressing the OTS
        if compressed:
            signature_fragments = Strings.hex_to_base64(signature_fragments)

        last_position = None

        for chunk_count, signature in enumerate(Strings.chunk_substr(signature_fragments, math.ceil(
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

    def generate_index(self) -> int:
        """
        :return: int
        """
        return Molecule.generate_next_atom_index(self.atoms)

    def check(self, sender: Wallet = None) -> bool:
        """
        :param sender: Wallet default None
        :return: bool
        """
        return Molecule.verify(self, sender)

    @classmethod
    def verify(cls, molecule: 'Molecule', sender: Wallet = None) -> bool:
        """

        :param molecule: Molecule
        :param sender: Wallet default None
        :return: bool
        :raises BaseError:
        """
        return CheckMolecule.molecular_hash(molecule) and \
               CheckMolecule.ots(molecule) and \
               CheckMolecule.isotope_m(molecule) and \
               CheckMolecule.isotope_v(molecule, sender) and \
               CheckMolecule.index(molecule)

    @classmethod
    def generate_next_atom_index(cls, atoms: List[Atom]) -> int:
        """
        :param atoms: List[Atom]
        :return: int
        """
        try:
            return atoms[-1].index + 1
        except IndexError:
            return 0
