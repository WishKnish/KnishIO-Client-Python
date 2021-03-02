# -*- coding: utf-8 -*-

import math
import string
from hashlib import shake_256 as shake
from json import JSONDecoder, JSONEncoder, dumps, JSONDecodeError
from numpy import array, add
from typing import Union, List, Dict, Any

from knishioclient.libraries import strings, decimal, crypto, check
from knishioclient.exception import *

__all__ = (
    'Meta',
    'Atom',
    'Wallet',
    'Molecule',
    'Coder',
)

_Metas = Union[List[Dict[str, Union[str, int, float]]], Dict[str, Union[str, int, float]]]
_StrOrNone = Union[str, bytes, None]


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
                'batchId': value.batchId,
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

        if isinstance(value, bytes):
            return strings.decode(value)

        return super().default(value)


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

    @classmethod
    def array_to_object(cls, data: Dict, obj=None):
        thing = obj or cls()

        for prop, value in data.items():
            if hasattr(thing, 'set_property') and callable(getattr(thing, 'set_property')):
                thing.set_property(prop, value)
                continue

            setattr(thing, prop, value)

        return thing


class Meta(_Base):
    """class Meta"""

    modelType: str
    modelId: str
    meta: _Metas
    snapshotMolecule: str
    createdAt: str

    def __int__(self, model_type: str, model_id: str, meta: _Metas, snapshot_molecule: str = None) -> None:
        """
        :param model_type: str
        :param model_id: str
        :param meta: _Metas
        :param snapshot_molecule: str default None
        """
        self.modelType = model_type
        self.modelId = model_id
        self.meta = meta
        self.snapshotMolecule = snapshot_molecule
        self.createdAt = strings.current_time_millis()

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

        for meta in metas:
            if "key" in meta:
                aggregate.update({meta["key"]: meta["value"]})
            else:
                aggregate.update(meta)

        return aggregate


class Atom(_Base):
    """class Atom"""

    position: str
    walletAddress: str
    isotope: str
    token: _StrOrNone
    value: _StrOrNone
    batchId: _StrOrNone
    metaType: _StrOrNone
    metaId: _StrOrNone
    meta: _Metas

    index: int
    otsFragment: _StrOrNone
    createdAt: str

    def __init__(self, position: str, wallet_address: str, isotope: str, token: str = None,
                 value: Union[str, int, float] = None, batch_id: str = None, meta_type: str = None, meta_id: str = None,
                 meta: _Metas = None, ots_fragment: str = None, index: int = None) -> None:
        self.position = position
        self.walletAddress = wallet_address
        self.isotope = isotope
        self.token = token
        self.value = str(value) if not isinstance(value, str) and value is not None else value
        self.batchId = batch_id

        self.metaType = meta_type
        self.metaId = meta_id
        self.meta = Meta.normalize_meta(meta) if meta is not None else []

        self.index = index
        self.otsFragment = ots_fragment
        self.createdAt = strings.current_time_millis()

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
        number_of_atoms = strings.encode(str(len(atom_list)))

        for atom in atom_list:
            molecular_sponge.update(number_of_atoms)

            for prop, value in atom.__dict__.items():

                if value is None and prop in ['batchId', 'characters', 'pubkey']:
                    continue

                if prop in ['otsFragment', 'index']:
                    continue

                if prop in ['meta']:
                    atom.meta = Meta.normalize_meta(value)
                    for index, meta in enumerate(atom.meta):
                        if meta['value'] is not None:
                            atom.meta[index]['value'] = str(meta['value'])

                            for key in ['key', 'value']:
                                molecular_sponge.update(strings.encode(meta[key]))
                    continue

                if prop in ['position', 'walletAddress', 'isotope']:
                    molecular_sponge.update(strings.encode('' if value is None else value))
                    continue

                if value is not None:
                    molecular_sponge.update(strings.encode(value))

        target = None

        if output in ['hex']:
            target = molecular_sponge.hexdigest(32)
        elif output in ['array']:
            target = list(molecular_sponge.hexdigest(32))
        elif output in ['base17']:
            target = strings.charset_base_convert(
                molecular_sponge.hexdigest(32), 16, 17, '0123456789abcdef', '0123456789abcdefg'
            )

            target = target.rjust(64, '0') if isinstance(target, str) else None

        return target

    def aggregated_meta(self) -> Dict:
        """
        :return: Dict
        """
        return Meta.aggregate_meta(self.meta)

    @classmethod
    def sort_atoms(cls, atoms: List['Atom']) -> List:
        """
        :param atoms: List[Atom]
        :return: List[Atom]
        """
        return sorted(atoms, key=lambda atom: atom.index)

    def set_property(self, attribute: str, value) -> None:
        """
        :param attribute:
        :param value:
        :return: None
        """
        feature = {'tokenSlug': 'token', 'metas': 'meta'}.get(attribute, attribute)

        if len(self.meta) == 0 and feature in 'metasJson':
            try:
                self.meta = JSONDecoder().decode(value)
            except JSONDecodeError:
                pass
            return

        setattr(self, feature, value)


class Wallet(object):
    """class Wallet"""

    batchId: _StrOrNone = None
    position: _StrOrNone = None
    token: str
    key: _StrOrNone = None
    address: _StrOrNone = None
    balance: Union[int, float]
    molecules: List = None
    bundle: _StrOrNone = None
    privkey: _StrOrNone = None
    pubkey: _StrOrNone = None
    characters: _StrOrNone = None

    def __init__(self, secret: str = None, token: str = 'USER', position: str = None, batch_id: str = None,
                 characters: str = None) -> None:
        """
        :param secret: str default None
        :param token: str default USER
        :param position: str default None
        :param batch_id: str default None
        :param characters: str default None
        """

        self.token = token
        self.balance = 0
        self.molecules = []

        # Empty values
        self.key = None
        self.address = None
        self.privkey = None
        self.pubkey = None

        self.bundle = None
        self.batchId = batch_id
        self.position = position
        self.characters = characters

        if secret is not None:
            self.bundle = crypto.generate_bundle_hash(secret)
            self.position = Wallet.generate_wallet_position()
            self.prepare_keys(secret)

    def prepare_keys(self, secret) -> None:
        """
        :param secret: str
        :return:
        """
        if self.key is None and self.address is None:
            self.key = Wallet.generate_private_key(secret, self.token, self.position)
            self.address = Wallet.generate_public_key(self.key)
            self.privkey = self.get_my_enc_private_key()
            self.pubkey = self.get_my_enc_public_key()

    def is_shadow(self) -> bool:
        """
        :return: bool
        """
        return self.position is None and self.address is None

    def encrypt_string(self, data: str = None, public_keys: Union[str, bytes, list] = None) -> str:
        """
        :param data: str
        :param public_keys: Union[str, bytes, list]
        :return: str
        """
        if public_keys is None:
            public_keys = []

        if data is not None:
            public_key = self.get_my_enc_public_key()

            if isinstance(public_keys, (str, bytes)):
                public_keys = [public_keys]

            encrypted_data = self.encrypt_my_message(data, public_key, *public_keys)
            return strings.base64_encode(Coder().encode(encrypted_data))
        return ''

    def decrypt_string(self, data: str = None, fallback_value: str = None):
        """
        :param data: str
        :param fallback_value: Union[str|None]
        :return:
        """
        if data is not None:
            decrypted = JSONDecoder().decode(strings.base64_decode(data))
            return self.decrypt_my_message(decrypted) or fallback_value
        return fallback_value

    @classmethod
    def create(cls, secret_or_bundle: str, token: str = 'USER', batch_id: str = None, characters: str = None):
        """
        :param secret_or_bundle: str
        :param token: str
        :param batch_id: str
        :param characters: str
        :return: Wallet
        """
        secret = None if cls.is_bundle_hash(secret_or_bundle) else secret_or_bundle
        bundle = crypto.generate_bundle_hash(secret) if secret is not None else secret_or_bundle
        position = cls.generate_wallet_position() if secret is not None else None

        if cls.is_bundle_hash(secret_or_bundle):
            return WalletShadow(secret_or_bundle, token, batch_id, characters)

        wallet = Wallet(secret, token, position, batch_id, characters)
        wallet.bundle = bundle

        return wallet

    @classmethod
    def generate_wallet_position(cls, salt_length: int = 64):
        """
        :param salt_length: int
        :return: str
        """
        return strings.random_string(salt_length)

    @classmethod
    def is_bundle_hash(cls, code: str) -> bool:
        """
        :param code: str
        :return: bool
        """
        return len(code) == 64 and all(c in string.hexdigits for c in code)

    @classmethod
    def generate_public_key(cls, key: str) -> str:
        """
        :param key: str
        :return: str
        """
        digest_sponge = shake()

        for fragment in strings.chunk_substr(key, 128):
            working_fragment = fragment

            for _ in range(16):
                working_sponge = shake()
                working_sponge.update(strings.encode(working_fragment))
                working_fragment = working_sponge.hexdigest(64)

            digest_sponge.update(strings.encode(working_fragment))

        sponge = shake()
        sponge.update(strings.encode(digest_sponge.hexdigest(1024)))

        return sponge.hexdigest(32)

    @classmethod
    def generate_private_key(cls, secret: str, token: str, position: str) -> str:
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
        sponge.update(strings.encode(intermediate_key_sponge.hexdigest(1024)))

        return sponge.hexdigest(1024)

    def init_batch_id(self, sender_wallet, transfer_amount, no_splitting: bool = False) -> None:
        """
        :param sender_wallet:
        :param transfer_amount:
        :param no_splitting: bool
        :return:
        """
        self.batchId = sender_wallet.batchId if no_splitting else crypto.generate_batch_id()

    def get_my_enc_private_key(self) -> bytes:
        """
        Derives a private key for encrypting data with this wallet's key

        :return: str
        """
        crypto.set_characters(self.characters)

        if self.privkey is None and self.key is not None:
            self.privkey = crypto.generate_enc_private_key(self.key)

        return self.privkey

    def get_my_enc_public_key(self) -> bytes:
        """
        Derives a public key for encrypting data for this wallet's consumption

        :return: str
        """
        crypto.set_characters(self.characters)
        private_key = self.get_my_enc_private_key()

        if self.pubkey is None and private_key is not None:
            self.pubkey = crypto.generate_enc_public_key(private_key)

        return self.pubkey

    def encrypt_my_message(self, message, *keys):
        crypto.set_characters(self.characters)
        return {crypto.hash_share(key): crypto.encrypt_message(message, key) for key in keys}

    def decrypt_my_message(self, message: str):
        crypto.set_characters(self.characters)
        pub_key = self.get_my_enc_public_key()
        encrypt = message

        if isinstance(message, dict):
            encrypt = message.get(crypto.hash_share(pub_key), message)

        return crypto.decrypt_message(encrypt, self.get_my_enc_private_key(), pub_key)


class WalletShadow(Wallet):
    """class WalletShadow"""

    def __init__(self, bundle_hash: str, token: str = 'USER', batch_id: str = None, characters: str = None):
        """
        :param bundle_hash: str
        :param token: str
        :param batch_id: str
        :param characters: str
        """
        super().__init__(None, token)

        self.bundle = bundle_hash
        self.batchId = batch_id
        self.characters = characters

        self.position = None
        self.key = None
        self.address = None
        self.pubkey = None


class MoleculeStructure(_Base):
    """class MoleculeStructure"""

    molecularHash: _StrOrNone
    cellSlug: _StrOrNone
    counterparty: _StrOrNone
    bundle: _StrOrNone
    status: _StrOrNone
    local: bool
    createdAt: str
    atoms: List[Atom]

    cellSlugOrigin: _StrOrNone

    def __init__(self, cell_slug: _StrOrNone = None):
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

        # Subdivide Kk into 16 segments of 256 bytes (128 characters) each
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
    def to_object(cls, data):
        obj = cls.array_to_object(data)

        for key, atom_data in enumerate(obj.atoms):
            atom = Atom(atom_data['position'], atom_data['walletAddress'], atom_data['isotope'])
            obj.atoms[key] = Atom.array_to_object(atom_data, atom)

        obj.atoms = Atom.sort_atoms(obj.atoms)

        return obj


class Molecule(MoleculeStructure):
    """class Molecule"""

    createdAt: str

    def __init__(self, secret=None, source_wallet: Wallet = None, remainder_wallet: Wallet = None,
                 cell_slug: str = None) -> None:
        """
        :param secret:
        :param source_wallet:
        :param remainder_wallet:
        :param cell_slug:
        """
        super(Molecule, self).__init__(cell_slug)

        self.__secret = secret
        self.sourceWallet = source_wallet

        if remainder_wallet or source_wallet:
            self.remainderWallet = remainder_wallet if remainder_wallet is not None else Wallet.create(
                secret, source_wallet.token, source_wallet.batchId, source_wallet.characters
            )

        self.clear()

    @property
    def USE_META_CONTEXT(self) -> bool:
        return False

    @property
    def DEFAULT_META_CONTEXT(self) -> str:
        return 'http://www.schema.org'

    def clear(self) -> 'Molecule':
        """
        Clears the instance of the data, leads the instance to a state equivalent to that after Molecule()

        :return: Molecule
        """

        self.molecularHash = None
        self.bundle = None
        self.status = None
        self.createdAt = strings.current_time_millis()
        self.atoms = []

        return self

    def fill(self, molecule_structure: MoleculeStructure):
        """
        :param molecule_structure: MoleculeStructure
        :return:
        """
        for name, value in molecule_structure.__dict__.items():
            setattr(self, name, value)

    def secret(self):
        """
        :return: str
        """
        return self.__secret

    def source_wallet(self):
        """
        :return: Wallet
        """
        return self.sourceWallet

    def remainder_wallet(self):
        """
        :return: Wallet
        """
        return self.remainderWallet

    def add_atom(self, atom: Atom):
        """
        :param atom: Atom
        :return: Molecule
        """
        self.molecularHash = None
        self.atoms.append(atom)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    # @classmethod
    # def merge_metas(cls, *arguments):
    #    target = {}
    #    for argument in arguments:
    #        target.update(Meta.aggregate_meta(Meta.normalize_meta(argument)))

    #    return target

    def encrypt_message(self, data, shared_wallets: list):
        args = [data, self.sourceWallet.pubkey]
        args.extend(shared_wallets)
        getattr(self.sourceWallet, 'encrypt_my_message')(*args)

    def final_metas(self, metas: _Metas, wallet: Wallet = None) -> _Metas:
        purse = wallet if wallet is not None else self.sourceWallet
        metas.update({'pubkey': purse.pubkey, 'characters': purse.characters})
        return metas

    def context_metas(self, metas: _Metas, context: str = None) -> _Metas:
        if Molecule.USE_META_CONTEXT:
            metas['context'] = context if context is not None else Molecule.DEFAULT_META_CONTEXT
        return metas

    @classmethod
    def continu_id_meta_type(cls) -> str:
        return 'walletBundle'

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

    def add_user_remainder_atom(self, user_remainder_wallet: Wallet):
        """
        :param user_remainder_wallet: Wallet
        :return: self
        """
        self.molecularHash = None
        self.atoms.append(
            Atom(
                user_remainder_wallet.position,
                user_remainder_wallet.address,
                "I",
                user_remainder_wallet.token,
                None,
                None,
                Molecule.continu_id_meta_type(),
                user_remainder_wallet.bundle,
                self.final_metas({}, user_remainder_wallet),
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def crate_rule(self, meta_type: str, meta_id: Union[str, bytes, int], meta: _Metas):
        aggregate_meta = Meta.aggregate_meta(Meta.normalize_meta(meta))

        if all(key not in aggregate_meta for key in ("conditions", "callback", "rule")):
            raise MetaMissingException('No or not defined conditions or callback or rule in meta')

        for index in ("conditions", "callback", "rule"):
            if isinstance(aggregate_meta[index], (list, Dict)):
                aggregate_meta[index] = Coder().encode(aggregate_meta[index])

        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                "R",
                self.sourceWallet.token,
                None,
                None,
                meta_type,
                meta_id,
                self.final_metas(aggregate_meta),
                None,
                self.generate_index()
            )
        )

        self.add_user_remainder_atom(self.remainderWallet)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def replenishing_tokens(self, value, token, metas: _Metas):
        """
        :param value:
        :param token: str
        :param metas: _Metas
        :return:
        """
        aggregate_meta = Meta.aggregate_meta(Meta.normalize_meta(metas))
        aggregate_meta.update({"action": "add"})

        if all(key not in aggregate_meta for key in ("address", "position", "batchId")):
            raise MetaMissingException('No or not defined address or position or batchId in meta')

        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                "C",
                self.sourceWallet.token,
                value,
                self.sourceWallet.batchId,
                "token",
                token,
                self.final_metas(self.context_metas(aggregate_meta)),
                None,
                self.generate_index()
            )
        )

        self.add_user_remainder_atom(self.remainderWallet)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def burning_tokens(self, value, wallet_bundle=None):
        if value < 0.0:
            raise NegativeMeaningException('It is impossible to use a negative value for the number of tokens')

        if decimal.cmp(0.0, float(self.sourceWallet.balance) - value) > 0:
            raise BalanceInsufficientException()

        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                "V",
                self.sourceWallet.token,
                - float(value),
                self.sourceWallet.batchId,
                None,
                None,
                self.final_metas({}),
                None,
                self.generate_index()
            )
        )

        self.add_atom(
            Atom(
                self.remainderWallet.position,
                self.remainderWallet.address,
                "V",
                self.sourceWallet.token,
                float(self.sourceWallet.balance) - value,
                self.remainderWallet.batchId,
                'walletBundle' if wallet_bundle else None,
                wallet_bundle,
                self.final_metas({}, self.remainderWallet),
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_value(self, recipient: Wallet, value: Union[int, float]) -> 'Molecule':
        """
        Initialize a V-type molecule to transfer value from one wallet to another, with a third,
        regenerated wallet receiving the remainder

        :param recipient: Wallet
        :param value: Union[int, float]
        :return: self
        """

        if decimal.cmp(float(value), float(self.sourceWallet.balance)) > 0:
            raise BalanceInsufficientException()

        self.molecularHash = None

        self.atoms.append(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'V',
                self.sourceWallet.token,
                -value,
                self.sourceWallet.batchId,
                None,
                None,
                self.final_metas({}),
                None,
                self.generate_index()
            )
        )

        self.atoms.append(
            Atom(
                recipient.position,
                recipient.address,
                'V',
                self.sourceWallet.token,
                value,
                recipient.batchId,
                'walletBundle',
                recipient.bundle,
                self.final_metas({}, recipient),
                None,
                self.generate_index()
            )
        )

        self.atoms.append(
            Atom(
                self.remainderWallet.position,
                self.remainderWallet.address,
                'V',
                self.sourceWallet.token,
                float(self.sourceWallet.balance) - value,
                self.remainderWallet.batchId,
                'walletBundle',
                self.sourceWallet.bundle,
                self.final_metas({}, self.remainderWallet),
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_wallet_creation(self, new_wallet: Wallet):
        metas = {
            "address": new_wallet.address,
            "token": new_wallet.token,
            "bundle": new_wallet.bundle,
            "position": new_wallet.position,
            "amount": 0,
            "batch_id": new_wallet.batchId
        }

        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                "C",
                self.sourceWallet.token,
                None,
                self.sourceWallet.batchId,
                "wallet",
                new_wallet.address,
                self.final_metas(self.context_metas(metas), new_wallet),
                None,
                self.generate_index()
            )
        )

        self.add_user_remainder_atom(self.remainderWallet)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_peer_creation(self, slug: str, host: str, name: str = None, cell_slugs: list = None):
        """
        :param slug: str
        :param host: str
        :param name: str
        :param cell_slugs: list
        :return: self
        """
        metas = {
            'host': host,
            'name': name,
            'cellSlugs': cell_slugs or []
        }

        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'P',
                self.sourceWallet.token,
                None,
                self.sourceWallet.batchId,
                'peer',
                slug,
                self.final_metas(metas),
                None,
                self.generate_index()
            )
        )

        self.add_user_remainder_atom(self.remainderWallet)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_identifier_creation(self, type0: str, contact: str, code: str) -> 'Molecule':
        """
        Initialize a C-type molecule to issue a new type of identifier

        :param type0: str
        :param contact: str
        :param code: str
        :return: self
        """

        self.molecularHash = None

        self.atoms.append(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'C',
                self.sourceWallet.token,
                None,
                None,
                'identifier',
                type0,
                {
                    "pubkey": self.sourceWallet.pubkey,
                    "characters": self.sourceWallet.characters,
                    "code": code,
                    "hash": crypto.generate_bundle_hash(contact.strip())
                },
                None,
                self.generate_index()
            )
        )

        self.add_user_remainder_atom(self.remainderWallet)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_token_creation(self, recipient: Wallet, amount: Union[int, float],
                            token_meta: Union[List, Dict]) -> 'Molecule':
        """
        Initialize a C-type molecule to issue a new type of token

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
                self.sourceWallet.position,
                self.sourceWallet.address,
                'C',
                self.sourceWallet.token,
                amount,
                recipient.batchId,
                'token',
                recipient.token,
                self.final_metas(Meta.aggregate_meta(metas)),
                None,
                self.generate_index()
            )
        )

        self.add_user_remainder_atom(self.remainderWallet)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_shadow_wallet_claim(self, token_slug: str, wallet: Wallet):
        self.molecularHash = None
        metas = {
            "tokenSlug"
            "walletAddress": wallet.address,
            "walletPosition": wallet.position,
            "batchId": wallet.batchId
        }

        self.atoms.append(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                "C",
                self.sourceWallet.token,
                None,
                None,
                'wallet',
                wallet.address,
                Molecule.final_metas(metas),
                None,
                self.generate_index()
            )
        )

        self.add_user_remainder_atom(self.remainderWallet)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_meta(self, meta: Union[List, Dict], meta_type: str,
                  meta_id: Union[str, int]) -> 'Molecule':
        """
        Initialize an M-type molecule with the given data

        :param meta: Union[List, Dict]
        :param meta_type: str
        :param meta_id: Union[str, int]
        :return: self
        """
        self.molecularHash = None

        self.atoms.append(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'M',
                self.sourceWallet.token,
                None,
                self.sourceWallet.batchId,
                meta_type,
                meta_id,
                self.final_metas(meta),
                None,
                self.generate_index()
            )
        )

        self.add_user_remainder_atom(self.remainderWallet)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_bundle_meta(self, meta):

        self.cellSlug = '%s%s%s' % (self.cellSlugOrigin, Molecule.cellSlugDelimiter, self.sourceWallet.bundle)

        return self.init_meta(meta, 'walletBundle', self.sourceWallet.bundle)

    def init_meta_append(self, meta, meta_type, meta_id):
        self.molecularHash = None

        self.atoms.append(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                "A",
                self.sourceWallet.token,
                None,
                None,
                meta_type,
                meta_id,
                Molecule.merge_metas(
                    {
                        "pubkey": self.sourceWallet.pubkey,
                        "characters": self.sourceWallet.characters,
                    },
                    meta
                ),
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_token_request(self, token, requested_amount, meta_type, meta_id, meta: Union[list, dict] = None):
        self.molecularHash = None
        meta = meta or []

        self.atoms.append(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                "T",
                self.sourceWallet.token,
                requested_amount,
                None,
                meta_type,
                meta_id,
                Molecule.merge_metas(
                    {
                        "pubkey": self.sourceWallet.pubkey,
                        "characters": self.sourceWallet.characters,
                        "token": token,
                    },
                    meta
                ),
                None,
                self.generate_index()
            )
        )

        self.add_user_remainder_atom(self.remainderWallet)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_authorization(self):
        self.molecularHash = None

        self.atoms.append(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                "U",
                self.sourceWallet.token,
                None,
                self.sourceWallet.batchId,
                None,
                None,
                {
                    "pubkey": self.sourceWallet.pubkey,
                    "characters": self.sourceWallet.characters,
                },
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def sign(self, anonymous: bool = False, compressed: bool = True) -> _StrOrNone:
        """
        Creates a one-time signature for a molecule and breaks it up across multiple atoms within that
        molecule. Resulting 4096 byte (2048 character) string is the one-time signature.

        :param anonymous: bool default False
        :param compressed: bool default True
        :return: _StrOrNone
        :raise TypeError: The molecule does not contain atoms
        """
        if len(self.atoms) == 0 or len([atom for atom in self.atoms if not isinstance(atom, Atom)]) != 0:
            raise AtomsMissingException()

        if not anonymous:
            self.bundle = crypto.generate_bundle_hash(self.secret())

        self.molecularHash = Atom.hash_atoms(self.atoms)
        self.atoms = Atom.sort_atoms(self.atoms)
        first_atom = self.atoms[0]
        key = Wallet.generate_private_key(self.secret(), first_atom.token, first_atom.position)

        signature_fragments = self.signature_fragments(key)

        # Compressing the OTS
        if compressed:
            signature_fragments = strings.hex_to_base64(signature_fragments)

        last_position = None

        for chunk_count, signature in enumerate(strings.chunk_substr(signature_fragments, math.ceil(
                len(signature_fragments) / len(self.atoms)))):
            atom = self.atoms[chunk_count]
            atom.otsFragment = signature
            last_position = atom.position

        return last_position

    def generate_index(self) -> int:
        """
        :return: int
        """
        return Molecule.generate_next_atom_index(self.atoms)

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
