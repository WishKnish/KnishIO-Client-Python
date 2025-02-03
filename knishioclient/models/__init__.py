# -*- coding: utf-8 -*-

import math
import string
import base64
import os
import numpy as np
from hashlib import shake_256 as shake
from json import JSONDecoder, JSONEncoder, dumps, JSONDecodeError, loads

from numpy import array, add
from typing import List, Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from knishioclient.libraries import strings, decimal, crypto, check
from knishioclient.exception import *

__all__ = (
    'Meta',
    'Atom',
    'Wallet',
    'Molecule',
    'Coder',
)

from knishioclient.libraries.kem import ml_kem768

USE_META_CONTEXT = False
DEFAULT_META_CONTEXT = 'https://www.schema.org'


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


class TokenUnit:
    def __init__(self, id: str, name: str, metas: Dict = None):
        self.id: str = id
        self.name: str = name
        self.metas: Dict = metas or {}

    @classmethod
    def create_from_graph_ql(cls, data: "TokenUnit" | Dict) -> "TokenUnit":
        if isinstance(data, cls):
            return cls(data.id, data.name, data.metas)
        metas = data["metas"] or {}
        if isinstance(metas, str):
            try:
                metas = loads(metas)
            except JSONDecodeError:
                metas = {}
        return cls(data["id"], data["name"], metas)

    @classmethod
    def create_from_db(cls, data: List) -> "TokenUnit":
        return cls(data[0], data[1], data[2] if len(data) > 2 else {})

    def get_fragment_zone(self):
        return self.metas.get("fragmentZone", None)

    def get_fused_token_units(self):
        return self.metas.get("fusedTokenUnits", None)

    def to_data(self) -> List:
        return [self.id, self.name, self.metas]

    def to_graph_ql_response(self) -> Dict:
        return {"id": self.id, "name": self.name, "metas": self.metas}


class Meta(_Base):
    """class Meta"""

    modelType: str
    modelId: str
    meta: List[Dict[str, str | int | float]] | Dict[str, str | int | float]
    snapshotMolecule: str
    createdAt: str

    def __int__(self, model_type: str, model_id: str,
                meta: List[Dict[str, str | int | float]] | Dict[str, str | int | float],
                snapshot_molecule: str = None) -> None:
        """
        :param model_type: str
        :param model_id: str
        :param meta: List[Dict[str, str | int | float]] | Dict[str, str | int | float]
        :param snapshot_molecule: str default None
        """
        self.modelType = model_type
        self.modelId = model_id
        self.meta = meta
        self.snapshotMolecule = snapshot_molecule
        self.createdAt = strings.current_time_millis()

    @classmethod
    def normalize_meta(cls, metas: List | Dict) -> List[Dict]:
        """
        :param metas: List | Dict
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


class PolicyMeta(_Base):
    """class PolicyMeta"""

    def __init__(self, policy: Dict = None, meta_keys: List = None):
        self.policy = PolicyMeta.normalize_policy(policy or {})
        self.fill_default(meta_keys or [])

    @classmethod
    def normalize_policy(cls, policy: Dict[str, Any]) -> Dict:
        return {k: dict(v) for k, v in policy.items() if v and k in ["read", "write"]}

    def fill_default(self, meta_keys: List) -> None:
        for action in ["read", "write"]:
            policy = {v["key"]: v for v in self.policy.values() if "action" in v and v["action"] == action}
            self.policy.setdefault(action, {})
            for key in set(meta_keys) - set(policy):
                self.policy[action][key] = ["self"] if action == "write" and key not in ["characters", "pubkey"] else [
                    "all"]

    def get(self) -> Dict:
        return self.policy

    def to_json(self) -> str:
        return dumps(self.policy)


class AtomMeta(_Base):
    """class AtomMeta"""

    def __init__(self, meta: Dict[str, str] | None = None):
        self.meta: Dict[str, str] | None = meta or {}

    def merge(self, meta: dict[str, str]) -> "AtomMeta":
        self.meta = self.meta | meta
        return self

    def add_context(self, context: str) -> "AtomMeta":
        if USE_META_CONTEXT:
            self.merge({"context": context or DEFAULT_META_CONTEXT})
        return self

    def set_atom_wallet(self, wallet: "Wallet") -> "AtomMeta":
        wallet_meta = {"pubkey": wallet.pubkey, "characters": wallet.characters}
        if wallet.tokenUnits:
            wallet_meta.update({"tokenUnits": dumps(wallet.get_token_units_data())})
        if wallet.tradeRates:
            wallet_meta.update({"tradeRates": dumps(wallet.tradeRates)})
        return self.merge(wallet_meta)

    def set_meta_wallet(self, wallet: "Wallet") -> "AtomMeta":
        return self.merge({
            "walletTokenSlug": wallet.token,
            "walletBundleHash": wallet.bundle,
            "walletAddress": wallet.address,
            "walletPosition": wallet.position,
            "walletBatchId": wallet.batchId,
            "walletPubkey": wallet.pubkey,
            "walletCharacters": wallet.characters
        })

    def set_shadow_wallet_claim(self, shadow_wallet_claim) -> "AtomMeta":
        return self.merge({"shadowWalletClaim": shadow_wallet_claim * 1})

    def set_signing_wallet(self, signing_wallet: "Wallet") -> "AtomMeta":
        return self.merge({
            "signingWallet": dumps({
                "tokenSlug": signing_wallet.token,
                "bundleHash": signing_wallet.bundle,
                "address": signing_wallet.address,
                "position": signing_wallet.position,
                "pubkey": signing_wallet.pubkey,
                "characters": signing_wallet.characters
            })
        })

    def add_policy(self, policy: Dict) -> "AtomMeta":
        policy_meta = PolicyMeta(policy, list(self.meta.keys()))
        return self.merge(policy_meta.get())

    def get(self) -> Dict:
          return self.meta


class Atom(_Base):
    """class Atom"""

    position: str
    walletAddress: str
    isotope: str
    token: str | bytes | None
    value: str | bytes | None
    batchId: str | bytes | None
    metaType: str | bytes | None
    metaId: str | bytes | None
    meta: List[Dict[str, str | int | float]] | Dict[str, str | int | float]

    index: int
    otsFragment: str | bytes | None
    createdAt: str

    def __init__(self, position: str, wallet_address: str, isotope: str, token: str = None,
                 value: str | int | float | None = None, batch_id: str = None, meta_type: str = None,
                 meta_id: str = None,
                 meta: List[Dict[str, str | int | float]] | Dict[str, str | int | float] = None,
                 ots_fragment: str = None, index: int = None) -> None:
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
    def create(
        cls,
        isotope: str,
        wallet: 'Wallet' = None,
        value: str | int | float = None,
        meta_type: str = None,
        meta_id: str = None,
        meta: AtomMeta | dict = None,
        batch_id: str = None
    ):
        if meta is None:
            meta = AtomMeta()
        if isinstance(meta, dict):
            meta = AtomMeta(meta)
        if wallet is not None:
            meta.set_atom_wallet(wallet)
            if batch_id is None:
                batch_id = wallet.batchId

        return cls(
            position = wallet.position if wallet is not None else None,
            wallet_address = wallet.address if wallet is not None else None,
            isotope = isotope,
            token = wallet.token if wallet is not None else None,
            value = value,
            batch_id = batch_id,
            meta_type = meta_type,
            meta_id = meta_id,
            meta = meta.get()
        )

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
    def hash_atoms(cls, atoms: List['Atom'], output: str = 'base17') -> str | None | List:
        """
        :param atoms: List[Atom]
        :param output: str default base17
        :return: str | None | List
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

    def __init__(self,
                 secret: str = None,
                 bundle: str | bytes = None,
                 token: str = 'USER',
                 address: str | bytes = None,
                 position: str = None,
                 batch_id: str = None,
                 characters: str = None) -> None:

        self.token: str = token
        self.balance: int | float = 0
        self.molecules: List = []

        # Empty values
        self.key: str | bytes | None = None
        self.privkey: List[int] | None = None
        self.pubkey: str | bytes | None = None
        self.tokenUnits: List["TokenUnit"] = []
        self.tradeRates: Dict = {}

        self.address: str | None = address
        self.position: str | None = position
        self.bundle: str | None = bundle
        self.batchId: str | None = batch_id
        self.characters: str | None = characters or 'BASE64'

        if secret is not None:
            self.bundle = self.bundle or crypto.generate_bundle_hash(secret)
            self.position = self.position or Wallet.generate_position()
            self.key = Wallet.generate_key(secret, self.token, self.position)
            self.address = self.address or Wallet.generate_address(self.key)
            self.initialize_mlkem()

    def initialize_mlkem(self):
        public_key, secret_key = crypto.keypair_from_seed(self.key)
        self.pubkey, self.privkey = Wallet.serialize_key(public_key), list(secret_key)

    @classmethod
    def serialize_key(cls, key: bytes) -> str:
        return base64.b64encode(key).decode('utf-8')

    @classmethod
    def deserialize_key(cls, serialized_key: str) -> bytes:
        return base64.b64decode(serialized_key)

    def is_shadow(self) -> bool:
        """
        :return: bool
        """
        return self.position is None and self.address is None

    def get_token_units_data(self):
        return [tokenUnit.to_data() for tokenUnit in self.tokenUnits]

    def split_units(self, units: List, remainder_wallet: "Wallet" = None, recipient_wallet: "Wallet" = None):
        if not units:
            return
        recipient_token_units = [tokenUnit for tokenUnit in self.tokenUnits if tokenUnit.id in units]
        self.tokenUnits = recipient_token_units
        if recipient_wallet:
            recipient_wallet.tokenUnits = recipient_token_units
        remainder_wallet.tokenUnits = [tokenUnit for tokenUnit in self.tokenUnits if tokenUnit.id not in units]

    @classmethod
    def get_token_units(cls, units_datas: List):
        return [TokenUnit.create_from_db(unit_data) for unit_data in units_datas]

    @classmethod
    def create(cls, secret: str = None, bundle: str = None, token: str = 'USER', batch_id: str = None,
               characters: str = None):
        if not secret and not bundle:
            raise WalletCredentialException()

        position: str | None = None

        if secret and not bundle:
            position = cls.generate_position()
            bundle = crypto.generate_bundle_hash(secret)

        return Wallet(
            secret=secret,
            bundle=bundle,
            token=token,
            position=position,
            batch_id=batch_id,
            characters=characters
        )

    def create_remainder(self, secret: str):
        remainder_wallet = Wallet.create(secret, token=self.token, characters=self.characters)
        remainder_wallet.init_batch_id(self, is_remainder=True)
        return remainder_wallet

    @classmethod
    def generate_position(cls, salt_length: int = 64):
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
    def generate_address(cls, key: str) -> str:
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
        sponge.update(strings.encode(intermediate_key_sponge.hexdigest(1024)))

        return sponge.hexdigest(1024)

    def init_batch_id(self, source_wallet: "Wallet", is_remainder: bool = False) -> None:
        """
        :param source_wallet:
        :param is_remainder: bool
        :return:
        """
        if source_wallet.batchId is not None:
            self.batchId = source_wallet.batchId if is_remainder else crypto.generate_batch_id()

    @classmethod
    def encrypt_with_shared_secret(cls, message: bytes, shared_secret: bytes) -> bytes:
        iv = np.random.bytes(12)
        aesgcm = AESGCM(shared_secret)
        encrypted_content = aesgcm.encrypt(iv, message, None)
        return iv + encrypted_content

    def encrypt_message(self, message: Any, recipient_pubkey: str) -> Dict[str, str]:
        message_string = dumps(message)
        message_bytes = message_string.encode('utf-8')
        deserialized_pubkey = Wallet.deserialize_key(recipient_pubkey)
        shared_secret, cipher_text = crypto.ml_kem768.encapsulate(deserialized_pubkey, np.random.bytes(32))
        encrypted_message = Wallet.encrypt_with_shared_secret(message_bytes, shared_secret)
        return {
            "cipherText": Wallet.serialize_key(cipher_text),
            "encryptedMessage": Wallet.serialize_key(encrypted_message)
        }

    @classmethod
    def decrypt_with_shared_secret(cls, encrypted_message: bytes, shared_secret: bytes) -> bytes:
        iv = encrypted_message[:12]
        ciphertext = encrypted_message[12:]
        aesgcm = AESGCM(shared_secret)
        return aesgcm.decrypt(iv, ciphertext, None)

    def decrypt_message(self, encrypted_data: Dict[str, str]) -> Any:
        cipher_text, encrypted_message = (
            Wallet.deserialize_key(encrypted_data["cipherText"]),
            Wallet.deserialize_key(encrypted_data["encryptedMessage"])
        )
        shared_secret = crypto.ml_kem768.decapsulate(bytes(self.privkey), cipher_text)
        decrypted = Wallet.decrypt_with_shared_secret(encrypted_message, shared_secret)
        return loads(decrypted.decode('utf-8'))


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

    def __init__(
            self,
            secret: str = None,
            bundle: str = None,
            source_wallet: Wallet = None,
            remainder_wallet: Wallet = None,
            cell_slug: str = None
    ) -> None:
        """
        :param secret:
        :param source_wallet:
        :param remainder_wallet:
        :param cell_slug:
        """
        super(Molecule, self).__init__(cell_slug)
        self.clear()

        self.bundle: str | None = bundle
        self.__secret: str | None = secret
        self.sourceWallet: Wallet | None = source_wallet

        if remainder_wallet or source_wallet:
            self.remainderWallet = remainder_wallet if remainder_wallet is not None else Wallet.create(
                secret=secret,
                bundle=bundle,
                token=source_wallet.token,
                batch_id=source_wallet.batchId,
                characters=source_wallet.characters
            )

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

    def secret(self) -> str | None:
        """
        :return: str
        """
        return self.__secret

    def source_wallet(self) -> Wallet | None:
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
        atom.index = self.generate_index()
        self.atoms.append(atom)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self


    def encrypt_message(self, data, shared_wallets: list):
        args = [data, self.sourceWallet.pubkey]
        args.extend(shared_wallets)
        getattr(self.sourceWallet, 'encrypt_my_message')(*args)

    def final_metas(self, metas: List[Dict[str, str | int | float]] | Dict[str, str | int | float],
                    wallet: Wallet = None) -> List[Dict[str, str | int | float]] | Dict[str, str | int | float]:
        purse = wallet if wallet is not None else self.sourceWallet
        metas.update({'pubkey': purse.pubkey, 'characters': purse.characters})
        return metas

    def context_metas(self, metas: List[Dict[str, str | int | float]] | Dict[str, str | int | float],
                      context: str = None) -> List[Dict[str, str | int | float]] | Dict[str, str | int | float]:
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

    def add_continue_id_atom(self):
        self.add_atom(Atom.create(
            isotope = "I",
            wallet = self.remainderWallet,
            meta_type = "walletBundle",
            meta_id = self.remainderWallet.bundle

        ))
        return self

    def crate_rule(self, meta_type: str, meta_id: str | bytes | int,
                   meta: List[Dict[str, str | int | float]] | Dict[str, str | int | float]):
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

        self.add_continue_id_atom()
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def replenishing_tokens(self, value, token,
                            metas: List[Dict[str, str | int | float]] | Dict[str, str | int | float]):
        """
        :param value:
        :param token: str
        :param metas: List[Dict[str, str | int | float]] | Dict[str, str | int | float]
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

        self.add_continue_id_atom()
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

    def init_value(self, recipient: Wallet, value: int | float) -> 'Molecule':
        """
        Initialize a V-type molecule to transfer value from one wallet to another, with a third,
        regenerated wallet receiving the remainder

        :param recipient: Wallet
        :param value: int | float
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

        self.add_continue_id_atom()
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

        self.add_continue_id_atom()
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

        self.add_continue_id_atom()
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_token_creation(self, recipient: Wallet, amount: int | float,
                            token_meta: List | Dict) -> 'Molecule':
        """
        Initialize a C-type molecule to issue a new type of token

        :param recipient: Wallet
        :param amount: int | float
        :param token_meta: List | Dict
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

        self.add_continue_id_atom()
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

        self.add_continue_id_atom()
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def add_policy_atom(
        self,
        meta_type: str,
        meta_id: str,
        meta: Dict,
        policy: Dict
    ) -> 'Molecule':
        atom_meta = AtomMeta(meta)
        atom_meta.add_policy(policy)

        wallet = Wallet.create(
            secret=self.secret(),
            bundle=self.sourceWallet.bundle,
            token="USER"
        )

        self.add_atom(Atom.create(
            wallet=wallet,
            isotope="R",
            meta_type=meta_type,
            meta_id=meta_id,
            meta=atom_meta
        ))

        return self


    def init_meta(
        self,
        meta: Dict,
        meta_type: str,
        meta_id: str | int,
        policy: Dict = None
    ) -> 'Molecule':
        """
        Initialize an M-type molecule with the given data

        :param meta: List | Dict
        :param meta_type: str
        :param meta_id: str | int
        :param policy: Dict
        :return: self
        """
        self.add_atom(Atom.create(
            isotope = "M",
            wallet = self.sourceWallet,
            meta_type = meta_type,
            meta_id = meta_id,
            meta = AtomMeta(meta)
        ))

        self.add_policy_atom(
            meta_type = meta_type,
            meta_id = meta_id,
            meta = meta,
            policy = policy or {}
        )

        self.add_continue_id_atom()

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

    def init_token_request(self, token, requested_amount, meta_type, meta_id, meta: list | dict = None):
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

        self.add_continue_id_atom()
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

    def sign(self, anonymous: bool = False, compressed: bool = True) -> str | bytes | None:
        """
        Creates a one-time signature for a molecule and breaks it up across multiple atoms within that
        molecule. Resulting 4096 byte (2048 character) string is the one-time signature.

        :param anonymous: bool default False
        :param compressed: bool default True
        :return: str | bytes | None
        :raise TypeError: The molecule does not contain atoms
        """
        if len(self.atoms) == 0 or len([atom for atom in self.atoms if not isinstance(atom, Atom)]) != 0:
            raise AtomsMissingException()

        if not anonymous:
            self.bundle = crypto.generate_bundle_hash(self.secret())

        self.molecularHash = Atom.hash_atoms(self.atoms)
        self.atoms = Atom.sort_atoms(self.atoms)
        first_atom = self.atoms[0]
        key = Wallet.generate_key(
            secret=self.secret(),
            token=first_atom.token,
            position=first_atom.position
        )

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
