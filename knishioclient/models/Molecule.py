# -*- coding: utf-8 -*-

import math
import json
from typing import List, Dict, Any, Optional, Union
from json import JSONDecoder
from ..libraries import strings, decimal, crypto
from ..exception import *
from .base import Coder
from .MoleculeStructure import MoleculeStructure
from .Atom import Atom
from .AtomMeta import AtomMeta
from .Meta import Meta
from .Wallet import Wallet


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
        
        # Support deterministic testing with KNISHIO_FIXED_TIMESTAMP environment variable
        import os
        fixed_timestamp = os.getenv('KNISHIO_FIXED_TIMESTAMP')
        if fixed_timestamp:
            # Use fixed timestamp in milliseconds for deterministic testing
            self.createdAt = str(int(fixed_timestamp) * 1000)
        else:
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

    def to_json(
        self, 
        include_validation_context: bool = True, 
        include_ots_fragments: bool = True, 
        secure_mode: bool = False
    ) -> Dict[str, Any]:
        """
        Returns JSON-ready dictionary for cross-SDK compatibility (Python best practices)

        Includes all necessary fields for cross-SDK validation while excluding sensitive data.
        Follows JavaScript canonical patterns for perfect cross-platform compatibility.

        :param include_validation_context: Include sourceWallet/remainderWallet for validation (default: True)
        :param include_ots_fragments: Include OTS signature fragments (default: True)
        :param secure_mode: Extra security checks (default: False)
        :return: JSON-serializable dictionary
        :raises Exception: If molecule is in invalid state for serialization
        """
        try:
            # Core molecule properties (always included)
            serialized = {
                'status': self.status,
                'molecularHash': self.molecularHash,
                'createdAt': self.createdAt,
                'cellSlug': self.cellSlug,
                'cellSlugOrigin': getattr(self, 'cellSlugOrigin', None),
                'bundle': self.bundle,
                
                # Serialized atoms array with optional OTS fragments
                'atoms': [atom.to_json(include_ots_fragments) for atom in self.atoms]
            }

            # Validation context (essential for cross-SDK validation)
            if include_validation_context:
                if self.sourceWallet:
                    serialized['sourceWallet'] = {
                        'address': self.sourceWallet.address,
                        'position': self.sourceWallet.position,
                        'token': self.sourceWallet.token,
                        'balance': getattr(self.sourceWallet, 'balance', 0.0),
                        'bundle': self.sourceWallet.bundle,
                        'batchId': self.sourceWallet.batchId,
                        'characters': getattr(self.sourceWallet, 'characters', 'BASE64'),
                        # Exclude sensitive fields like secret, key, privkey
                        'pubkey': getattr(self.sourceWallet, 'pubkey', None),
                        'tokenUnits': getattr(self.sourceWallet, 'tokenUnits', []),
                        'tradeRates': {},
                        'molecules': {}
                    }

                if hasattr(self, 'remainderWallet') and self.remainderWallet:
                    serialized['remainderWallet'] = {
                        'address': self.remainderWallet.address,
                        'position': self.remainderWallet.position,
                        'token': self.remainderWallet.token,
                        'balance': getattr(self.remainderWallet, 'balance', 0.0),
                        'bundle': self.remainderWallet.bundle,
                        'batchId': self.remainderWallet.batchId,
                        'characters': getattr(self.remainderWallet, 'characters', 'BASE64'),
                        # Exclude sensitive fields
                        'pubkey': getattr(self.remainderWallet, 'pubkey', None),
                        'tokenUnits': getattr(self.remainderWallet, 'tokenUnits', []),
                        'tradeRates': {},
                        'molecules': {}
                    }

            return serialized

        except Exception as e:
            raise Exception(f"Molecule serialization failed: {str(e)}")

    @classmethod
    def from_json(
        cls,
        json_data: Union[str, Dict[str, Any]],
        include_validation_context: bool = True,
        validate_structure: bool = True
    ) -> 'Molecule':
        """
        Creates a Molecule instance from JSON data (Python best practices)

        Handles cross-SDK deserialization with robust error handling following
        JavaScript canonical patterns for perfect cross-platform compatibility.

        :param json_data: JSON string or dictionary to deserialize
        :param include_validation_context: Reconstruct sourceWallet/remainderWallet (default: True)
        :param validate_structure: Validate required fields (default: True)
        :return: Reconstructed molecule instance
        :raises Exception: If JSON is invalid or required fields are missing
        """
        try:
            # Parse JSON safely
            if isinstance(json_data, str):
                data = json.loads(json_data)
            else:
                data = json_data

            # Validate required fields in strict mode
            if validate_structure:
                if 'molecularHash' not in data or 'atoms' not in data:
                    raise ValueError("Invalid molecule data: missing molecularHash or atoms array")

            # Create minimal molecule instance (never include secret from JSON)
            molecule = cls(
                secret=None,
                bundle=data.get('bundle'),
                cell_slug=data.get('cellSlug')
            )

            # Populate core properties
            molecule.status = data.get('status')
            molecule.molecularHash = data.get('molecularHash')
            molecule.createdAt = data.get('createdAt', strings.current_time_millis())
            if 'cellSlugOrigin' in data:
                setattr(molecule, 'cellSlugOrigin', data['cellSlugOrigin'])

            # Reconstruct atoms array with proper Atom instances
            if 'atoms' in data and isinstance(data['atoms'], list):
                molecule.atoms = []
                
                for i, atom_data in enumerate(data['atoms']):
                    try:
                        atom = Atom.from_json(atom_data)
                        molecule.atoms.append(atom)
                    except Exception as e:
                        raise Exception(f"Failed to reconstruct atom {i}: {str(e)}")

            # Reconstruct validation context if available and requested
            if include_validation_context:
                if 'sourceWallet' in data and data['sourceWallet']:
                    sw_data = data['sourceWallet']
                    
                    # Create source wallet for validation (without secret for security)
                    source_wallet = Wallet(
                        secret=None,
                        token=sw_data.get('token', 'USER'),
                        position=sw_data.get('position'),
                        batch_id=sw_data.get('batchId'),
                        characters=sw_data.get('characters', 'BASE64')
                    )

                    # Set additional properties for validation context
                    source_wallet.balance = sw_data.get('balance', 0.0)
                    source_wallet.address = sw_data.get('address')
                    source_wallet.bundle = sw_data.get('bundle')
                    if 'pubkey' in sw_data:
                        source_wallet.pubkey = sw_data['pubkey']
                    
                    molecule.sourceWallet = source_wallet

                if 'remainderWallet' in data and data['remainderWallet']:
                    rw_data = data['remainderWallet']
                    
                    # Create remainder wallet for validation (without secret for security)
                    remainder_wallet = Wallet(
                        secret=None,
                        token=rw_data.get('token', 'USER'),
                        position=rw_data.get('position'),
                        batch_id=rw_data.get('batchId'),
                        characters=rw_data.get('characters', 'BASE64')
                    )

                    # Set additional properties for validation context
                    remainder_wallet.balance = rw_data.get('balance', 0.0)
                    remainder_wallet.address = rw_data.get('address')
                    remainder_wallet.bundle = rw_data.get('bundle')
                    if 'pubkey' in rw_data:
                        remainder_wallet.pubkey = rw_data['pubkey']

                    molecule.remainderWallet = remainder_wallet

            return molecule

        except Exception as e:
            raise Exception(f"Molecule deserialization failed: {str(e)}")

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
                float(self.sourceWallet.balance) - value,  # Correct remainder calculation
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
                -float(self.sourceWallet.balance),  # Debit full balance, not just transfer amount
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
                float(self.sourceWallet.balance) - value,  # Correct remainder calculation
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
            "tokenSlug": token_slug,
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
                self.final_metas(metas),
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
        meta,
        meta_type: str,
        meta_id,
        policy: Dict = None
    ) -> 'Molecule':
        """
        Initialize an M-type molecule with the given data

        :param meta: List or Dict
        :param meta_type: str
        :param meta_id: str or int
        :param policy: Dict
        :return: self
        """
        # Convert list to dict if necessary
        if isinstance(meta, list):
            meta_dict = {}
            for item in meta:
                if isinstance(item, dict) and 'key' in item and 'value' in item:
                    meta_dict[item['key']] = item['value']
        else:
            meta_dict = meta
            
        self.add_atom(Atom.create(
            isotope = "M",
            wallet = self.sourceWallet,
            meta_type = meta_type,
            meta_id = meta_id,
            meta = AtomMeta(meta_dict)
        ))

        # Only add policy atom if policy is provided and not empty (matching JavaScript)
        if policy and policy != {}:
            self.add_policy_atom(
                meta_type = meta_type,
                meta_id = meta_id,
                meta = meta_dict,
                policy = policy
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
                {**{
                    "pubkey": self.sourceWallet.pubkey,
                    "characters": self.sourceWallet.characters,
                }, **meta},
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

    def init_rule_creation(self, meta_type: str, meta_id: str, rule: list, policy: dict = None) -> 'Molecule':
        """
        Initialize molecule for rule creation
        
        :param meta_type: Meta type to attach rule to
        :param meta_id: Meta ID to attach rule to  
        :param rule: List of rule objects
        :param policy: Policy dict (optional)
        :return: self
        """
        self.molecularHash = None
        policy = policy or {}
        
        # Create atom meta with rules
        atom_meta = AtomMeta(
            data={'rule': json.dumps(rule)}
        )
        
        # Add policies to meta object
        if policy:
            atom_meta.add_policy(policy)
        
        # Create rule atom with isotope 'R'
        self.atoms.append(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'R',
                self.sourceWallet.token,
                meta_type,
                meta_id,
                value=None,
                metas=[atom_meta]
            )
        )
        
        # Add ContinuID atom
        self.add_continuid_atom()
        
        return self
    
    def init_deposit_buffer(self, amount: float, trade_rates: dict = None) -> 'Molecule':
        """
        Initialize molecule for depositing tokens to buffer
        
        :param amount: Amount to deposit to buffer
        :param trade_rates: Trade rates for the buffer wallet (optional)
        :return: self
        """
        from ..exception import BalanceInsufficientException
        
        if self.sourceWallet.balance - amount < 0:
            raise BalanceInsufficientException()
        
        # Create a buffer wallet
        buffer_wallet = Wallet.create(
            self.secret,
            self.sourceWallet.token,
            self.sourceWallet.batchId
        )
        if trade_rates:
            buffer_wallet.tradeRates = trade_rates
        
        # Remove tokens from source
        self.atoms.append(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'V',
                self.sourceWallet.token,
                value=-amount
            )
        )
        
        # Add tokens to buffer
        self.atoms.append(
            Atom(
                buffer_wallet.position,
                buffer_wallet.address,
                'B',
                self.sourceWallet.token,
                'walletBundle',
                self.sourceWallet.bundleHash,
                amount
            )
        )
        
        # Add remainder
        self.atoms.append(
            Atom(
                self.remainderWallet.position,
                self.remainderWallet.address,
                'V',
                self.sourceWallet.token,
                'walletBundle',
                self.sourceWallet.bundleHash,
                self.sourceWallet.balance - amount
            )
        )
        
        return self
    
    def init_withdraw_buffer(self, recipients: dict, signing_wallet=None) -> 'Molecule':
        """
        Initialize molecule for withdrawing tokens from buffer
        
        :param recipients: Dict of recipient_bundle: amount mappings
        :param signing_wallet: Optional signing wallet
        :return: self
        """
        from ..exception import BalanceInsufficientException
        
        # Calculate total amount
        amount = sum(recipients.values()) if recipients else 0
        
        if self.sourceWallet.balance - amount < 0:
            raise BalanceInsufficientException()
        
        # Set signing position for molecule reconciliation
        first_atom_meta = AtomMeta()
        if signing_wallet:
            first_atom_meta.set_signing_wallet(signing_wallet)
        
        # Remove tokens from source buffer
        self.atoms.append(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'B',
                self.sourceWallet.token,
                'walletBundle',
                self.sourceWallet.bundleHash,
                -amount,
                metas=[first_atom_meta] if signing_wallet else []
            )
        )
        
        # Add tokens to recipients
        for recipient_bundle, recipient_amount in (recipients or {}).items():
            self.atoms.append(
                Atom(
                    None,
                    None,
                    'V',
                    self.sourceWallet.token,
                    'walletBundle',
                    recipient_bundle,
                    recipient_amount,
                    self.sourceWallet.batchId
                )
            )
        
        # Add remainder to buffer
        self.atoms.append(
            Atom(
                self.remainderWallet.position,
                self.remainderWallet.address,
                'B',
                self.sourceWallet.token,
                'walletBundle',
                self.remainderWallet.bundleHash,
                self.sourceWallet.balance - amount
            )
        )
        
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
    
    def burn_token(self, amount: float, wallet_bundle=None):
        """
        Wrapper method for burning_tokens to match JavaScript naming convention
        
        :param amount: Amount to burn
        :param wallet_bundle: Optional wallet bundle
        :return: self for chaining
        """
        return self.burning_tokens(amount, wallet_bundle)
    
    def replenish_token(self, amount: float, token: str, 
                        metas: List[Dict[str, str | int | float]] | Dict[str, str | int | float]):
        """
        Wrapper method for replenishing_tokens to match JavaScript naming convention
        
        :param amount: Amount to replenish
        :param token: Token slug
        :param metas: Metadata for the operation
        :return: self for chaining
        """
        return self.replenishing_tokens(amount, token, metas)