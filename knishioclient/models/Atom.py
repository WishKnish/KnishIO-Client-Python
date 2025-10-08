# -*- coding: utf-8 -*-

import json
from typing import List, Dict, Union, Any, Optional
from hashlib import shake_256 as shake
from json import JSONDecoder, JSONDecodeError
from ..libraries import strings
from .base import Base
from .Meta import Meta
from .AtomMeta import AtomMeta


class Atom(Base):
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
        
        # Support deterministic testing with KNISHIO_FIXED_TIMESTAMP environment variable
        import os
        fixed_timestamp = os.getenv('KNISHIO_FIXED_TIMESTAMP')
        if fixed_timestamp:
            # Use fixed timestamp in milliseconds for deterministic testing
            self.createdAt = str(int(fixed_timestamp) * 1000)
        else:
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

    def to_json(
        self, 
        include_ots_fragments: bool = True, 
        validate_fields: bool = False
    ) -> Dict[str, Any]:
        """
        Returns JSON-ready dictionary for cross-SDK compatibility (Python best practices)
        
        Provides clean serialization of atomic operations with optional OTS fragments following
        JavaScript canonical patterns for perfect cross-platform compatibility.

        :param include_ots_fragments: Include OTS signature fragments (default: True)
        :param validate_fields: Validate required fields (default: False)
        :return: JSON-serializable dictionary
        :raises Exception: If atom is in invalid state for serialization
        """
        try:
            # Validate required fields if requested
            if validate_fields:
                required_fields = ['position', 'walletAddress', 'isotope', 'token']
                for field in required_fields:
                    field_value = getattr(self, field, None)
                    if not field_value:
                        raise ValueError(f"Required field '{field}' is missing or empty")

            # Core atom properties (always included)
            serialized = {
                'position': self.position,
                'walletAddress': self.walletAddress,
                'isotope': self.isotope,
                'token': self.token,
                'value': self.value,
                'batchId': self.batchId,
                'metaType': self.metaType,
                'metaId': self.metaId,
                'meta': self.meta if self.meta else [],
                'index': self.index,
                'createdAt': self.createdAt
            }

            # Optional OTS fragments (can be large, so optional)
            if include_ots_fragments and self.otsFragment:
                serialized['otsFragment'] = self.otsFragment

            return serialized

        except Exception as e:
            raise Exception(f"Atom serialization failed: {str(e)}")

    @classmethod
    def from_json(
        cls,
        json_data: Union[str, Dict[str, Any]],
        validate_structure: bool = True,
        strict_mode: bool = False
    ) -> 'Atom':
        """
        Creates an Atom instance from JSON data (Python best practices)
        
        Handles cross-SDK atom deserialization with robust error handling following
        JavaScript canonical patterns for perfect cross-platform compatibility.

        :param json_data: JSON string or dictionary to deserialize
        :param validate_structure: Validate required fields (default: True)
        :param strict_mode: Strict validation mode (default: False)
        :return: Reconstructed atom instance
        :raises Exception: If JSON is invalid or required fields are missing
        """
        try:
            # Parse JSON safely
            if isinstance(json_data, str):
                data = json.loads(json_data)
            else:
                data = json_data

            # Validate required fields in strict mode
            if strict_mode or validate_structure:
                required_fields = ['position', 'walletAddress', 'isotope', 'token']
                for field in required_fields:
                    if field not in data or not data[field]:
                        raise ValueError(f"Required field '{field}' is missing or empty")

            # Create atom instance with required fields
            atom = cls(
                position=data.get('position', ''),
                wallet_address=data.get('walletAddress', ''),
                isotope=data.get('isotope', 'V'),
                token=data.get('token', ''),
                value=data.get('value'),
                batch_id=data.get('batchId'),
                meta_type=data.get('metaType'),
                meta_id=data.get('metaId'),
                meta=data.get('meta', []),
                index=data.get('index', 0)
            )

            # Set additional properties that may not be in constructor
            if 'otsFragment' in data and data['otsFragment']:
                atom.otsFragment = data['otsFragment']
            if 'createdAt' in data and data['createdAt']:
                atom.createdAt = data['createdAt']

            return atom

        except Exception as e:
            raise Exception(f"Atom deserialization failed: {str(e)}")

    @classmethod
    def hash_atoms(cls, atoms: List['Atom'], output: str = 'base17') -> str | None | List:
        """
        Generate molecular hash from atoms using proven C SDK pattern for cross-platform compatibility.
        
        :param atoms: List[Atom]
        :param output: str default base17
        :return: str | None | List
        """
        atom_list = Atom.sort_atoms(atoms)
        molecular_sponge = shake()
        atom_count_str = str(len(atom_list))

        # Process each atom following the exact C SDK pattern
        for atom in atom_list:
            # Add atom count for each atom (matching C SDK update_sponge_with_atom)
            molecular_sponge.update(strings.encode(atom_count_str))

            # Add properties in exact order from C SDK:
            # position, walletAddress, isotope, token, value, batchId, metaType, metaId, meta (keys/values), createdAt
            
            # Position (always include - required field)
            if atom.position:
                molecular_sponge.update(strings.encode(atom.position))
            
            # WalletAddress (always include - required field) 
            if atom.walletAddress:
                molecular_sponge.update(strings.encode(atom.walletAddress))
            
            # Isotope as string (always include)
            molecular_sponge.update(strings.encode(atom.isotope))
            
            # Token (only if not None per C SDK)
            if atom.token:
                molecular_sponge.update(strings.encode(atom.token))
            
            # Value (only if not None per C SDK)
            if atom.value:
                molecular_sponge.update(strings.encode(str(atom.value)))
            
            # BatchId (only if not None per C SDK)
            if atom.batchId:
                molecular_sponge.update(strings.encode(atom.batchId))
            
            # MetaType (only if not None per C SDK)
            if atom.metaType:
                molecular_sponge.update(strings.encode(atom.metaType))
            
            # MetaId (only if not None per C SDK)
            if atom.metaId:
                molecular_sponge.update(strings.encode(atom.metaId))
            
            # Meta keys and values (matching C SDK pattern)
            if atom.meta:
                normalized_meta = Meta.normalize_meta(atom.meta) if atom.meta else []
                for meta_item in normalized_meta:
                    if meta_item and meta_item.get('key') is not None and meta_item.get('value') is not None:
                        molecular_sponge.update(strings.encode(str(meta_item['key'])))
                        molecular_sponge.update(strings.encode(str(meta_item['value'])))
            
            # CreatedAt as string (milliseconds since epoch, matching C SDK)
            if atom.createdAt:
                # Ensure createdAt is in milliseconds format like C SDK
                created_at_ms = atom.createdAt
                if len(str(created_at_ms)) <= 10:  # Looks like seconds, convert to ms
                    created_at_ms = str(int(created_at_ms) * 1000)
                molecular_sponge.update(strings.encode(str(created_at_ms)))

        target = None

        if output in ['hex']:
            target = molecular_sponge.hexdigest(32)
        elif output in ['array']:
            target = list(molecular_sponge.hexdigest(32))
        elif output in ['base17']:
            hex_hash = molecular_sponge.hexdigest(32)
            target = strings.charset_base_convert(
                hex_hash, 16, 17, '0123456789abcdef', '0123456789abcdefg'
            )

            # Ensure base17 result is exactly 64 characters with proper padding (matching C SDK)
            if isinstance(target, str):
                target = target.rjust(64, '0')

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