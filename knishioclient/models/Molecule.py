# -*- coding: utf-8 -*-

import math
import json
from typing import List, Dict, Any, Union
from json import JSONDecoder
from ..libraries import strings, decimal, crypto
from ..exception import *
from .base import Coder
from .MoleculeStructure import MoleculeStructure
from .Atom import Atom
from .AtomMeta import AtomMeta
from .Rule import Rule
from .Meta import Meta
from .Wallet import Wallet
from .TokenUnit import TokenUnit

# Hash versions a molecule can be built at (JS src/versions/index.js); any other version is ignored,
# as in JS, and the molecule hashes with the legacy scheme.
SUPPORTED_VERSIONS = ('4',)


class Molecule(MoleculeStructure):
    """class Molecule"""

    createdAt: str

    def __init__(
            self,
            secret: str = None,
            bundle: str = None,
            source_wallet: Wallet = None,
            remainder_wallet: Wallet = None,
            cell_slug: str = None,
            continu_id_position: str = None,
            mlkem_param_set: int = None,
            min_ots_version: int = 1,
            version: str | int = None
    ) -> None:
        """
        :param secret:
        :param source_wallet:
        :param remainder_wallet:
        :param cell_slug:
        :param min_ots_version: lowest OTS version (1 or 2) for the wallets this molecule creates
            for its signer; see successor_ots_version()
        :param version: hash version (JS Molecule ``version``): "4" puts every atom on Version 4;
            any value the SDK does not know is ignored
        """
        super(Molecule, self).__init__(cell_slug)
        self.clear()

        self.bundle: str | None = bundle
        self.__secret: str | None = secret
        self.sourceWallet: Wallet | None = source_wallet
        self.continuIdPosition: str | None = continu_id_position
        self.minOtsVersion: int = Wallet.checked_ots_version(min_ots_version)
        self.parentHashes: List[str] = []
        self.version: str | None = str(version) if version is not None and str(version) in SUPPORTED_VERSIONS \
            else None

        self.mlkem_param_set = mlkem_param_set or (source_wallet.mlkem_param_set if source_wallet and hasattr(source_wallet, 'mlkem_param_set') else 1024)
        if remainder_wallet or source_wallet:
            self.remainderWallet = remainder_wallet if remainder_wallet is not None else Wallet.create(
                secret=secret,
                bundle=bundle,
                token=source_wallet.token,
                batch_id=source_wallet.batchId,
                characters=source_wallet.characters,
                mlkem_param_set=self.mlkem_param_set,
                ots_version=self.successor_ots_version()
            )

    def with_parent_hashes(self, hashes: List[str]) -> 'Molecule':
        """
        Sets the parent molecular hashes (DAG linkage), as JS ``withParentHashes``.

        :param hashes: List[str]
        :return: self
        """
        self.parentHashes = list(hashes) if isinstance(hashes, (list, tuple)) else []
        return self

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
        atom.version = self.version
        self.atoms.append(atom)
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

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

            # Parent molecular hashes, only when there are any (JS toJSON)
            if self.parentHashes:
                serialized['parentHashes'] = list(self.parentHashes)

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
            molecule.parentHashes = list(data['parentHashes']) if isinstance(data.get('parentHashes'), list) else []
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
                        characters=sw_data.get('characters', 'BASE64'),
                        mlkem_param_set=molecule.mlkem_param_set
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
                        characters=rw_data.get('characters', 'BASE64'),
                        mlkem_param_set=molecule.mlkem_param_set
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
        # Mirror the JS reference (Molecule.js addContinuIdAtom): the ContinuID I-atom registers a
        # USER wallet (a missing or non-USER remainder is replaced) and carries previousPosition plus
        # the remainder wallet's pubkey/characters.
        remainder = getattr(self, 'remainderWallet', None)
        if remainder is None or remainder.token != 'USER':
            if not self.secret():
                raise WalletCredentialException('KnishIO: a ContinuID remainder needs the molecule secret.')
            self.remainderWallet = Wallet.create(
                secret=self.secret(),
                bundle=self.bundle,
                mlkem_param_set=self.mlkem_param_set,
                ots_version=self.successor_ots_version()
            )

        continu_id_meta: Dict[str, Any] = {}
        previous_position = getattr(self, 'continuIdPosition', None) or (
            self.sourceWallet.position if self.sourceWallet is not None else None
        )
        if previous_position:
            continu_id_meta['previousPosition'] = previous_position
        if self.remainderWallet.pubkey:
            continu_id_meta['pubkey'] = self.remainderWallet.pubkey
        if self.remainderWallet.characters:
            continu_id_meta['characters'] = self.remainderWallet.characters

        self.add_atom(Atom.create(
            isotope = "I",
            wallet = self.remainderWallet,
            meta_type = "walletBundle",
            meta_id = self.remainderWallet.bundle,
            meta = continu_id_meta
        ))
        return self

    @classmethod
    def token_units_data(cls, units: List) -> List:
        """Normalise a unit list (TokenUnit, [id, name, metas] triple or bare id) to triples."""
        normalised = []
        for unit in units or []:
            if isinstance(unit, TokenUnit):
                normalised.append(unit.to_data())
            elif isinstance(unit, (list, tuple)):
                normalised.append(TokenUnit.create_from_db(list(unit)).to_data())
            else:
                normalised.append([unit, unit, {}])
        return normalised

    def replenishing_tokens(self, value, token: str, recipient_wallet: Wallet, units: List = None) -> 'Molecule':
        """
        Contract 9.1: mint more supply of an EXISTING token with a C atom signed by the source
        (USER) wallet, crediting ``recipient_wallet`` (the identity's wallet for the token), then
        the ContinuID I atom. Stackable / non-fungible replenishes carry the new units and their
        count is the value.

        :param value: int | float | None - the amount (fungible); None or len(units) with units
        :param token: str - the token slug
        :param recipient_wallet: Wallet - the credited wallet
        :param units: list - the new token units (triples, TokenUnit objects or ids)
        :return: self
        """
        units_data = Molecule.token_units_data(units)
        if units_data:
            if value is not None and decimal.cmp(float(value), float(len(units_data))) != 0:
                raise StackableUnitAmountException(
                    'Replenish amount must be omitted or equal the number of token units'
                )
            value = len(units_data)
        if value is None or decimal.cmp(float(value), 0.0) <= 0:
            raise NegativeMeaningException('Amount to replenish must be positive')

        self.molecularHash = None

        metas = {
            'action': 'add',
            'address': recipient_wallet.address,
            'position': recipient_wallet.position,
            'pubkey': recipient_wallet.pubkey,
        }
        if recipient_wallet.batchId:
            metas['batchId'] = recipient_wallet.batchId
        if units_data:
            metas['tokenUnits'] = strings.js_json_stringify(units_data)

        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'C',
                self.sourceWallet.token,
                value,
                recipient_wallet.batchId,
                'token',
                token,
                metas,
                None,
                self.generate_index()
            )
        )

        self.add_continue_id_atom()
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_token_fusion(self, fused_token_unit_ids: List[str], recipient_wallet: Wallet,
                          new_token_unit: 'str | TokenUnit') -> 'Molecule':
        """
        Contract 9.2: fuse M >= 2 units of the source's stackable token into ONE new unit N
        delivered to ``recipient_wallet``. Atoms: source V (-B, the fused units in source order),
        burn V (+(M-1), the fused units but the last, caller order), F (+1, [N] with
        fusedTokenUnits = the fused triples in caller order), remainder V (+(B-M), the kept units).
        No ContinuID atom: the molecule is signed by the source token wallet, like a transfer.

        :param fused_token_unit_ids: list[str] - the unit ids to fuse, caller order
        :param recipient_wallet: Wallet - receives N
        :param new_token_unit: str | TokenUnit - N (a string id also becomes its name)
        :return: self
        """
        if len(fused_token_unit_ids) < 2:
            raise TransferBalanceException('Token fusion requires at least two token units')

        source_units = list(self.sourceWallet.tokenUnits)
        source_by_id = {unit.id: unit for unit in source_units}
        for unit_id in fused_token_unit_ids:
            if unit_id not in source_by_id:
                raise TransferBalanceException(
                    f'Fused token unit ID = {unit_id} not found in the source wallet.'
                )

        if isinstance(new_token_unit, str):
            new_token_unit = TokenUnit(new_token_unit, new_token_unit, {})
        if new_token_unit.id in source_by_id:
            raise TransferBalanceException('Token fusion unit id already exists in the source wallet')

        balance = float(self.sourceWallet.balance)
        fused_count = len(fused_token_unit_ids)
        if decimal.cmp(balance, float(fused_count)) < 0:
            raise BalanceInsufficientException()

        fused_units = [source_by_id[unit_id] for unit_id in fused_token_unit_ids]

        burn_wallet = Wallet(
            bundle='0000000000000000000000000000000000000000000000000000000000000000',
            token=self.sourceWallet.token,
            mlkem_param_set=self.mlkem_param_set
        )
        burn_wallet.init_batch_id(self.sourceWallet)
        burn_wallet.tokenUnits = fused_units[:-1]

        new_token_unit.metas = {
            **new_token_unit.metas,
            'fusedTokenUnits': [unit.to_data() for unit in fused_units],
        }
        recipient_wallet.tokenUnits = [new_token_unit]

        # SENT (source order) on the source atom; KEPT (source order) on the remainder atom
        self.sourceWallet.tokenUnits = [unit for unit in source_units if unit.id in fused_token_unit_ids]
        self.remainderWallet.tokenUnits = [unit for unit in source_units if unit.id not in fused_token_unit_ids]

        self.molecularHash = None

        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'V',
                self.sourceWallet.token,
                -balance,
                self.sourceWallet.batchId,
                None,
                None,
                AtomMeta({}).set_atom_wallet(self.sourceWallet).get(),
                None,
                self.generate_index()
            )
        )
        self.add_atom(
            Atom(
                burn_wallet.position,
                burn_wallet.address,
                'V',
                self.sourceWallet.token,
                fused_count - 1,
                burn_wallet.batchId,
                'walletBundle',
                burn_wallet.bundle,
                AtomMeta({}).set_atom_wallet(burn_wallet).get(),
                None,
                self.generate_index()
            )
        )
        self.add_atom(
            Atom(
                recipient_wallet.position,
                recipient_wallet.address,
                'F',
                self.sourceWallet.token,
                1,
                recipient_wallet.batchId,
                'walletBundle',
                recipient_wallet.bundle,
                AtomMeta({}).set_atom_wallet(recipient_wallet).get(),
                None,
                self.generate_index()
            )
        )
        self.add_atom(
            Atom(
                self.remainderWallet.position,
                self.remainderWallet.address,
                'V',
                self.sourceWallet.token,
                balance - fused_count,
                self.remainderWallet.batchId,
                'walletBundle',
                self.remainderWallet.bundle,
                AtomMeta({}).set_atom_wallet(self.remainderWallet).get(),
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def burning_tokens(self, value, wallet_bundle=None):
        # wallet_bundle is vestigial (JS parity): the burn always targets the all-zeros bundle.
        if value < 0.0:
            raise NegativeMeaningException('It is impossible to use a negative value for the number of tokens')

        if decimal.cmp(0.0, float(self.sourceWallet.balance) - value) > 0:
            raise BalanceInsufficientException()

        self.molecularHash = None

        # Burn-address wallet: the all-zeros bundle = token destruction. No secret, so it has
        # no position/address (the Coder wire coerces null -> "" and hash_atoms skips falsy);
        # the validator credits the burn amount to this unspendable bundle, satisfying V-isotope
        # conservation (sum == 0) while permanently destroying the tokens. Mirrors JS burnToken
        # + the sibling init_value (3 V-atoms, no pubkey/characters meta).
        burn_wallet = Wallet(
            bundle='0000000000000000000000000000000000000000000000000000000000000000',
            token=self.sourceWallet.token,
            mlkem_param_set=self.mlkem_param_set
        )

        # V-atom 1: debit the ENTIRE source balance (UTXO model). Must be -balance (not -value):
        # the burn target gets +value and the remainder +(balance-value), so the three V-atoms
        # sum to zero (validator requires exactly 3 V-atoms + sum == 0).
        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'V',
                self.sourceWallet.token,
                -float(self.sourceWallet.balance),
                self.sourceWallet.batchId,
                None,
                None,
                AtomMeta({}).set_atom_wallet(self.sourceWallet).get(),  # stackable: tokenUnits (BURNED); fungible -> {}
                None,
                self.generate_index()
            )
        )

        # V-atom 2: credit the burn amount to the all-zeros burn address (destruction)
        self.add_atom(
            Atom(
                burn_wallet.position,
                burn_wallet.address,
                'V',
                self.sourceWallet.token,
                float(value),
                burn_wallet.batchId,
                'walletBundle',
                burn_wallet.bundle,
                {},
                None,
                self.generate_index()
            )
        )

        # V-atom 3: remainder back to the source identity
        self.add_atom(
            Atom(
                self.remainderWallet.position,
                self.remainderWallet.address,
                'V',
                self.sourceWallet.token,
                float(self.sourceWallet.balance) - value,
                self.remainderWallet.batchId,
                'walletBundle',
                self.remainderWallet.bundle,
                AtomMeta({}).set_atom_wallet(self.remainderWallet).get(),  # stackable: tokenUnits (KEPT); fungible -> {}
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

        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'V',
                self.sourceWallet.token,
                -float(self.sourceWallet.balance),  # Debit full balance, not just transfer amount
                self.sourceWallet.batchId,
                None,
                None,
                AtomMeta({}).set_atom_wallet(self.sourceWallet).get(),  # stackable: tokenUnits (SENT); fungible -> {} (frozen-hash-safe)
                None,
                self.generate_index()
            )
        )

        self.add_atom(
            Atom(
                recipient.position,
                recipient.address,
                'V',
                self.sourceWallet.token,
                value,
                recipient.batchId,
                'walletBundle',
                recipient.bundle,
                AtomMeta({}).set_atom_wallet(recipient).get(),  # stackable: tokenUnits (SENT); fungible -> {}
                None,
                self.generate_index()
            )
        )

        self.add_atom(
            Atom(
                self.remainderWallet.position,
                self.remainderWallet.address,
                'V',
                self.sourceWallet.token,
                float(self.sourceWallet.balance) - value,  # Correct remainder calculation
                self.remainderWallet.batchId,
                'walletBundle',
                self.remainderWallet.bundle,
                AtomMeta({}).set_atom_wallet(self.remainderWallet).get(),  # stackable: tokenUnits (KEPT); fungible -> {}
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_values(self, recipient_wallets: list, amounts: list) -> 'Molecule':
        """
        Initialize a MULTI-recipient V-type molecule: one source debits its FULL balance to fund
        N recipients (each its own amount + stackable units) plus a remainder back to the sender.
        Multi-recipient sibling of init_value (WP line 544: fund multiple recipients with one
        transaction). recipient_wallets is parallel to amounts.

        :param recipient_wallets: list[Wallet]
        :param amounts: list[int | float]
        :return: self
        """

        total = sum(float(amount) for amount in amounts)

        if decimal.cmp(total, float(self.sourceWallet.balance)) > 0:
            raise BalanceInsufficientException()

        self.molecularHash = None

        # Source atom: debit the ENTIRE balance (UTXO drain); carries the SENT union of token units
        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'V',
                self.sourceWallet.token,
                -float(self.sourceWallet.balance),
                self.sourceWallet.batchId,
                None,
                None,
                AtomMeta({}).set_atom_wallet(self.sourceWallet).get(),  # stackable: tokenUnits (SENT union)
                None,
                self.generate_index()
            )
        )

        # One atom per recipient: +amount_i, walletBundle -> recipient bundle, its own SENT units
        for recipient, amount in zip(recipient_wallets, amounts):
            self.add_atom(
                Atom(
                    recipient.position,
                    recipient.address,
                    'V',
                    self.sourceWallet.token,
                    amount,
                    recipient.batchId,
                    'walletBundle',
                    recipient.bundle,
                    AtomMeta({}).set_atom_wallet(recipient).get(),  # stackable: tokenUnits (this recipient's SENT)
                    None,
                    self.generate_index()
                )
            )

        # Remainder atom: +(balance - total), walletBundle -> sender bundle, KEPT units
        self.add_atom(
            Atom(
                self.remainderWallet.position,
                self.remainderWallet.address,
                'V',
                self.sourceWallet.token,
                float(self.sourceWallet.balance) - total,
                self.remainderWallet.batchId,
                'walletBundle',
                self.remainderWallet.bundle,
                AtomMeta({}).set_atom_wallet(self.remainderWallet).get(),  # stackable: tokenUnits (KEPT)
                None,
                self.generate_index()
            )
        )

        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_wallet_creation(self, new_wallet: Wallet):
        # Cross-SDK parity (cycle 28): mirror JS initWalletCreation — the C-atom meta is the 7
        # PREFIXED wallet* keys via setMetaWallet (no unprefixed pubkey/characters), and the
        # C-atom batchId is the NEW wallet's (was sourceWallet's). The ContinuID I-atom follows.
        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                "C",
                self.sourceWallet.token,
                None,
                new_wallet.batchId,
                "wallet",
                new_wallet.address,
                AtomMeta({}).set_meta_wallet(new_wallet).get(),
                None,
                self.generate_index()
            )
        )

        self.add_continue_id_atom()
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_peering(self, host: str) -> 'Molecule':
        """
        Initialize a P-type molecule registering a peer (JS ``initPeering``): a P atom from the
        source wallet bound to this molecule's bundle with meta ``peerHost``, then ContinuID.

        :param host: str - the peer host URL
        :return: self
        """
        self.add_atom(Atom.create(
            isotope='P',
            wallet=self.sourceWallet,
            meta_type='walletBundle',
            meta_id=self.bundle,
            meta=AtomMeta({'peerHost': host})
        ))

        self.add_continue_id_atom()

        return self

    def init_identifier_creation(self, type0: str, contact: str, code: str) -> 'Molecule':
        """
        Initialize a C-type molecule to issue a new type of identifier (JS
        ``initIdentifierCreation``): meta ``code`` and ``hash`` = bundle hash of the trimmed contact.

        :param type0: str
        :param contact: str
        :param code: str
        :return: self
        """
        self.add_atom(Atom.create(
            isotope='C',
            wallet=self.sourceWallet,
            meta_type='identifier',
            meta_id=type0,
            meta=AtomMeta({
                'code': code,
                'hash': crypto.generate_bundle_hash(contact.strip())
            })
        ))

        self.add_continue_id_atom()

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

        # Cross-SDK parity (2026-06-15, cycle 22): mirror the JS reference
        # `new AtomMeta(meta).setMetaWallet(recipientWallet)` — the C-atom carries the
        # user token meta followed by the 7 PREFIXED wallet* keys (walletTokenSlug,
        # walletBundleHash, walletAddress, walletPosition, walletBatchId, walletPubkey,
        # walletCharacters) in insertion order, with no unprefixed pubkey/characters and no
        # unprefixed walletAddress/Position.
        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'C',
                self.sourceWallet.token,
                amount,
                recipient.batchId,
                'token',
                recipient.token,
                AtomMeta(Meta.aggregate_meta(metas)).set_meta_wallet(recipient).get(),
                None,
                self.generate_index()
            )
        )

        self.add_continue_id_atom()
        self.atoms = Atom.sort_atoms(self.atoms)

        return self

    def init_shadow_wallet_claim(self, wallet: Wallet):
        # Cross-SDK parity (cycle 28): mirror JS initShadowWalletClaim — meta = shadowWalletClaim
        # THEN the 7 PREFIXED wallet* keys via setMetaWallet (NO tokenSlug; the token is carried by
        # walletTokenSlug). The C-atom batchId is the claimed wallet's.
        self.molecularHash = None

        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                "C",
                self.sourceWallet.token,
                None,
                wallet.batchId,
                'wallet',
                wallet.address,
                AtomMeta({}).set_shadow_wallet_claim(True).set_meta_wallet(wallet).get(),
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

        # F-3 (cross-SDK parity, 2026-06-03): sign the policy (R-isotope) atom from the
        # established ContinuID source wallet, NOT a freshly-created Wallet.create() at a
        # random position. As the signing atom in createPolicy(), a fresh-wallet position
        # is unknown to the validator -> "ContinuID chain validation failed: signing
        # position ... not found as wallet". Mirrors init_rule_creation, which uses
        # self.sourceWallet.
        self.add_atom(Atom.create(
            wallet=self.sourceWallet,
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

    def init_append_request(self, meta_type: str, meta_id: str, action: str, meta: Dict = None) -> 'Molecule':
        """
        Initialize an A-type molecule for an append request (JS ``initAppendRequest``): an A atom
        from the source wallet with meta ``action`` followed by ``meta``, then ContinuID.

        :param meta_type: str - the target MetaType
        :param meta_id: str - the target MetaId
        :param action: str - the action to perform
        :param meta: dict - additional metadata
        :return: self
        """
        self.add_atom(Atom.create(
            isotope='A',
            wallet=self.sourceWallet,
            meta_type=meta_type,
            meta_id=meta_id,
            meta=AtomMeta({'action': action, **(meta or {})})
        ))

        self.add_continue_id_atom()

        return self

    def init_token_request(self, token, requested_amount, meta_type, meta_id, meta: list | dict = None,
                           batch_id: str = None) -> 'Molecule':
        """
        Arrange a T atom requesting tokens from the node (JS ``initTokenRequest``): the meta gains
        ``token`` and ``amount`` (the amount as JS ``String()`` writes it), then ContinuID.

        :param token: str - the token slug
        :param requested_amount: int | float
        :param meta_type: str
        :param meta_id: str
        :param meta: dict | list - additional metadata
        :param batch_id: str | None
        :return: self
        """
        # JS assigns meta.token / meta.amount on the meta object (an existing key keeps its place)
        additions = {'token': token, 'amount': strings.js_string(requested_amount)}
        if isinstance(meta, list):
            atom_meta = AtomMeta(meta).merge(additions)
        else:
            atom_meta = AtomMeta({**(meta or {}), **additions})

        self.add_atom(Atom.create(
            isotope='T',
            wallet=self.sourceWallet,
            value=requested_amount,
            meta_type=meta_type,
            meta_id=meta_id,
            meta=atom_meta,
            batch_id=batch_id
        ))

        self.add_continue_id_atom()

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

        # JS Molecule.createRule: normalise through Rule.toObject, serialise like JSON.stringify,
        # and always add the policy (JS defaults it to {}, which still fills per-key defaults).
        rules = [item if isinstance(item, Rule) else Rule.to_object(item) for item in rule]
        atom_meta = AtomMeta({'rule': strings.js_json_stringify([item.to_json() for item in rules])})
        atom_meta.add_policy(policy or {})

        self.add_atom(Atom.create(
            wallet=self.sourceWallet,
            isotope='R',
            meta_type=meta_type,
            meta_id=meta_id,
            meta=atom_meta
        ))

        self.add_continue_id_atom()

        return self
    
    def init_deposit_buffer(self, amount: float, trade_rates=None) -> 'Molecule':
        """
        Initialize molecule for depositing tokens to buffer (JS ``initDepositBuffer``): source V
        (-balance), buffer B (+amount) bound to the source bundle, remainder V (+change). Every
        atom is built with ``Atom.create``, so its meta is what JS ``AtomMeta.setAtomWallet`` gives.

        :param amount: Amount to deposit to buffer
        :param trade_rates: Trade rates for the buffer wallet (optional)
        :return: self
        """
        if self.sourceWallet.balance - amount < 0:
            raise BalanceInsufficientException()

        buffer_wallet = Wallet.create(
            secret=self.secret(),
            bundle=self.bundle,
            token=self.sourceWallet.token,
            batch_id=self.sourceWallet.batchId,
            mlkem_param_set=self.mlkem_param_set,
            ots_version=self.successor_ots_version()
        )
        if trade_rates is not None:
            buffer_wallet.tradeRates = trade_rates

        # Debit the FULL balance; the change goes to the remainder atom so V+B sum to 0
        self.add_atom(Atom.create(
            isotope='V',
            wallet=self.sourceWallet,
            value=-self.sourceWallet.balance
        ))

        self.add_atom(Atom.create(
            isotope='B',
            wallet=buffer_wallet,
            value=amount,
            meta_type='walletBundle',
            meta_id=self.sourceWallet.bundle
        ))

        self.add_atom(Atom.create(
            isotope='V',
            wallet=self.remainderWallet,
            value=self.sourceWallet.balance - amount,
            meta_type='walletBundle',
            meta_id=self.sourceWallet.bundle
        ))

        return self
    
    def init_withdraw_buffer(self, recipients: dict) -> 'Molecule':
        """
        Contract 9.6: withdraw from the buffer wallet S (the molecule's source). Atoms: B S
        (-S.balance), one addressless V (+amount) per recipient bundle (a fresh batch id only when S
        has one), and the B remainder (+(S.balance - amount)) on the molecule's remainder wallet,
        which must be S.create_remainder(secret): a FRESH position, never S's own (a credit behind
        the consumed signing key is stranded; validator 0.6.1 rejects it). No ContinuID atom.

        :param recipients: Dict of recipient_bundle: amount mappings
        :return: self
        """
        amount = sum(recipients.values()) if recipients else 0

        if decimal.cmp(float(self.sourceWallet.balance), float(amount)) < 0:
            raise BalanceInsufficientException()

        self.molecularHash = None

        self.add_atom(
            Atom(
                self.sourceWallet.position,
                self.sourceWallet.address,
                'B',
                self.sourceWallet.token,
                -float(self.sourceWallet.balance),
                self.sourceWallet.batchId,
                'walletBundle',
                self.sourceWallet.bundle,
                AtomMeta({}).set_atom_wallet(self.sourceWallet).get(),
                None,
                self.generate_index()
            )
        )

        for recipient_bundle, recipient_amount in (recipients or {}).items():
            self.add_atom(
                Atom(
                    None,
                    None,
                    'V',
                    self.sourceWallet.token,
                    recipient_amount,
                    crypto.generate_batch_id() if self.sourceWallet.batchId else None,
                    'walletBundle',
                    recipient_bundle,
                    None,
                    None,
                    self.generate_index()
                )
            )

        self.add_atom(
            Atom(
                self.remainderWallet.position,
                self.remainderWallet.address,
                'B',
                self.sourceWallet.token,
                float(self.sourceWallet.balance) - amount,
                self.remainderWallet.batchId,
                'walletBundle',
                self.remainderWallet.bundle,
                AtomMeta({}).set_atom_wallet(self.remainderWallet).get(),
                None,
                self.generate_index()
            )
        )

        return self
    
    def init_authorization(self, meta: Dict = None) -> 'Molecule':
        """
        Arrange a U atom requesting an authorization token (JS ``initAuthorization``), then
        ContinuID. The client passes ``{'encrypt': 'true'|'false', 'walletPubkey': <pubkey>}``:
        the requested transport mode and the source wallet's ML-KEM public key travel signed.

        :param meta: dict
        :return: self
        """
        self.add_atom(Atom.create(
            isotope='U',
            wallet=self.sourceWallet,
            meta=AtomMeta(meta if meta is not None else {})
        ))

        self.add_continue_id_atom()

        return self

    def signing_ots_version(self) -> int:
        """
        OTS version used to sign this molecule: the source wallet's version, or 1 without a source wallet.

        :return: int
        """
        source_wallet = getattr(self, 'sourceWallet', None)
        return getattr(source_wallet, 'ots_version', 1) if source_wallet is not None else 1

    def successor_ots_version(self) -> int:
        """
        OTS version of the wallets this molecule creates for its signer (remainder, ContinuID,
        buffer): the higher of the signing version and min_ots_version.

        :return: int
        """
        return max(self.signing_ots_version(), getattr(self, 'minOtsVersion', 1))

    def sign(self, anonymous: bool = False, compressed: bool = True, bundle: str = None) -> str | bytes | None:
        """
        Creates a one-time signature for a molecule and breaks it up across multiple atoms within that
        molecule. The signature is 2048 hex characters for OTS v1 and 8192 for OTS v2.

        :param anonymous: bool default False
        :param compressed: bool default True
        :param bundle: str - the bundle to set when the molecule has none (JS ``sign({ bundle })``)
        :return: str | bytes | None
        :raise AtomsMissingException: The molecule does not contain atoms
        :raise SignatureMalformedException: The molecular hash is not 64 characters of [0-9a-g]
        """
        if len(self.atoms) == 0 or len([atom for atom in self.atoms if not isinstance(atom, Atom)]) != 0:
            raise AtomsMissingException()

        # JS Molecule.sign: an existing bundle is kept
        if not anonymous and not self.bundle:
            self.bundle = bundle or crypto.generate_bundle_hash(self.secret())

        self.molecularHash = Atom.hash_atoms(self.atoms)
        self.atoms = Atom.sort_atoms(self.atoms)
        if not crypto.is_signable_hash(self.molecularHash):
            raise SignatureMalformedException()
        first_atom = self.atoms[0]
        key = Wallet.generate_key(
            secret=self.secret(),
            token=first_atom.token,
            position=first_atom.position,
            ots_version=self.signing_ots_version()
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
    
    def replenish_token(self, amount, token: str, recipient_wallet: Wallet, units: List = None) -> 'Molecule':
        """
        Wrapper method for replenishing_tokens to match JavaScript naming convention

        :param amount: Amount to replenish (None or len(units) for stackable / non-fungible)
        :param token: Token slug
        :param recipient_wallet: The credited wallet
        :param units: The new token units (stackable / non-fungible)
        :return: self for chaining
        """
        return self.replenishing_tokens(amount, token, recipient_wallet, units)