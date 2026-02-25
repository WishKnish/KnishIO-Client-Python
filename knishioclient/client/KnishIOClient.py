# -*- coding: utf-8 -*-
from typing import Optional, Dict, Any, Union, Awaitable, Callable
import asyncio
import time
from ..exception import (
    UnauthenticatedException,
    CodeException,
    TransferBalanceException,
    NegativeMeaningException,
    BalanceInsufficientException
)
from ..query import (
    Query,
    QueryContinuId,
    QueryBalance,
    QueryWalletList,
    QueryMetaType,
    QueryWalletBundle,
    QueryMetaTypeViaAtom,
    QueryAtom,
    QueryBatch,
    QueryBatchHistory,
    QueryPolicy,
    QueryUserActivity
)
from ..mutation import (
    Mutation,
    MutationProposeMolecule,
    MutationRequestAuthorization,
    MutationCreateToken,
    MutationRequestTokens,
    MutationLinkIdentifier,
    MutationClaimShadowWallet,
    MutationTransferTokens,
    MutationCreateWallet,
    MutationCreateMeta
)
from ..models import Wallet, Molecule
from ..libraries.array import array_get, get_signed_atom
from ..libraries.crypto import generate_bundle_hash
from ..libraries import decimal, strings, crypto
from ..config.standard_config import ClientConfig, MetaConfig, TokenConfig, TransferConfig
from ..response.standard_response import StandardResponse, ResponseFactory, ValidationResult
from .HttpClient import HttpClient


class KnishIOClient(object):
    def __init__(self, url: str, client: HttpClient = None, server_sdk_version=3, logging: bool = False):
        self.__client = None
        self.__cell_slug = None
        self.__secret = None
        self.__bundle = None
        self.__last_molecule_query = None
        self.__remainder_wallet: Wallet | None = None
        self.__authorization_wallet = None
        self.__server_key = None
        self.__logging = False
        self.__server_sdk_version = 3

        self.initialize(url, client, server_sdk_version, logging)

    def initialize(self, url: str, client: HttpClient = None, server_sdk_version: int = 3, logging: bool = False):
        self.reset()
        self.__logging = logging
        self.__client = client or HttpClient(url)
        self.__server_sdk_version = server_sdk_version

    def deinitialize(self):
        self.reset()

    def reset(self):
        self.__secret = None
        self.__bundle = None
        self.__remainder_wallet: Wallet | None = None

    def bundle(self) -> str:
        if self.__bundle is None:
            raise UnauthenticatedException()
        return self.__bundle

    def get_server_sdk_version(self):
        return self.__server_sdk_version

    def url(self):
        self.__client.get_url()

    def set_url(self, url):
        self.__client.set_url(url)

    def cell_slug(self):
        return self.__cell_slug

    def set_cell_slug(self, cell_slug: str):
        self.__cell_slug = cell_slug

    def client(self):
        return self.__client

    def set_secret(self, secret: str):
        self.__secret = secret
        self.__bundle = generate_bundle_hash(secret)

    def has_secret(self):
        return self.__secret is not None

    def create_molecule(self, secret: str = None, bundle: str = None, source_wallet: Wallet = None, remainder_wallet: Wallet = None):
        secret = secret or self.secret()
        bundle = bundle or self.bundle()

        if source_wallet is None \
                and self.get_remainder_wallet().token not in 'USER' \
                and self.__last_molecule_query is not None \
                and self.__last_molecule_query.response() is not None \
                and self.__last_molecule_query.response().success():
            source_wallet = self.get_remainder_wallet()

        if source_wallet is None:
            source_wallet = self.get_source_wallet()

        self.__remainder_wallet = remainder_wallet or Wallet.create(
            secret, bundle, source_wallet.token, source_wallet.batchId, source_wallet.characters
        )
        molecule = Molecule(
            secret=secret,
            bundle=bundle,
            source_wallet=source_wallet,
            remainder_wallet=self.get_remainder_wallet(),
            cell_slug=self.cell_slug()
        )
        return molecule

    def create_molecule_mutation(self, mutation_class, molecule: Molecule = None) -> Mutation:
        molecule = molecule or self.create_molecule()
        mutation = mutation_class(self, molecule)

        if not isinstance(mutation, MutationProposeMolecule):
            raise CodeException(
                '%s.createMoleculeQuery - required class instance of MutationProposeMolecule.' % self.__class__.__name__
            )
        self.__last_molecule_query = mutation

        return mutation

    def create_query(self, query) -> Query:
        return query(self)

    def secret(self):
        if self.__secret is None:
            raise UnauthenticatedException('Expected KnishIOClient.request_auth_token call before.')

        return self.__secret

    def get_source_wallet(self) -> Wallet:
        source_wallet = self.query_continu_id(self.bundle()).payload()

        if source_wallet is None:
            source_wallet = Wallet(self.secret())

        return source_wallet

    def query_continu_id(self, bundle_hash: str):
        return self.create_query(QueryContinuId).execute({'bundle': bundle_hash})

    def get_remainder_wallet(self) -> Wallet:
        return self.__remainder_wallet

    def query_balance(self, token_slug: str, bundle_hash: str = None):
        query = self.create_query(QueryBalance)

        return query.execute({
            'bundleHash': bundle_hash or self.bundle(),
            'token': token_slug
        })

    def create_meta(
        self,
        meta_type: str,
        meta_id: str,
        metadata = None,
        policy: dict = None
    ):
        if metadata is None:
            metadata = {}

        query = self.create_molecule_mutation(
            MutationCreateMeta,
            self.create_molecule(secret=self.secret(), source_wallet=self.get_source_wallet())
        )

        query.fill_molecule(meta_type=meta_type, meta_id=meta_id, metadata=metadata, policy=policy)

        return query.execute()

    def query_meta(
            self,
            meta_type: str = None,
            meta_id: str | bytes | int | float = None,
            key: str | bytes | None = None,
            value: str | bytes | int | float = None,
            latest: bool = None,
            fields: dict = None,
            filter: list | dict | None = None,
            query_args: dict = None,
            count: str = None,
            count_by: str = None,
            through_atom: bool = True,
            values: list = None,
            keys: list = None,
            atom_values: list = None
    ):
        if through_atom:
            query = self.create_query(QueryMetaTypeViaAtom)
            variables = QueryMetaTypeViaAtom.create_variables(
                meta_type=meta_type,
                meta_id=meta_id,
                key=key,
                value=value,
                latest=latest,
                filter=filter,
                query_args=query_args,
                count_by=count_by,
                values=values,
                keys=keys,
                atom_values=atom_values,
                cell_slug=self.cell_slug()
            )
        else:
            query = self.create_query(QueryMetaType)
            variables = QueryMetaType.create_variables(
                meta_type=meta_type,
                meta_id=meta_id,
                key=key,
                value=value,
                latest=latest,
                filter=filter,
                query_args=query_args,
                count_by=count_by,
                count=count,
                cell_slug=self.cell_slug()
            )

        return query.execute(variables, fields).payload()

    def create_wallet(self, token_slug: str):
        new_wallet = Wallet(self.secret(), token_slug)
        query = self.create_molecule_mutation(MutationCreateWallet)
        query.fill_molecule(new_wallet)

        return query.execute()

    def query_wallets(self, bundle_hash: str | bytes | None = None, unspent: bool = True):
        wallet_query = self.create_query(QueryWalletList)
        response = wallet_query.execute({
            'bundleHash': bundle_hash or self.bundle(),
            'unspent': unspent
        })

        return response.get_wallets()

    def request_auth_token(self, secret: str = None, cell_slug: str = None, encrypt: bool = False):
        """
        Unified authentication method supporting both guest and profile modes
        
        :param secret: User secret for profile auth (None for guest auth)
        :param cell_slug: Cell slug for the session
        :param encrypt: Whether to use encryption
        :return: Authentication response
        """
        # If no secret provided, use guest authentication
        if secret is None:
            return self.request_guest_auth_token(cell_slug, encrypt)
        
        # Otherwise use profile authentication
        return self.request_profile_auth_token(secret, encrypt)

    def create_token(self, token_slug: str, initial_amount,
                     token_metadata=None):
        data_metas = token_metadata or {}
        recipient_wallet = Wallet(self.secret(), token_slug)

        fungibility = array_get(data_metas, 'fungibility')
        if fungibility and fungibility in 'stackable':
            recipient_wallet.batchId = crypto.generate_batch_id()

        query = self.create_molecule_mutation(MutationCreateToken)
        query.fill_molecule(recipient_wallet, initial_amount, data_metas)

        return query.execute()

    def request_tokens(self, token_slug: str, requested_amount: int | float,
                       to: str | bytes | Wallet | None = None, metas: list | dict | None = None):
        data_metas = metas or {}
        meta_type = None
        meta_id = None

        if to is not None:
            if isinstance(to, (str, bytes)):
                if Wallet.is_bundle_hash(to):
                    meta_type = 'walletbundle'
                    meta_id = to
                else:
                    to = Wallet.create(to, token_slug)
            if isinstance(to, Wallet):
                meta_type = 'wallet'
                data_metas.update({
                    'position': to.position,
                    'bundle': to.bundle,
                })
                meta_id = to.address
        else:
            meta_type = 'walletBundle'
            meta_id = self.bundle()

        query = self.create_molecule_mutation(MutationRequestTokens)
        query.fill_molecule(token_slug, requested_amount, meta_type, meta_id, data_metas)

        return query.execute()

    def create_identifier(self, type0, contact, code):
        query = self.create_molecule_mutation(MutationLinkIdentifier)
        query.fill_molecule(type0, contact, code)

        return query.execute()

    def query_shadow_wallets(self, token_slug: str = 'KNISH', bundle_hash: str | bytes | None = None):
        query = self.create_query(QueryWalletList)
        response = query.execute({
            'bundleHash': bundle_hash or self.bundle(),
            'token': token_slug
        })

        return response.payload()

    def claim_shadow_wallet(self, token_slug: str, batch_id: str, molecule: Molecule = None):
        query = self.create_molecule_mutation(MutationClaimShadowWallet, molecule)
        query.fill_molecule(token_slug, batch_id)

        return query.execute()

    def query_bundle(self, bundle_hash: str | bytes | None = None, key: str | bytes | None = None,
                     value: str | bytes | int | float | None = None, latest: bool = True, fields=None):
        query = self.create_query(QueryWalletBundle)
        variables = QueryWalletBundle.create_variables(bundle_hash or self.bundle(), key, value, latest)
        response = query.execute(variables, fields)

        return response.payload()

    def transfer_token(self, wallet_object_or_bundle_hash: Wallet | str | bytes, token_slug: str,
                       amount: int | float):
        from_wallet = self.query_bundle(token_slug).payload()

        if from_wallet is None or decimal.cmp(strings.number(from_wallet.balance), amount) < 0:
            raise TransferBalanceException('The transfer amount cannot be greater than the sender\'s balance')

        to_wallet = wallet_object_or_bundle_hash if isinstance(wallet_object_or_bundle_hash, Wallet) else \
            self.query_balance(token_slug, wallet_object_or_bundle_hash).payload()

        if to_wallet is None:
            to_wallet = Wallet.create(wallet_object_or_bundle_hash, token_slug)

        to_wallet.init_batch_id(from_wallet, amount)

        self.__remainder_wallet = Wallet.create(self.secret(), token_slug, to_wallet.batchId, from_wallet.characters)

        molecule = self.create_molecule(None, from_wallet, self.get_remainder_wallet())
        query = self.create_molecule_mutation(MutationTransferTokens, molecule)
        query.fill_molecule(to_wallet, amount)

        return query.execute()

    def get_authorization_wallet(self):
        return self.__authorization_wallet

    def get_server_key(self):
        return self.__server_key

    def extracting_authorization_wallet(self, molecule: Molecule):
        atom = get_signed_atom(molecule)
        return Wallet(self.secret(), atom.token, atom.position) if atom is not None else None
    
    def query_batch(self, batch_id: str = None):
        """Query batch information"""
        query = self.create_query(QueryBatch)
        return query.execute({'batchId': batch_id} if batch_id else {})
    
    def query_batch_history(self, batch_id: str = None):
        """Query batch history information"""
        query = self.create_query(QueryBatchHistory)
        return query.execute({'batchId': batch_id} if batch_id else {})
    
    def query_atom(self, **kwargs):
        """Query atomic data from the ledger"""
        query = self.create_query(QueryAtom)
        return query.execute(kwargs)
    
    def query_policy(self, meta_type: str = None, meta_id: str = None):
        """Query policy information"""
        query = self.create_query(QueryPolicy)
        params = {}
        if meta_type:
            params['metaType'] = meta_type
        if meta_id:
            params['metaId'] = meta_id
        return query.execute(params)
    
    def query_user_activity(self, **kwargs):
        """Query user activity information"""
        query = self.create_query(QueryUserActivity)
        return query.execute(kwargs)
    
    def create_rule(self, meta_type: str, meta_id: str, rule: list, policy: dict = None):
        """
        Builds and executes a molecule to create a rule on the ledger
        
        :param meta_type: The type of the metadata entry
        :param meta_id: The ID of the metadata entry
        :param rule: List of rule objects
        :param policy: The policy object (optional)
        :return: Response from the mutation
        """
        from ..mutation import MutationCreateRule
        
        molecule = self.create_molecule(
            secret=self.secret(),
            source_wallet=self.get_source_wallet()
        )
        
        query = self.create_molecule_mutation(MutationCreateRule, molecule)
        query.fill_molecule(meta_type, meta_id, rule, policy or {})
        
        return query.execute()
    
    def deposit_buffer_token(self, token_slug: str, amount: float, trade_rates: dict = None, source_wallet=None):
        """
        Deposits tokens into a buffer wallet
        
        :param token_slug: The token slug
        :param amount: Amount to deposit
        :param trade_rates: Trade rates for the buffer wallet (optional)
        :param source_wallet: Source wallet (optional, will query if not provided)
        :return: Response from the mutation
        """
        from ..mutation import MutationDepositBufferToken
        
        # Get source wallet if not provided
        if source_wallet is None:
            source_wallet = self.query_balance(token_slug, self.bundle())
            if not source_wallet or source_wallet.balance < amount:
                raise Exception(f"Insufficient balance for token {token_slug}")
        
        # Create remainder wallet
        remainder_wallet = source_wallet.create_remainder(self.secret())
        
        # Build the molecule
        molecule = self.create_molecule(
            source_wallet=source_wallet,
            remainder_wallet=remainder_wallet
        )
        
        query = self.create_molecule_mutation(MutationDepositBufferToken, molecule)
        query.fill_molecule(amount, trade_rates)
        
        return query.execute()
    
    def withdraw_buffer_token(self, token_slug: str, amount: float, source_wallet=None, signing_wallet=None):
        """
        Withdraws tokens from a buffer wallet
        
        :param token_slug: The token slug
        :param amount: Amount to withdraw
        :param source_wallet: Source wallet (optional, will query if not provided)
        :param signing_wallet: Signing wallet for the transaction (optional)
        :return: Response from the mutation
        """
        from ..mutation import MutationWithdrawBufferToken
        
        # Get source wallet if not provided - note this should be a buffer wallet
        if source_wallet is None:
            # This would need a query for buffer wallets - using regular balance for now
            source_wallet = self.query_balance(token_slug, self.bundle())
            if not source_wallet or source_wallet.balance < amount:
                raise Exception(f"Insufficient buffer balance for token {token_slug}")
        
        # Remainder wallet is the source wallet itself for buffer operations
        remainder_wallet = source_wallet
        
        # Build the molecule
        molecule = self.create_molecule(
            source_wallet=source_wallet,
            remainder_wallet=remainder_wallet
        )
        
        query = self.create_molecule_mutation(MutationWithdrawBufferToken, molecule)
        
        # Create recipients dict with user's bundle
        recipients = {self.bundle(): amount}
        query.fill_molecule(recipients, signing_wallet)
        
        return query.execute()
    
    def burn_tokens(self, token_slug: str, amount: float, source_wallet: Wallet = None):
        """
        Burns (destroys) tokens from the specified wallet
        
        :param token_slug: The token to burn
        :param amount: Amount of tokens to burn
        :param source_wallet: Source wallet (optional, uses balance query if not provided)
        :return: Response from the mutation
        """
        if amount <= 0:
            raise NegativeMeaningException('Amount to burn must be positive')
        
        # Get source wallet if not provided
        if source_wallet is None:
            source_wallet = self.query_balance(token_slug).data()
            if not source_wallet:
                raise TransferBalanceException('Source wallet not found')
        
        # Check balance
        if source_wallet.balance < amount:
            raise BalanceInsufficientException('Insufficient balance to burn tokens')
        
        # Create remainder wallet
        remainder_wallet = Wallet(
            secret=self.secret(),
            token=source_wallet.token,
            batchId=source_wallet.batchId,
            characters=source_wallet.characters
        )
        
        # Create molecule
        molecule = self.create_molecule(
            source_wallet=source_wallet,
            remainder_wallet=remainder_wallet
        )
        
        # Burn the tokens
        molecule.burning_tokens(amount)
        molecule.sign()
        molecule.check()
        
        # Create and execute mutation
        query = self.create_molecule_mutation(MutationProposeMolecule, molecule)
        return query.execute()
    
    def replenish_token(self, token_slug: str, amount: float, 
                        metas: list = None, source_wallet: Wallet = None):
        """
        Replenishes (mints new) tokens
        
        :param token_slug: The token to replenish
        :param amount: Amount of tokens to create
        :param metas: Metadata for the replenish operation
        :param source_wallet: Source wallet (optional)
        :return: Response from the mutation
        """
        if amount <= 0:
            raise NegativeMeaningException('Amount to replenish must be positive')
        
        # Get source wallet if not provided
        if source_wallet is None:
            source_wallet = self.query_balance(token_slug).data()
            if not source_wallet:
                # Create new wallet if it doesn't exist
                source_wallet = Wallet(secret=self.secret(), token=token_slug)
        
        # Create remainder wallet
        remainder_wallet = Wallet(
            secret=self.secret(),
            token=source_wallet.token,
            batchId=source_wallet.batchId,
            characters=source_wallet.characters
        )
        
        # Create molecule
        molecule = self.create_molecule(
            source_wallet=source_wallet,
            remainder_wallet=remainder_wallet
        )
        
        # Prepare metadata
        if metas is None:
            metas = {
                'action': 'add',
                'address': source_wallet.address,
                'position': source_wallet.position
            }
            if source_wallet.batchId:
                metas['batchId'] = source_wallet.batchId
        
        # Replenish the tokens
        molecule.replenishing_tokens(amount, token_slug, metas)
        molecule.sign()
        molecule.check()
        
        # Create and execute mutation
        query = self.create_molecule_mutation(MutationProposeMolecule, molecule)
        return query.execute()
    
    def request_guest_auth_token(self, cell_slug: str = None, encrypt: bool = False):
        """
        Requests a guest authentication token
        
        :param cell_slug: The cell slug for the guest session
        :param encrypt: Whether to use encryption
        :return: Response with auth token
        """
        from ..mutation import MutationRequestAuthorizationGuest
        from ..models import AuthToken
        from ..libraries import crypto
        
        self.set_cell_slug(cell_slug or self.cell_slug())
        
        # Create a temporary wallet for guest
        # In Python, we don't have fingerprinting, so use a random secret
        guest_secret = crypto.generate_secret()
        wallet = Wallet(secret=guest_secret, token='AUTH')
        
        # Create the guest auth mutation
        query = self.create_query(MutationRequestAuthorizationGuest)
        
        # Execute the query with guest parameters
        response = query.execute({
            'cellSlug': self.cell_slug(),
            'pubkey': wallet.pubkey,
            'encrypt': encrypt
        })
        
        if response.success():
            # Create auth token from response
            auth_token = AuthToken.create(response.data(), wallet)
            self.client().set_auth_token(response.token())  # Use token() for guest auth
            return response
        else:
            raise UnauthenticatedException(f'Guest authentication failed: {response.reason()}')
    
    def request_profile_auth_token(self, secret: str, encrypt: bool = False):
        """
        Requests a profile authentication token
        
        :param secret: The user's secret
        :param encrypt: Whether to use encryption
        :return: Response with auth token
        """
        from ..models import AuthToken
        
        self.set_secret(secret)
        
        # Create wallet for authentication
        wallet = Wallet(secret=secret, token='AUTH')
        
        # Create molecule with the wallet
        molecule = self.create_molecule(self.secret(), source_wallet=wallet)
        
        # Create auth mutation
        query = self.create_molecule_mutation(MutationRequestAuthorization, molecule)
        
        # Add encryption meta if requested
        if encrypt:
            query.fill_molecule([{'encrypt': 'true'}])
        else:
            query.fill_molecule()
        
        # Execute the mutation
        response = query.execute()
        
        if response.success():
            # Create auth token from response
            auth_token = AuthToken.create(response.data(), wallet)
            self.client().set_auth_token(response.auth_token())
            return response
        else:
            raise UnauthenticatedException(f'Profile authentication failed: {response.reason()}')
    
    # =======================================================================
    # Enhanced API Methods with StandardResponse Framework Integration
    # =======================================================================
    
    @classmethod
    def create_enhanced(cls, config: Union[ClientConfig, Dict[str, Any]]) -> 'KnishIOClient':
        """Enhanced factory method using ClientConfig for type safety"""
        if isinstance(config, dict):
            config = ClientConfig.from_dict(config)
        
        # Validate configuration
        validation_result = config.validate()
        if not validation_result.success:
            raise ValueError(f"Invalid client configuration: {validation_result.error.message}")
        
        return cls(
            url=config.uri,
            server_sdk_version=config.server_sdk_version,
            logging=config.logging
        )
    
    async def create_meta_enhanced(
        self,
        config: Union[MetaConfig, Dict[str, Any]]
    ) -> StandardResponse[Dict[str, Any]]:
        """Create metadata with enhanced response handling and AsyncIO support"""
        start_time = time.time()
        
        try:
            # Configuration validation
            if isinstance(config, dict):
                config = MetaConfig.from_dict(config)
            
            validation_result = config.validate()
            if not validation_result.success:
                return StandardResponse.create_failure(
                    f"MetaConfig validation failed: {validation_result.error.message}",
                    "create_meta_enhanced",
                    config,
                    time.time() - start_time
                )
            
            # Create molecule for metadata
            molecule = self.create_molecule()
            
            # Use init_meta with validated configuration
            molecule.init_meta(
                meta=config.meta,
                meta_type=config.meta_type,
                meta_id=config.meta_id,
                policy=config.policy
            )
            
            # Sign molecule
            molecule.sign()
            
            # Create mutation and execute
            mutation = self.create_molecule_mutation(MutationCreateMeta, molecule)
            legacy_response = mutation.execute()
            
            # Convert legacy response to StandardResponse
            if legacy_response.success():
                return StandardResponse.create_success(
                    legacy_response.payload(),
                    "create_meta_enhanced",
                    legacy_response.data(),
                    time.time() - start_time
                )
            else:
                return StandardResponse.create_failure(
                    legacy_response.reason() or "Meta creation failed",
                    "create_meta_enhanced",
                    legacy_response.data(),
                    time.time() - start_time
                )
                
        except Exception as e:
            return StandardResponse.create_failure(
                f"Meta creation error: {str(e)}",
                "create_meta_enhanced",
                None,
                time.time() - start_time
            )
    
    def create_meta_sync(
        self,
        config: Union[MetaConfig, Dict[str, Any]]
    ) -> StandardResponse[Dict[str, Any]]:
        """Synchronous version of create_meta_enhanced for backward compatibility"""
        # Use asyncio.run for internal async operations while maintaining sync interface
        return asyncio.run(self.create_meta_enhanced(config))
    
    async def create_token_enhanced(
        self,
        config: Union[TokenConfig, Dict[str, Any]]
    ) -> StandardResponse[Dict[str, Any]]:
        """Create token with enhanced response handling"""
        start_time = time.time()
        
        try:
            if isinstance(config, dict):
                config = TokenConfig.from_dict(config)
            
            validation_result = config.validate()
            if not validation_result.success:
                return StandardResponse.create_failure(
                    f"TokenConfig validation failed: {validation_result.error.message}",
                    "create_token_enhanced",
                    config,
                    time.time() - start_time
                )
            
            # Create recipient wallet for the token
            recipient_wallet = self.get_source_wallet()
            
            # Create token creation mutation
            mutation = self.create_token(
                recipient_wallet=recipient_wallet,
                token_slug=config.token,
                amount=config.amount or 0,
                token_meta=config.meta or {}
            )
            
            legacy_response = mutation.execute()
            
            if legacy_response.success():
                return StandardResponse.create_success(
                    legacy_response.payload(),
                    "create_token_enhanced",
                    legacy_response.data(),
                    time.time() - start_time
                )
            else:
                return StandardResponse.create_failure(
                    legacy_response.reason() or "Token creation failed",
                    "create_token_enhanced",
                    legacy_response.data(),
                    time.time() - start_time
                )
                
        except Exception as e:
            return StandardResponse.create_failure(
                f"Token creation error: {str(e)}",
                "create_token_enhanced",
                None,
                time.time() - start_time
            )
    
    async def query_balance_enhanced(
        self,
        token: str,
        bundle: Optional[str] = None
    ) -> StandardResponse[Dict[str, Any]]:
        """Query balance with enhanced response handling and AsyncIO"""
        start_time = time.time()
        
        try:
            query = self.query_balance(
                bundle_hash=bundle or self.bundle(),
                token=token
            )
            
            legacy_response = query.execute()
            
            if legacy_response.success():
                return StandardResponse.create_success(
                    legacy_response.payload(),
                    "query_balance_enhanced",
                    legacy_response.data(),
                    time.time() - start_time
                )
            else:
                return StandardResponse.create_failure(
                    legacy_response.reason() or "Balance query failed",
                    "query_balance_enhanced",
                    legacy_response.data(),
                    time.time() - start_time
                )
                
        except Exception as e:
            return StandardResponse.create_failure(
                f"Balance query error: {str(e)}",
                "query_balance_enhanced",
                None,
                time.time() - start_time
            )
    
    def wrap_legacy_response(
        self,
        legacy_response: Any,
        operation: str
    ) -> StandardResponse[Any]:
        """Utility method to wrap legacy responses in StandardResponse format"""
        return StandardResponse.from_legacy_response(legacy_response, operation)
    
    def get_enhanced_config(self) -> ClientConfig:
        """Get current client configuration as enhanced ClientConfig object"""
        return ClientConfig(
            uri=self.client().get_url(),
            cell_slug=self.cell_slug(),
            server_sdk_version=self.get_server_sdk_version(),
            logging=self.__logging
        )
    
    def validate_and_execute(
        self,
        config: Union[Dict[str, Any], Any],
        config_type: str,
        operation_func: Callable
    ) -> StandardResponse[Any]:
        """Generic validation and execution pattern for enhanced methods"""
        from ..config.standard_config import ConfigUtils
        
        validation_result = ConfigUtils.validate_config(config, config_type)
        
        if not validation_result.success:
            return StandardResponse.create_failure(
                f"{config_type} validation failed: {validation_result.error.message}",
                f"validate_and_execute_{config_type}"
            )
        
        try:
            return operation_func(validation_result.data)
        except Exception as e:
            return StandardResponse.create_failure(
                f"Operation failed: {str(e)}",
                f"validate_and_execute_{config_type}"
            )