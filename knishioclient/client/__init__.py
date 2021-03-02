# -*- coding: utf-8 -*-

import aiohttp
import asyncio
from knishioclient.exception import (
    UnauthenticatedException,
    CodeException,
    TransferBalanceException
)
from knishioclient.query import (
    Query,
    QueryContinuId,
    QueryBalance,
    QueryWalletList,
    QueryMetaType,
    QueryWalletBundle
)
from knishioclient.mutation import (
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
from knishioclient.models import Wallet, Molecule, Union, Coder
from knishioclient.libraries.array import array_get, get_signed_atom
from knishioclient.libraries.crypto import generate_bundle_hash
from knishioclient.libraries import decimal, strings, crypto


class HttpClient(object):
    def __init__(self, url: str):
        self.__xAuthToken = None
        self.__url = url

    def get_url(self):
        return self.__url

    def set_url(self, url: str):
        self.__url = url

    def set_auth_token(self, auth_token: str):
        self.__xAuthToken = auth_token

    def get_auth_token(self):
        return self.__xAuthToken

    def send(self, request: str, options: dict = None):
        loop = asyncio.get_event_loop()
        response = loop.run_until_complete(asyncio.gather(self.__send(request, options)))
        return array_get(response, '0')

    async def __send(self, request: str, options: dict = None):
        if options is None:
            options = {}
        options.update({
            'User-Agent': 'KnishIO/0.1',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        })
        if self.get_auth_token() is not None:
            options.update({'X-Auth-Token': self.get_auth_token()})
        async with aiohttp.ClientSession(headers=options, json_serialize=Coder().encode) as session:
            async with session.post(self.get_url(), json=request, ssl=False) as response:
                return await response.json()


class KnishIOClient(object):
    def __init__(self, url: str, client: HttpClient = None, server_sdk_version=3, logging: bool = False):
        self.__client = None
        self.__cell_slug = None
        self.__secret = None
        self.__bundle = None
        self.__last_molecule_query = None
        self.__remainder_wallet = None
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
        self.__remainder_wallet = None

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

    def create_molecule(self, secret: str = None, source_wallet: Wallet = None, remainder_wallet: Wallet = None):
        secret = secret or self.secret()
        if source_wallet is None \
                and self.__remainder_wallet.token not in 'AUTH' \
                and self.__last_molecule_query is not None \
                and self.__last_molecule_query.response() is not None \
                and self.__last_molecule_query.response().success():
            source_wallet = self.__remainder_wallet

        if source_wallet is None:
            source_wallet = self.get_source_wallet()

        self.__remainder_wallet = remainder_wallet or Wallet.create(
            secret, source_wallet.token, source_wallet.batchId, source_wallet.characters
        )

        return Molecule(secret, source_wallet, self.__remainder_wallet, self.cell_slug())

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

    def get_remainder_wallet(self):
        return self.__remainder_wallet

    def query_balance(self, token_slug: str, bundle_hash: str = None):
        query = self.create_query(QueryBalance)

        return query.execute({
            'bundleHash': bundle_hash or self.bundle(),
            'token': token_slug
        })

    def create_meta(self, meta_type, meta_id, metadata=None):
        if metadata is None:
            metadata = {}

        query = self.create_molecule_mutation(
            MutationCreateMeta,
            self.create_molecule(self.secret(), self.get_source_wallet())
        )

        query.fill_molecule(meta_type, meta_id, metadata)

        return query.execute()

    def query_meta(self, meta_type: str = None, meta_id: Union[str, bytes, int, float] = None,
                   key: Union[str, bytes] = None, value: Union[str, bytes, int, float] = None,
                   latest: bool = None, fields=None, filter: Union[list, dict] = None):
        query = self.create_query(QueryMetaType)
        variables = QueryMetaType.create_variables(meta_type, meta_id, key, value, latest, filter)

        return query.execute(variables, fields).payload()

    def create_wallet(self, token_slug: str):
        new_wallet = Wallet(self.secret(), token_slug)
        query = self.create_molecule_mutation(MutationCreateWallet)
        query.fill_molecule(new_wallet)

        return query.execute()

    def query_wallets(self, bundle_hash: Union[str, bytes] = None, unspent: bool = True):
        wallet_query = self.create_query(QueryWalletList)
        response = wallet_query.execute({
            'bundleHash': bundle_hash or self.bundle(),
            'unspent': unspent
        })

        return response.get_wallets()

    def request_auth_token(self, secret: str, cell_slug: str = None):
        self.set_secret(secret)
        self.set_cell_slug(cell_slug or self.cell_slug())

        molecule = self.create_molecule(self.secret(), Wallet(self.secret(), 'AUTH'))
        query = self.create_molecule_mutation(MutationRequestAuthorization, molecule)

        query.fill_molecule()

        response = query.execute()

        if response.success():
            self.client().set_auth_token(response.token())
        else:
            raise UnauthenticatedException(response.reason())

        return response

    def create_token(self, token_slug: str, initial_amount: Union[int, float],
                     token_metadata: Union[list, dict] = None):
        data_metas = token_metadata or {}
        recipient_wallet = Wallet(self.secret(), token_slug)

        if array_get(data_metas, 'fungibility') in 'stackable':
            recipient_wallet.batchId = crypto.generate_batch_id()

        query = self.create_molecule_mutation(MutationCreateToken)
        query.fill_molecule(recipient_wallet, initial_amount, data_metas)

        return query.execute()

    def request_tokens(self, token_slug: str, requested_amount: Union[int, float],
                       to: Union[str, bytes, Wallet] = None, metas: Union[list, dict] = None):
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

    def query_shadow_wallets(self, token_slug: str = 'KNISH', bundle_hash: Union[str, bytes] = None):
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

    def query_bundle(self, bundle_hash: Union[str, bytes] = None, key: Union[str, bytes] = None,
                     value: Union[str, bytes, int, float] = None, latest: bool = True, fields=None):
        query = self.create_query(QueryWalletBundle)
        variables = QueryWalletBundle.create_variables(bundle_hash or self.bundle(), key, value, latest)
        response = query.execute(variables, fields)

        return response.payload()

    def transfer_token(self, wallet_object_or_bundle_hash: Union[Wallet, str, bytes], token_slug: str,
                       amount: Union[int, float]):
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
