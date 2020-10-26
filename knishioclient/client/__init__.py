# -*- coding: utf-8 -*-

import aiohttp
import asyncio
from knishioclient.exception import (
    UnauthenticatedException,
    CodeException,
    WalletShadowException,
    TransferBalanceException
)
from knishioclient.query import (
    QueryContinuId,
    QueryMoleculePropose,
    QueryBalance,
    QueryAuthentication,
    Query,
    QueryTokenCreate,
    QueryTokenReceive,
    QueryIdentifierCreate,
    QueryWalletList,
    QueryShadowWalletClaim,
    QueryTokenTransfer,
)
from knishioclient.models import Wallet, Molecule, WalletShadow
from knishioclient.libraries.array import array_get, get_signed_atom
from knishioclient.libraries.crypto import generate_bundle_hash
from knishioclient.libraries import decimal, strings


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
        async with aiohttp.ClientSession(headers=options) as session:
            async with session.post(self.get_url(), data=request, ssl=False) as response:
                return await response.json()


class KnishIOClient(object):
    def __init__(self, url: str, client: HttpClient = None):
        self.__client = client or HttpClient(url)
        self.__cell_slug = None
        self.__secret = None
        self.__last_molecule_query = None
        self.__remainder_wallet = None
        self.__authorization_wallet = None
        self.__server_key = None

    def url(self):
        self.__client.get_url()

    def set_url(self, url):
        self.__client.set_url(url)

    def cell_slug(self):
        return self.__cell_slug

    def set_cell_clug(self, cell_slug: str):
        self.__cell_slug = cell_slug

    def cell_slug(self):
        return self.__cell_slug

    def client(self):
        return self.__client

    def set_secret(self, secret: str):
        self.__secret = secret

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
            secret, 'USER', source_wallet.batchId, source_wallet.characters
        )

        return Molecule(secret, source_wallet, self.__remainder_wallet, self.cell_slug())

    def create_molecule_query(self, aclass: Query, molecule: Molecule = None) -> Query:
        molecule = molecule or self.create_molecule()
        query = aclass(self, molecule)

        if not isinstance(query, QueryMoleculePropose):
            raise CodeException(
                '%s.createMoleculeQuery - required class instance of QueryMoleculePropose.' % self.__class__.__name__
            )
        self.__last_molecule_query = query

        return query

    def create_query(self, aclass: Query) -> Query:
        return aclass(self)

    def secret(self):
        if self.__secret is None:
            raise UnauthenticatedException('Expected KnishIOClient.authentication call before.')

        return self.__secret

    def get_source_wallet(self):
        source_wallet = self.get_continu_id(generate_bundle_hash(self.secret())).payload()
        if source_wallet is None:
            source_wallet = Wallet(self.secret())
        return source_wallet

    def get_continu_id(self, bundle_hash: str):
        return self.create_query(QueryContinuId).execute({'bundle': bundle_hash})

    def get_remainder_wallet(self):
        return self.__remainder_wallet

    def get_balance(self, code: str, token: str):
        query = self.create_query(QueryBalance)
        bundle_hash = code if Wallet.is_bundle_hash(code) else generate_bundle_hash(code)

        return query.execute({
            'bundleHash': bundle_hash,
            'token': token
        })

    def authentication(self, secret: str, cell_slug: str = None):
        self.set_secret(secret)
        self.set_cell_clug(cell_slug or self.cell_slug())
        molecule = self.create_molecule(self.secret(), Wallet(self.secret(), 'AUTH'))
        query = self.create_molecule_query(QueryAuthentication, molecule)
        query.fill_molecule()
        response = query.execute()

        if response.success():
            self.__authorization_wallet = self.extracting_authorization_wallet(query.molecule())
            self.client().set_auth_token(response.token())
            self.__server_key = response.pubkey()
        else:
            return UnauthenticatedException(response.reason())

        return response

    def create_token(self, token, amount, metas=None):
        data_metas = metas or {}
        recipient_wallet = Wallet(self.secret(), token)

        if array_get(data_metas, 'fungibility') in 'stackable':
            recipient_wallet.batchId = Wallet.generate_batch_id()

        query = self.create_molecule_query(QueryTokenCreate)
        query.fill_molecule(recipient_wallet, amount, data_metas)

        return query.execute()

    def receive_token(self, token, value, to, metas=None):
        data_metas = metas or {}

        if isinstance(to, str) or isinstance(to, bytes):
            if Wallet.is_bundle_hash(to):
                meta_type = 'walletbundle'
                meta_id = to
            else:
                to = Wallet.create(to, token)
        if isinstance(to, Wallet):
            meta_type = 'wallet'
            data_metas.update({
                'position': to.position,
                'bundle': to.bundle,
            })
            meta_id = to.address

        query = self.create_molecule_query(QueryTokenReceive)
        query.fill_molecule(token, value, meta_type, meta_id, data_metas)

        return query.execute()

    def create_identifier(self, type0, contact, code):
        query = self.create_molecule_query(QueryIdentifierCreate)
        query.fill_molecule(type0, contact, code)

        return query.execute()

    def get_shadow_wallets(self, token):
        query = self.create_query(QueryWalletList)
        response = query.execute({
            'bundleHash': generate_bundle_hash(self.secret()),
            'token': token
        })
        shadow_wallets = response.payload()

        if shadow_wallets is None:
            raise WalletShadowException()
        if not all((isinstance(shadow_wallet, WalletShadow) for shadow_wallet in shadow_wallets)):
            raise WalletShadowException()
        return shadow_wallets

    def claim_shadow_wallet(self, token, molecule: Molecule = None):
        shadow_wallets = self.get_shadow_wallets(token)
        query = self.create_molecule_query(QueryShadowWalletClaim)
        query.fill_molecule(token, shadow_wallets)
        return query.execute()

    def transfer_token(self, to, token, amount):
        from_wallet = self.get_balance(self.secret(), token).payload()
        if from_wallet is None or decimal.cmp(strings.number(from_wallet.balance), amount) < 0:
            raise TransferBalanceException('The transfer amount cannot be greater than the sender\'s balance')
        to_wallet = to if isinstance(to, Wallet) else self.get_balance(to, token).payload()
        if to_wallet is None:
            to_wallet = Wallet.create(to, token)
        to_wallet.init_batch_id(from_wallet, amount)
        self.__remainder_wallet = Wallet.create(self.secret(), token, to_wallet.batchId, from_wallet.characters)
        molecule = self.create_molecule(None, from_wallet, self.get_remainder_wallet())
        query = self.create_molecule_query(QueryTokenTransfer, molecule)
        query.fill_molecule(to_wallet, amount)
        return query.execute()

    def get_authorization_wallet(self):
        return self.__authorization_wallet

    def get_server_key(self):
        return self.__server_key

    def extracting_authorization_wallet(self, molecule: Molecule):
        atom = get_signed_atom(molecule)
        return Wallet(self.secret(), atom.token, atom.position) if atom is not None else None