# -*- coding: utf-8 -*-
from json import loads
from knishioclient.exception import *
from knishioclient.models import Wallet, WalletShadow, MoleculeStructure
from knishioclient.libraries.array import array_has, array_get


class Response(object):
    def __init__(self, query: 'Query', json: dict):
        self.__query = query
        self.origin_response = json
        self.__response = json
        self.dataKey = None

        if array_has(self.__response, 'exception'):
            message = self.__response['message']
            if 'unauthenticated' in message.lower():
                raise UnauthenticatedException(message)
            raise InvalidResponseException(message)

        self.init()

    def init(self):
        pass

    def data(self):
        if self.dataKey is None:
            return self.response()

        if not array_has(self.response(), self.dataKey):
            raise InvalidResponseException()

        return array_get(self.response(), self.dataKey)

    def response(self):
        return self.__response

    def payload(self):
        return None

    def query(self):
        return self.__query


class ResponseBalance(Response):
    def __init__(self, query, json):
        super(ResponseBalance, self).__init__(query, json)
        self.dataKey = 'data.Balance'

    def payload(self):
        balance = self.data()
        if not balance:
            return None
        return ResponseWalletList.to_client_wallet(balance)


class ResponseWalletList(Response):
    def __init__(self, query, json):
        super(ResponseWalletList, self).__init__(query, json)
        self.dataKey = 'data.Wallet'

    @classmethod
    def to_client_wallet(cls, data):
        if data['position'] is None:
            wallet = WalletShadow(data['bundleHash'], data['tokenSlug'], data['batchId'])
        else:
            wallet = Wallet(None, data['tokenSlug'])
            wallet.address = data['address']
            wallet.position = data['position']
            wallet.bundle = data['bundleHash']
            wallet.batchId = data['batchId']
            wallet.characters = data['characters']
            wallet.pubkey = data['pubkey']
        wallet.balance = data['amount']

        return wallet

    def payload(self):
        data_list = self.data()

        if not data_list:
            return None

        return [ResponseWalletList.to_client_wallet(data) for data in data_list]


class ResponseContinuId(Response):
    def __init__(self, query, json):
        super(ResponseContinuId, self).__init__(query, json)
        self.dataKey = 'data.ContinuId'

    def payload(self):
        data = self.data()

        if data is not None:
            return ResponseWalletList.to_client_wallet(data)

        return None


class ResponseMolecule(Response):
    def __init__(self, query, json):
        super(ResponseMolecule, self).__init__(query, json)
        self.dataKey = 'data.ProposeMolecule'
        self.__payload = None
        self.init()

    def payload(self):
        return self.__payload

    def init(self):
        payload_json = array_get(self.data(), 'payload')
        self.__payload = payload_json if payload_json is None else loads(payload_json)

    def molecule(self):
        data = self.data()
        if data is not None:
            return None
        molecule = MoleculeStructure()
        molecule.molecularHash = array_get(data, 'molecularHash')
        molecule.status = array_get(data, 'status')
        molecule.createdAt = array_get(data, 'createdAt')
        return molecule

    def status(self):
        return array_get(self.data(), 'status', 'rejected')

    def reason(self):
        return array_get(self.data(), 'reason', 'Invalid response from server')

    def success(self) -> bool:
        return self.status() in 'accepted'


class ResponseAuthentication(ResponseMolecule):
    def __payload_key(self, key: str):
        if not array_has(self.payload(), key):
            raise InvalidResponseException('ResponseAuthentication %s key is not found in the payload.' % key)

        return array_get(self.payload(), key)

    def token(self):
        return self.__payload_key('token')

    def time(self):
        return self.__payload_key('time')


class ResponseIdentifier(Response):
    def __init__(self, query, json):
        super(ResponseIdentifier, self).__init__(query, json)
        self.dataKey = 'data.LinkIdentifier'

    def success(self):
        return array_get(self.data(), 'set')

    def message(self):
        return array_get(self.data(), 'message')