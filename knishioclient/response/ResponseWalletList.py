# -*- coding: utf-8 -*-
from ..models import Wallet
from .Response import Response


class ResponseWalletList(Response):
    __bundle = None

    def bundle(self):
        return self.__bundle

    def init_response(self, response: dict):
        super(ResponseWalletList, self).init_response(response)

        if self.errors() is not None:
            return

        data = self.data()
        if data is None:
            return

        wallets = data if isinstance(data, list) else [data]
        for item in wallets:
            wallet = Wallet.json_to_object(item)
            if not isinstance(wallet, Wallet):
                continue

            if wallet.bundle == self.query.variables()["bundleHash"]:
                self.__bundle = wallet.bundle
                return

    def payload(self):
        data = self.data()
        if data is None:
            return []

        wallets = []
        _wallets = data if isinstance(data, list) else [data]
        for item in _wallets:
            wallet = Wallet.json_to_object(item)
            if not isinstance(wallet, Wallet):
                continue
            if self.__bundle is not None and wallet.bundle != self.__bundle:
                continue
            wallets.append(wallet)

        return wallets