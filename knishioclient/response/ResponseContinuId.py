# -*- coding: utf-8 -*-
from .Response import Response
from .ResponseWalletList import _wallet_from_data


class ResponseContinuId(Response):
    def payload(self):
        data = self.data()
        if data is None:
            return None

        wallet_data = data[0] if isinstance(data, list) and len(data) > 0 else data
        return _wallet_from_data(wallet_data)