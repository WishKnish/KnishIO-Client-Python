# -*- coding: utf-8 -*-
from ..models import Wallet
from .Response import Response


class ResponseContinuId(Response):
    def payload(self):
        data = self.data()
        if data is None:
            return None

        wallet_data = data[0] if isinstance(data, list) and len(data) > 0 else data
        return Wallet.json_to_object(wallet_data)