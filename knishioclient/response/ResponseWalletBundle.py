# -*- coding: utf-8 -*-
from .Response import Response


class ResponseWalletBundle(Response):
    def payload(self):
        data = self.data()
        if data is None:
            return None

        return data[0] if isinstance(data, list) and len(data) > 0 else data