# -*- coding: utf-8 -*-
from .Response import Response


class ResponseLinkIdentifier(Response):
    def data_key(self):
        return 'LinkIdentifier'

    def success(self):
        data = self.data()
        return data is not None and 'set' in data and data['set'] == True