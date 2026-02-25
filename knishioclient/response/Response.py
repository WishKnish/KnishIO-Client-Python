# -*- coding: utf-8 -*-
import json
from ..exception import InvalidResponseException


class Response(object):
    def __init__(self, query: 'Query', response: dict):
        self.query = query
        self.response = response
        self.__data = None
        self.__errors = None
        self.init_response(response)

    def init_response(self, response: dict):
        if 'data' not in response:
            raise InvalidResponseException(f"Invalid response structure: {json.dumps(response)}")

        errors = response.get('errors')
        if errors is not None and len(errors) > 0:
            self.__errors = errors
            return

        data_key = self.data_key()
        data = response['data']
        if data_key not in data:
            self.__errors = ['Invalid response']
            return

        self.__data = data[data_key]

    def data_key(self):
        query = self.query.query
        keys = query.replace('{', '(').split('(')[1].split(')')[0].split(' ')
        return keys[0] if len(keys) > 0 else ''

    def data(self):
        return self.__data

    def __str__(self):
        return json.dumps(self.data())

    def payload(self):
        return self.data()

    def errors(self):
        return self.__errors