# -*- coding: utf-8 -*-
import json
import re
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
        # The top-level response field is the first identifier inside the outermost
        # selection set, e.g. "query( $b: String ) { Balance( ... ) @fields }" -> "Balance".
        # The previous split('(')/split(')') heuristic returned '' for any query that
        # declared variables (the common "query( $... ) { Field }" form), so every live
        # query whose Response did not override data_key() (e.g. ResponseBalance) failed
        # to parse. Find the first identifier after the opening brace instead.
        query = self.query.query
        brace = query.find('{')
        if brace == -1:
            return ''
        match = re.search(r'[A-Za-z_][A-Za-z0-9_]*', query[brace + 1:])
        return match.group(0) if match else ''

    def data(self):
        return self.__data

    def __str__(self):
        return json.dumps(self.data())

    def payload(self):
        return self.data()

    def errors(self):
        return self.__errors