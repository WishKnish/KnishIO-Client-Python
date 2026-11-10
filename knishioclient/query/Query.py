# -*- coding: utf-8 -*-
from ..response import Response


class Query(object):
    query: str
    default_query: str
    fields: dict
    __variables: dict

    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        self.__variables = {}
        self.fields = {}
        self.default_query = ''
        self.query = query or self.default_query
        self.__request = None
        self.__response = None
        self.knishIO = knish_io_client

    def get_knish_io_client(self):
        return self.knishIO

    def client(self):
        return self.knishIO.client()

    def request(self):
        return self.__request

    def response(self):
        return self.__response

    def execute(self, variables: dict = None, fields: dict = None):
        self.__request = self.create_request(variables, fields)
        response = self.client().send(self.__request)
        self.__response = self.create_response_raw(response)

        return self.response()

    def create_response_raw(self, response: dict):
        return self.create_response(response)

    def create_response(self, response: dict):
        return Response(self, response)

    def create_request(self, variables: dict = None, fields: dict = None):
        self.__variables = self.compiled_variables(variables)

        return {
            "query": self.compiled_query(fields),
            "variables": variables,
        }

    def compiled_variables(self, variables: dict = None):
        return variables or {}

    def compiled_query(self, fields: dict = None):
        if fields is not None:
            self.fields = fields

        return self.query.replace('@fields', self.compiled_fields(self.fields))

    def compiled_fields(self, fields: dict):
        return '{%s}' % ','.join(
            [key if fields[key] is None else '%s%s' % (key, self.compiled_fields(fields[key])) for key in fields.keys()]
        )

    def url(self):
        return self.knishIO.url()

    def variables(self):
        return self.__variables