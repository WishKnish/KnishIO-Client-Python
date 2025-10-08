# -*- coding: utf-8 -*-
import aiohttp
import asyncio
from ..models import Coder
from ..libraries.array import array_get


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
        async with aiohttp.ClientSession(headers=options, json_serialize=Coder().encode) as session:
            async with session.post(self.get_url(), json=request, ssl=False) as response:
                return await response.json()