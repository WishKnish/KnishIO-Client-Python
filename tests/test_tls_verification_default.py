# -*- coding: utf-8 -*-
"""
TLS certificates are verified by default.
=========================================
``HttpClient`` used to post every request with ``ssl=False``, which turns off aiohttp's
certificate and hostname checks: any party on the network path could present its own certificate
and read or rewrite the traffic. Verification is now aiohttp's default; ``insecure_tls=True`` is
the explicit opt-out for a node with a self-signed certificate (``insecure_tls`` in the Rust and C
SDKs, ``insecureTls`` in Kotlin and C++).
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

# Ensure the SDK root is importable
SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if SDK_ROOT not in sys.path:
    sys.path.insert(0, SDK_ROOT)

from knishioclient.client.HttpClient import HttpClient
from knishioclient.client.KnishIOClient import KnishIOClient

URL = "https://test.local/graphql"
INTROSPECTION_REQUEST = {"query": "query { __schema { types { name } } }", "variables": {}}


class _FakeResponse(object):
    async def json(self):
        return {"data": {}}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession(object):
    """Stands in for aiohttp.ClientSession and records the keyword arguments of every post."""

    posts = []
    closed = False

    def __init__(self, *args, **kwargs):
        pass

    async def close(self):
        pass

    def post(self, url, **kwargs):
        _FakeSession.posts.append(kwargs)
        return _FakeResponse()


class TlsVerificationDefaultTest(unittest.TestCase):
    def setUp(self):
        _FakeSession.posts = []
        patcher = mock.patch("aiohttp.ClientSession", _FakeSession)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _sent_kwargs(self, client):
        client.send(dict(INTROSPECTION_REQUEST))
        self.assertEqual(1, len(_FakeSession.posts))
        return _FakeSession.posts[0]

    def test_certificates_are_verified_by_default(self):
        kwargs = self._sent_kwargs(HttpClient(URL))

        self.assertNotIn("ssl", kwargs)

    def test_insecure_tls_is_an_explicit_opt_in(self):
        kwargs = self._sent_kwargs(HttpClient(URL, insecure_tls=True))

        self.assertIs(False, kwargs["ssl"])

    def test_client_passes_the_opt_in_through(self):
        kwargs = self._sent_kwargs(KnishIOClient(URL, insecure_tls=True).client())
        self.assertIs(False, kwargs["ssl"])

        _FakeSession.posts = []
        kwargs = self._sent_kwargs(KnishIOClient(URL).client())
        self.assertNotIn("ssl", kwargs)


if __name__ == "__main__":
    unittest.main()
