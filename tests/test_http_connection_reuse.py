# -*- coding: utf-8 -*-
"""
HttpClient must reuse its TCP connection across requests.
=========================================================
Up to 1.7.0 every request opened its own aiohttp.ClientSession, so every request cost a new TCP
connection. A client submitting at a sustained rate left tens of thousands of sockets in TIME_WAIT
and ran out of local ports ("Cannot assign requested address"). These tests count the connections
a keep-alive server actually sees.
"""

import asyncio
import gc
import json
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if SDK_ROOT not in sys.path:
    sys.path.insert(0, SDK_ROOT)

from knishioclient.client.HttpClient import HttpClient

REQUEST = {"query": "query { __schema { types { name } } }", "variables": {}}
SENDS = 5


class _Server(ThreadingHTTPServer):
    def __init__(self, handler=None):
        super().__init__(("127.0.0.1", 0), handler or _Handler)
        self.client_ports = []  # one entry per request: the client's source port


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.client_ports.append(self.client_address[1])  # type: ignore[attr-defined]
        body = json.dumps({"data": {}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class _IdleClosingHandler(_Handler):
    timeout = 1  # close a keep-alive connection after 1 s without a request, as proxies do


class HttpConnectionReuseTest(unittest.TestCase):
    def setUp(self):
        self.server = _Server()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = "http://127.0.0.1:%d/graphql" % self.server.server_address[1]
        self.client = HttpClient(self.url)
        # The client's finalizer, which also runs when it is garbage-collected.
        self.addCleanup(self.client._HttpClient__close)

    def assert_one_connection(self):
        self.assertEqual(SENDS, len(self.server.client_ports))
        self.assertEqual(1, len(set(self.server.client_ports)), self.server.client_ports)

    def test_sync_sends_share_one_connection(self):
        for _ in range(SENDS):
            self.assertEqual({"data": {}}, self.client.send(dict(REQUEST)))
        self.assert_one_connection()

    def test_sends_from_inside_a_running_loop_share_one_connection(self):
        async def caller():
            return [self.client.send(dict(REQUEST)) for _ in range(SENDS)]

        loop = asyncio.new_event_loop()
        try:
            self.assertEqual([{"data": {}}] * SENDS, loop.run_until_complete(caller()))
        finally:
            loop.close()
        self.assert_one_connection()

    def test_a_connection_the_server_closed_while_idle_is_not_reused(self):
        server = _Server(_IdleClosingHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client = HttpClient("http://127.0.0.1:%d/graphql" % server.server_address[1])
        self.addCleanup(client._HttpClient__close)

        self.assertEqual({"data": {}}, client.send(dict(REQUEST)))
        time.sleep(2)
        self.assertEqual({"data": {}}, client.send(dict(REQUEST)))
        self.assertEqual(2, len(set(server.client_ports)))

    def test_collecting_the_client_stops_its_loop_thread(self):
        thread = self._loop_thread_of_a_used_client()
        gc.collect()
        thread.join(5)
        self.assertFalse(thread.is_alive())

    def _loop_thread_of_a_used_client(self):
        client = HttpClient(self.url)
        client.send(dict(REQUEST))
        thread = client._HttpClient__transport._thread
        self.assertTrue(thread.is_alive())
        return thread


if __name__ == "__main__":
    unittest.main()
