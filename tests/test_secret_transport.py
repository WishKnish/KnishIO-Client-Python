# -*- coding: utf-8 -*-
"""
Secret handling and the encrypted transport:
- AES-GCM IVs come from the OS CSPRNG (os.urandom), not numpy's Mersenne Twister;
- the Node ML-KEM bridge receives seeds and secret keys on stdin, never in argv, and its errors
  do not echo them;
- a guest session asked to encrypt binds the token, the validator's key and its wallet to the
  transport and turns encryption on (JS requestGuestAuthToken / setAuthToken);
- a missing libkcore under KNISHIO_KCORE=require propagates; an undecryptable message is None.
"""

import base64
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from knishioclient.client import KnishIOClient
from knishioclient.client.HttpClient import HttpClient
from knishioclient.exception import CodeException
from knishioclient.libraries import crypto, kcore
from knishioclient.libraries.NobleMLKEMBridge import NobleMLKEMBridge
from knishioclient.models.Wallet import Wallet

SECRET = crypto.generate_secret('fleet-audit-2026-11')


class IvSourceTest(unittest.TestCase):

    def test_iv_does_not_come_from_numpy(self):
        key = bytes(range(32))
        with mock.patch('numpy.random.bytes', side_effect=AssertionError('numpy.random.bytes used for an IV')):
            first = Wallet.encrypt_with_shared_secret(b'message', key)
            second = Wallet.encrypt_with_shared_secret(b'message', key)
        self.assertNotEqual(first[:12], second[:12])
        self.assertEqual(b'message', Wallet.decrypt_with_shared_secret(first, key))


class BridgeArgvTest(unittest.TestCase):

    def setUp(self):
        if not NobleMLKEMBridge.is_available():
            self.skipTest('Node ML-KEM bridge not installed (bin/node_modules)')
        self.calls = []
        real_run = subprocess.run

        def spy(*args, **kwargs):
            self.calls.append((args, kwargs))
            return real_run(*args, **kwargs)

        patcher = mock.patch('knishioclient.libraries.NobleMLKEMBridge.subprocess.run', side_effect=spy)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _argv(self):
        return [' '.join(map(str, call[0][0])) for call in self.calls]

    def test_keygen_encaps_decaps_keep_secrets_out_of_argv(self):
        seed = crypto.shake256(SECRET, 512)
        public_key, secret_key = NobleMLKEMBridge.generate_keypair_from_seed(seed, 1024)
        ciphertext, shared = NobleMLKEMBridge.encapsulate(public_key)
        self.assertEqual(shared, NobleMLKEMBridge.decapsulate(ciphertext, secret_key))

        secret_b64 = base64.b64encode(secret_key).decode()
        self.assertEqual(3, len(self.calls))
        for argv in self._argv():
            self.assertNotIn(seed, argv)
            self.assertNotIn(secret_b64, argv)
        requests = [json.loads(call[1]['input']) for call in self.calls]
        self.assertEqual(['keygen', 'encaps', 'decaps'], [request['command'] for request in requests])
        self.assertEqual([seed, '1024'], requests[0]['args'])
        self.assertEqual(secret_b64, requests[2]['args'][1])

    def test_bridge_keys_match_the_wallet_derivation(self):
        # The wallet derives its key through libkcore when it is loaded (KNISHIO_KCORE=require), so
        # this pins the bridge to the same keys; with KNISHIO_KCORE=off both sides use the bridge.
        wallet = Wallet(secret=SECRET, token='USER', position='aa' * 32)
        bridge_public, _ = NobleMLKEMBridge.generate_keypair_from_seed(crypto.generate_secret(wallet.key, 128), 1024)
        self.assertEqual(wallet.pubkey, Wallet.serialize_key(bridge_public))

    def test_errors_do_not_echo_the_request(self):
        public_key, secret_key = NobleMLKEMBridge.generate_keypair_from_seed(crypto.shake256(SECRET, 512), 1024)
        ciphertext, _ = NobleMLKEMBridge.encapsulate(public_key)
        truncated = secret_key[:100]
        with self.assertRaises(RuntimeError) as raised:
            NobleMLKEMBridge.decapsulate(ciphertext, truncated)
        message = str(raised.exception)
        self.assertNotIn(base64.b64encode(truncated).decode(), message)
        self.assertNotIn('Command:', message)
        self.assertIn('Unexpected ciphertext', message)

    def test_node_is_found_without_which(self):
        with mock.patch.object(NobleMLKEMBridge, '_initialized', False), \
                mock.patch.object(NobleMLKEMBridge, '_node_command', None), \
                mock.patch('knishioclient.libraries.NobleMLKEMBridge.shutil.which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'Node.js not found'):
                NobleMLKEMBridge._initialize()
        for call in self.calls:
            self.assertNotEqual('which', call[0][0][0])


class GuestEncryptionTest(unittest.TestCase):

    def test_guest_session_with_encrypt_binds_the_transport(self):
        client = KnishIOClient('https://example.invalid')
        response = mock.Mock(success=lambda: True, token=lambda: 'guest-token', pub_key=lambda: 'server-key')
        query = mock.Mock(execute=mock.Mock(return_value=response))
        with mock.patch.object(type(client), 'create_query', return_value=query):
            client.request_guest_auth_token('public', encrypt=True)

        variables = query.execute.call_args[0][0]
        transport = client.client()
        self.assertTrue(transport.has_encryption())
        self.assertEqual('guest-token', transport.get_auth_token())
        self.assertEqual('server-key', transport._HttpClient__pubkey)
        wallet = transport._HttpClient__wallet
        self.assertEqual('AUTH', wallet.token)
        self.assertEqual(variables['pubkey'], wallet.pubkey)
        self.assertTrue(variables['encrypt'])

    def test_guest_session_without_encrypt_stays_plaintext(self):
        client = KnishIOClient('https://example.invalid')
        response = mock.Mock(success=lambda: True, token=lambda: 'guest-token', pub_key=lambda: 'server-key')
        with mock.patch.object(type(client), 'create_query', return_value=mock.Mock(execute=lambda variables: response)):
            client.request_guest_auth_token('public', encrypt=False)
        self.assertFalse(client.client().has_encryption())
        self.assertEqual('guest-token', client.client().get_auth_token())


class DecryptFailureTest(unittest.TestCase):

    def setUp(self):
        self.wallet = Wallet(secret=SECRET, token='AUTH', position='aa' * 32)

    def test_tampered_message_is_none(self):
        envelope = self.wallet.encrypt_message({'a': 1}, self.wallet.pubkey)
        self.assertEqual({'a': 1}, self.wallet.decrypt_message(envelope))
        raw = bytearray(base64.b64decode(envelope['encryptedMessage']))
        raw[-1] ^= 1
        self.assertIsNone(self.wallet.decrypt_message({**envelope, 'encryptedMessage': base64.b64encode(raw).decode()}))

    def test_kcore_unavailable_propagates_from_wallet_and_transport(self):
        envelope = self.wallet.encrypt_message({'a': 1}, self.wallet.pubkey)
        with mock.patch.object(crypto, 'noble_bridge_decaps', side_effect=kcore.KcoreUnavailable('no libkcore')):
            with self.assertRaises(kcore.KcoreUnavailable):
                self.wallet.decrypt_message(envelope)

        client = HttpClient('https://example.invalid')
        client.set_encryption(True)
        client.set_auth_data('T', pubkey=self.wallet.pubkey, wallet=self.wallet)
        reply = {'data': {'CipherHash': {'hash': json.dumps({'x': envelope})}}}

        class _Response:
            async def json(self):
                return reply

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

        class _Session:
            def post(self, *args, **kwargs):
                return _Response()

        request = {'query': 'query { Balance { address } }', 'variables': {}}
        with mock.patch.object(client._HttpClient__transport, 'session', return_value=_Session()), \
                mock.patch.object(Wallet, 'decrypt_my_message_ml', side_effect=kcore.KcoreUnavailable('no libkcore')):
            with self.assertRaises(kcore.KcoreUnavailable):
                client.send(request)
        with mock.patch.object(client._HttpClient__transport, 'session', return_value=_Session()), \
                mock.patch.object(Wallet, 'decrypt_my_message_ml', side_effect=ValueError('bad envelope')):
            with self.assertRaises(CodeException):
                client.send(request)


if __name__ == '__main__':
    unittest.main()
