# -*- coding: utf-8 -*-
"""
Encrypted transport must fail CLOSED (PQ-transport Phase E).
============================================================
An encryption-enabled client with no authorized wallet or no validator ML-KEM public key used to
fall through to the plaintext body: the envelope was gated on
``self.__encrypt and self.__wallet is not None and self.__pubkey is not None and ...`` and, when
that was false, ``payload = request`` went on the wire unencrypted. The caller asked for an
encrypted transport and silently got none.

PHP (Libraries/Cipher.php) and Kotlin (httpClient/HttpClient.kt) already raised
``Authorized wallet missing.`` / ``Server public key missing.`` here; these tests pin the same
behaviour for Python.

The bypass set must keep working: the auth bootstrap (``__schema``, ``ContinuId``,
``AccessToken``, U-isotope ``ProposeMolecule``) cannot be encrypted, because the server pubkey is
what it is fetching.
"""

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

# Ensure the SDK root is importable
SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if SDK_ROOT not in sys.path:
    sys.path.insert(0, SDK_ROOT)

from knishioclient.client.HttpClient import HttpClient
from knishioclient.exception import CodeException
from knishioclient.models.Wallet import Wallet
from knishioclient.models.Molecule import Molecule
from knishioclient.libraries import crypto

SECRET = "a1b2c3d4e5f6" * 8
URL = "https://test.local/graphql"
BALANCE_REQUEST = {"query": 'query B { Balance(token: "USER") { address } }', "variables": {}}
INTROSPECTION_REQUEST = {"query": "query { __schema { types { name } } }", "variables": {}}
PROPOSE_QUERY = "mutation( $molecule: MoleculeInput! ) { ProposeMolecule( molecule: $molecule ) {status} }"


class _FakeResponse(object):
    async def json(self):
        return {"data": {}}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession(object):
    """Stands in for aiohttp.ClientSession and records every payload that reaches the wire."""

    sent = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def post(self, url, json=None, ssl=None):
        _FakeSession.sent.append(json)
        return _FakeResponse()


class EncryptedTransportFailClosedTest(unittest.TestCase):
    def setUp(self):
        _FakeSession.sent = []
        patcher = mock.patch("aiohttp.ClientSession", _FakeSession)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_refuses_to_send_a_normal_operation_without_a_wallet(self):
        client = HttpClient(URL)
        client.set_encryption(True)

        with self.assertRaises(CodeException) as ctx:
            client.send(BALANCE_REQUEST)

        self.assertEqual("Authorized wallet missing.", str(ctx.exception.args[0]))
        # The decisive assertion: nothing at all went on the wire.
        self.assertEqual([], _FakeSession.sent)

    def test_refuses_when_only_the_validator_pubkey_is_missing(self):
        client = HttpClient(URL)
        client.set_encryption(True)
        client.set_auth_data("T", pubkey=None, wallet=Wallet(secret=SECRET, token="AUTH"))

        with self.assertRaises(CodeException) as ctx:
            client.send(BALANCE_REQUEST)

        self.assertEqual("Server public key missing.", str(ctx.exception.args[0]))
        self.assertEqual([], _FakeSession.sent)

    def test_refuses_when_the_validator_pubkey_is_empty(self):
        # An empty advertised key is not a key. JS/TS treat it as missing (`!serverPubkey`); if
        # Python let it through, encrypt_string_ml would fail on a length check instead of naming
        # the real problem, and a caller could not tell the two apart.
        client = HttpClient(URL)
        client.set_encryption(True)
        client.set_auth_data("T", pubkey="", wallet=Wallet(secret=SECRET, token="AUTH"))

        with self.assertRaises(CodeException) as ctx:
            client.send(BALANCE_REQUEST)

        self.assertEqual("Server public key missing.", str(ctx.exception.args[0]))
        self.assertEqual([], _FakeSession.sent)

    def test_still_sends_a_bypassed_operation_in_plaintext(self):
        client = HttpClient(URL)
        client.set_encryption(True)

        client.send(INTROSPECTION_REQUEST)

        self.assertEqual([INTROSPECTION_REQUEST], _FakeSession.sent)

    def test_wraps_the_operation_in_the_cipher_hash_envelope_when_keyed(self):
        wallet = Wallet(secret=SECRET, token="AUTH")
        client = HttpClient(URL)
        client.set_encryption(True)
        client.set_auth_data("T", pubkey=wallet.pubkey, wallet=wallet)

        client.send(BALANCE_REQUEST)

        self.assertEqual(1, len(_FakeSession.sent))
        payload = _FakeSession.sent[0]
        self.assertIn("CipherHash", payload["query"])
        self.assertIsInstance(payload["variables"]["Hash"], str)
        self.assertNotIn("Balance", payload["variables"]["Hash"])


class EncryptedProposeMoleculeTest(unittest.TestCase):
    """A ProposeMolecule request carries the Molecule model itself (``Coder`` serializes it on the
    wire), not a dict. The U-isotope bypass read ``molecule.get('atoms')`` and raised
    AttributeError, so an encryption-enabled session could propose nothing -- not even the next
    login -- and encrypting a non-U molecule failed to serialize the model."""

    def setUp(self):
        _FakeSession.sent = []
        patcher = mock.patch("aiohttp.ClientSession", _FakeSession)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.wallet = Wallet(secret=SECRET, token="AUTH")
        self.client = HttpClient(URL)
        self.client.set_encryption(True)
        self.client.set_auth_data("T", pubkey=self.wallet.pubkey, wallet=self.wallet)
        self.bundle = crypto.generate_bundle_hash(SECRET)

    def _molecule(self):
        return Molecule(
            secret=SECRET,
            bundle=self.bundle,
            source_wallet=Wallet(secret=SECRET, token="USER"),
            remainder_wallet=Wallet.create(SECRET, self.bundle, "USER"),
        )

    def test_an_authorization_molecule_is_sent_in_plaintext(self):
        molecule = self._molecule().init_authorization(True)
        request = {"query": PROPOSE_QUERY, "variables": {"molecule": molecule}}

        self.client.send(request)

        self.assertEqual([request], _FakeSession.sent)

    def test_a_non_u_molecule_is_encrypted_with_its_atoms(self):
        molecule = self._molecule()
        molecule.add_continue_id_atom()
        request = {"query": PROPOSE_QUERY, "variables": {"molecule": molecule}}

        self.client.send(request)

        self.assertEqual(1, len(_FakeSession.sent))
        payload = _FakeSession.sent[0]
        self.assertIn("CipherHash", payload["query"])
        inner = self.wallet.decrypt_my_message_ml(json.loads(payload["variables"]["Hash"]))
        atoms = inner["variables"]["molecule"]["atoms"]
        self.assertEqual(["I"], [atom["isotope"] for atom in atoms])
        self.assertEqual(molecule.atoms[0].position, atoms[0]["position"])



class AuthMoleculeEncryptMetaTest(unittest.TestCase):
    """The validator reads the session's transport mode from the SIGNED `encrypt` meta on the
    U-atom (`extract_encrypt_flag`, comparing against the literal "true"). Python used to omit it
    entirely, so every Python profile session was persisted as plaintext no matter what the caller
    requested, and the validator's encrypted-transport enforcement could never apply to it."""

    def _auth_molecule(self, encrypt):
        bundle = crypto.generate_bundle_hash(SECRET)
        source = Wallet(secret=SECRET, token="AUTH")
        remainder = Wallet.create(SECRET, bundle, "USER")
        molecule = Molecule(
            secret=SECRET, bundle=bundle, source_wallet=source, remainder_wallet=remainder
        )
        return molecule.init_authorization(encrypt)

    def _u_atom(self, encrypt):
        return next(atom for atom in self._auth_molecule(encrypt).atoms if atom.isotope == "U")

    def test_signed_encrypt_meta_mirrors_the_request(self):
        for requested, literal in ((True, "true"), (False, "false")):
            with self.subTest(encrypt=requested):
                u_atom = self._u_atom(requested)
                self.assertEqual(
                    [{"key": "encrypt", "value": literal}],
                    [meta for meta in u_atom.meta if meta["key"] == "encrypt"],
                )
                # Emitted first, as C (molecule.c) and C++ (Molecule.cpp) do.
                self.assertEqual("encrypt", u_atom.meta[0]["key"])

    def test_default_is_a_plaintext_session(self):
        self.assertIn({"key": "encrypt", "value": "false"}, self._u_atom(False).meta)


if __name__ == "__main__":
    unittest.main()
