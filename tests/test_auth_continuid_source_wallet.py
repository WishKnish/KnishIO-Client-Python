# -*- coding: utf-8 -*-
"""
Profile authorization and the ContinuID pointer.
================================================
``request_profile_auth_token`` signs its U + I molecule from a fresh RANDOM-position AUTH wallet
and leaves that molecule's USER remainder (the I-atom wallet) cached. ``create_molecule`` used to
adopt that cached remainder as the source wallet whenever the last molecule query succeeded, so
the first molecule after every login was signed from the I-atom position.

Since validator 0.5.0 (two-tier rejection model) the I-atom of an UNPROVEN re-authorization --
every login after the first -- is no longer executed: no USER wallet is created at its position
and the ContinuID pointer does not move. The next molecule was then rejected with
``Wallet not found: bundle=..., position=...``. Resolving the source wallet through the
ContinuID query is correct against every validator version.

A returning user's login must itself be signed from the ContinuID pointer: the validator marks a
re-authorization proven only when atoms[0] is the USER wallet registered at the pointer, and an
unproven token is treated as a guest for permissioned and private cells. One login sends at most
two authorization molecules (testnet allows three per minute per IP).

Fully offline: the transport is stubbed at ``HttpClient.send``, so the real auth response and the
real ContinuId response parsing both run.
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

from knishioclient.client.KnishIOClient import KnishIOClient
from knishioclient.exception import InvalidResponseException, UnauthenticatedException
from knishioclient.libraries import crypto
from knishioclient.models import AuthToken, Wallet

SECRET = "a1b2c3d4e5f6" * 8
URL = "https://test.local/graphql"
POINTER_POSITION = "c0ffee" + "0" * 58


def continu_id_wallet(bundle, token="USER", position=POINTER_POSITION, address="a" * 64):
    return {
        "address": address,
        "bundleHash": bundle,
        "tokenSlug": token,
        "position": position,
        "batchId": None,
        "characters": "BASE64",
        "pubkey": None,
        "amount": "0",
        "createdAt": None,
    }


def propose_response(status):
    return {"data": {"ProposeMolecule": {
        "molecularHash": "0" * 64,
        "status": status,
        "reason": None if status == "accepted" else "forged signature",
        "payload": json.dumps({"token": "offline-auth-token", "key": None}) if status == "accepted" else None,
    }}}


class StubTransport:
    """Records every request; answers ContinuId with ``continu_id`` and each ProposeMolecule with
    the next status from ``statuses``."""

    def __init__(self, continu_id, statuses):
        self.continu_id = continu_id
        self.statuses = list(statuses)
        self.continu_id_requests = []
        self.proposals = []

    def send(self, request, options=None):
        query = request["query"]
        if "ContinuId" in query:
            self.continu_id_requests.append(request)
            return {"data": {"ContinuId": self.continu_id}}
        if "ProposeMolecule" in query:
            self.proposals.append(request["variables"]["molecule"])
            return propose_response(self.statuses.pop(0))
        raise AssertionError("unexpected request: %s" % query)


class AuthContinuIdSourceWalletTest(unittest.TestCase):
    def setUp(self):
        self.client = KnishIOClient(URL)
        self.client.set_cell_slug("public")
        self.bundle = crypto.generate_bundle_hash(SECRET)
        self.sent = []

    def _send(self, request, options=None):
        query = request["query"]
        self.sent.append(query)
        if "ContinuId" in query:
            return {"data": {"ContinuId": continu_id_wallet(self.bundle)}}
        if "ProposeMolecule" in query:
            return propose_response("accepted")
        raise AssertionError("unexpected request: %s" % query)

    def test_next_molecule_after_profile_auth_is_signed_from_the_continuid_pointer(self):
        client = self.client
        with mock.patch.object(client.client(), "send", side_effect=self._send), \
                mock.patch.object(client, "query_continu_id", wraps=client.query_continu_id) as query_continu_id:
            client.request_profile_auth_token(SECRET, encrypt=False)
            auth_remainder_position = client.get_remainder_wallet().position

            molecule = client.create_molecule()

        self.assertEqual(query_continu_id.call_args_list[-1], mock.call(client.bundle()))
        self.assertIn("ContinuId", self.sent[-1])
        self.assertNotEqual(auth_remainder_position, POINTER_POSITION)
        self.assertEqual(molecule.sourceWallet.position, POINTER_POSITION)


class ProvenReloginTest(unittest.TestCase):
    def setUp(self):
        self.bundle = crypto.generate_bundle_hash(SECRET)
        self.pointer_wallet = Wallet(secret=SECRET, token="USER", position=POINTER_POSITION)

    def _login(self, continu_id, statuses):
        client = KnishIOClient(URL)
        client.set_cell_slug("public")
        transport = StubTransport(continu_id, statuses)
        with mock.patch.object(client.client(), "send", side_effect=transport.send):
            try:
                response = client.request_profile_auth_token(SECRET, encrypt=False)
            except UnauthenticatedException as error:
                return client, transport, error
        return client, transport, response

    def _assert_queried_with_user_token(self, transport):
        self.assertEqual(len(transport.continu_id_requests), 1)
        request = transport.continu_id_requests[0]
        self.assertEqual(request["variables"], {"bundle": self.bundle, "token": "USER"})
        self.assertIn("token: $token", request["query"])

    def test_returning_user_login_is_signed_from_the_continuid_pointer(self):
        pointer = continu_id_wallet(self.bundle, address=self.pointer_wallet.address)
        client, transport, response = self._login(pointer, ["accepted"])

        self.assertTrue(response.success())
        self._assert_queried_with_user_token(transport)
        self.assertEqual(len(transport.proposals), 1)
        u_atom, i_atom = transport.proposals[0].atoms
        self.assertEqual(u_atom.isotope, "U")
        self.assertEqual(u_atom.token, "USER")
        self.assertEqual(u_atom.position, POINTER_POSITION)
        self.assertEqual(u_atom.walletAddress, self.pointer_wallet.address)
        self.assertEqual(u_atom.aggregated_meta()["walletPubkey"], self.pointer_wallet.pubkey)
        self.assertEqual(i_atom.isotope, "I")
        self.assertEqual(i_atom.token, "USER")
        self.assertNotEqual(i_atom.position, POINTER_POSITION)
        self.assertEqual(i_atom.aggregated_meta()["previousPosition"], POINTER_POSITION)
        # The token is bound to the pointer wallet, which decrypts CipherHash responses.
        bound = client.client()._HttpClient__wallet
        self.assertEqual(bound.token, "USER")
        self.assertEqual(bound.address, self.pointer_wallet.address)
        self.assertEqual(client.client().get_auth_token(), "offline-auth-token")

    def test_login_without_a_usable_user_pointer_signs_from_a_fresh_auth_wallet(self):
        cases = {
            "no ContinuID wallet": None,
            "non-USER wallet": continu_id_wallet(self.bundle, token="AUTH", address=None),
            "empty position": continu_id_wallet(self.bundle, position="", address=None),
            "address mismatch": continu_id_wallet(self.bundle, address="f" * 64),
        }
        for name, continu_id in cases.items():
            client, transport, response = self._login(continu_id, ["accepted"])

            self.assertTrue(response.success(), name)
            self._assert_queried_with_user_token(transport)
            self.assertEqual(len(transport.proposals), 1, name)
            u_atom = transport.proposals[0].atoms[0]
            self.assertEqual(u_atom.isotope, "U", name)
            self.assertEqual(u_atom.token, "AUTH", name)
            self.assertNotEqual(u_atom.position, POINTER_POSITION, name)
            self.assertEqual(client.client()._HttpClient__wallet.token, "AUTH", name)

    def test_rejected_pointer_login_falls_back_once_to_a_fresh_auth_wallet(self):
        pointer = continu_id_wallet(self.bundle, address=self.pointer_wallet.address)
        with self.assertLogs("knishioclient.client.KnishIOClient", level="WARNING") as logs:
            client, transport, response = self._login(pointer, ["rejected", "accepted"])

        self.assertTrue(response.success())
        self.assertIn("forged signature", "\n".join(logs.output))
        self.assertEqual(len(transport.continu_id_requests), 1)
        self.assertEqual([proposal.atoms[0].token for proposal in transport.proposals], ["USER", "AUTH"])
        self.assertEqual(client.client()._HttpClient__wallet.token, "AUTH")

    def test_rejected_fallback_raises_and_sends_no_third_molecule(self):
        pointer = continu_id_wallet(self.bundle, address=self.pointer_wallet.address)
        _, transport, error = self._login(pointer, ["rejected", "rejected"])

        self.assertIsInstance(error, UnauthenticatedException)
        self.assertIn("Profile authentication failed: forged signature", str(error))
        self.assertEqual([proposal.atoms[0].token for proposal in transport.proposals], ["USER", "AUTH"])

    def test_continuid_query_errors_propagate_without_proposing(self):
        client = KnishIOClient(URL)
        client.set_cell_slug("public")
        proposals = []

        def send(request, options=None):
            if "ProposeMolecule" in request["query"]:
                proposals.append(request)
                return propose_response("accepted")
            return {"data": {"ContinuId": None}, "errors": [{"message": "database unavailable"}]}

        with mock.patch.object(client.client(), "send", side_effect=send):
            with self.assertRaisesRegex(InvalidResponseException, "database unavailable"):
                client.request_profile_auth_token(SECRET, encrypt=False)
        self.assertEqual(proposals, [])


class AuthTokenSnapshotTest(unittest.TestCase):
    DATA = {"token": "t", "expiresAt": 4102444800, "pubkey": None, "encrypt": False}

    def test_snapshot_of_a_user_bound_token_restores_the_user_wallet(self):
        wallet = Wallet(secret=SECRET, token="USER", position=POINTER_POSITION)
        snapshot = AuthToken.create(self.DATA, wallet).get_snapshot()

        restored = AuthToken.restore(snapshot, SECRET).get_wallet()

        self.assertEqual(restored.token, "USER")
        self.assertEqual(restored.address, wallet.address)
        self.assertEqual(restored.pubkey, wallet.pubkey)

    def test_snapshot_without_a_wallet_token_restores_an_auth_wallet(self):
        wallet = Wallet(secret=SECRET, token="AUTH", position=POINTER_POSITION)
        snapshot = AuthToken.create(self.DATA, wallet).get_snapshot()
        snapshot["wallet"].pop("token", None)

        restored = AuthToken.restore(snapshot, SECRET).get_wallet()

        self.assertEqual(restored.token, "AUTH")
        self.assertEqual(restored.address, wallet.address)


if __name__ == "__main__":
    unittest.main()
