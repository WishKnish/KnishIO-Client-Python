# -*- coding: utf-8 -*-
"""
After a profile authorization, the next molecule must be signed from the ContinuID pointer.
==========================================================================================
``request_profile_auth_token`` signs its U + I molecule from a fresh RANDOM-position AUTH wallet
and leaves that molecule's USER remainder (the I-atom wallet) cached. ``create_molecule`` used to
adopt that cached remainder as the source wallet whenever the last molecule query succeeded, so
the first molecule after every login was signed from the I-atom position.

Since validator 0.5.0 (two-tier rejection model) the I-atom of an UNPROVEN re-authorization --
every login after the first -- is no longer executed: no USER wallet is created at its position
and the ContinuID pointer does not move. The next molecule was then rejected with
``Wallet not found: bundle=..., position=...``. Resolving the source wallet through the
ContinuID query is correct against every validator version.

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
from knishioclient.libraries import crypto

SECRET = "a1b2c3d4e5f6" * 8
URL = "https://test.local/graphql"
POINTER_POSITION = "c0ffee" + "0" * 58


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
            return {"data": {"ContinuId": {
                "address": "a" * 64,
                "bundleHash": self.bundle,
                "tokenSlug": "USER",
                "position": POINTER_POSITION,
                "batchId": None,
                "characters": "BASE64",
                "pubkey": None,
                "amount": "0",
                "createdAt": None,
            }}}
        if "ProposeMolecule" in query:
            return {"data": {"ProposeMolecule": {
                "molecularHash": "0" * 64,
                "status": "accepted",
                "reason": None,
                "payload": json.dumps({"token": "offline-auth-token", "key": None}),
            }}}
        raise AssertionError("unexpected request: %s" % query)

    def test_next_molecule_after_profile_auth_is_signed_from_the_continuid_pointer(self):
        client = self.client
        with mock.patch.object(client.client(), "send", side_effect=self._send), \
                mock.patch.object(client, "query_continu_id", wraps=client.query_continu_id) as query_continu_id:
            client.request_profile_auth_token(SECRET, encrypt=False)
            auth_remainder_position = client.get_remainder_wallet().position

            molecule = client.create_molecule()

        query_continu_id.assert_called_once_with(client.bundle())
        self.assertIn("ContinuId", self.sent[-1])
        self.assertNotEqual(auth_remainder_position, POINTER_POSITION)
        self.assertEqual(molecule.sourceWallet.position, POINTER_POSITION)


if __name__ == "__main__":
    unittest.main()
