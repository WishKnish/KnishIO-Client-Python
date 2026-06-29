# -*- coding: utf-8 -*-
"""
Live ML-KEM768 CipherHash encrypted-transport round-trip against a running validator
(PQ-transport Phase E, cycle 167 — Python).

End-to-end: the client authenticates (conveying its AUTH source wallet's ML-KEM public key via a
signed walletPubkey U-atom meta), then issues an encrypted query_balance — the validator
ML-KEM-decrypts the request, executes it, and encrypts the response back to the client's ML-KEM
pubkey, which the client decrypts. The transport must be TRANSPARENT, so we assert the encrypted
result's DATA equals a plaintext baseline (not merely that both succeed).

Gated on CIPHERHASH_TEST_URL (skips cleanly when unset → CI-safe). Run live:
  CIPHERHASH_TEST_URL=http://localhost:8081/graphql python -m pytest tests/test_cipherhash_live.py -v
"""
import os
import unittest

from knishioclient.client import KnishIOClient
from knishioclient.libraries import crypto


class CipherHashLiveTest(unittest.TestCase):
    def test_encrypted_round_trip_matches_plaintext(self):
        url = os.environ.get('CIPHERHASH_TEST_URL')
        if not url:
            self.skipTest('CIPHERHASH_TEST_URL not set — skipping live CipherHash test')

        secret = crypto.generate_secret()

        # ONE authenticated session (encrypt=True → conveys the AUTH wallet's ML-KEM pubkey as a
        # signed walletPubkey U-atom meta, so the validator can encrypt responses back to it). We
        # vary ONLY the transport on this SAME session — the queried balance wallet stays fixed.
        # (A fresh second auth would rotate the USER remainder via ContinuID → a different address/
        # position/pubkey: correct protocol behaviour, NOT a transport bug.)
        client = KnishIOClient(url)
        client.set_cell_slug('public')   # the active dev cell (TESTCELL is inactive there)
        client.request_auth_token(secret, 'public', encrypt=True)

        # Encrypted round-trip: the validator ML-KEM-decrypts the request, executes it, and encrypts
        # the response back to the client's ML-KEM pubkey; the client decrypts it.
        enc_resp = client.query_balance('USER')

        # Plaintext baseline of the SAME wallet on the SAME authed session — only the transport differs.
        client.switch_encryption(False)
        plain_resp = client.query_balance('USER')

        enc = enc_resp.payload()
        plain = plain_resp.payload()

        # The PQ transport must be transparent: not just a non-error response, but the SAME data.
        # A null decrypted payload would mean the transport silently dropped the data.
        self.assertIsNotNone(enc, 'encrypted query_balance payload must not be null — the transport must deliver data')
        self.assertIsNotNone(plain, 'plaintext query_balance payload must not be null')

        # Same authed session → identical balance wallet → its deterministic identity fields match.
        self.assertEqual(plain.address, enc.address)
        self.assertEqual(plain.position, enc.position)
        self.assertEqual(plain.pubkey, enc.pubkey)
        self.assertEqual(plain.token, enc.token)
        self.assertEqual(plain.bundle, enc.bundle)


if __name__ == '__main__':
    unittest.main()
