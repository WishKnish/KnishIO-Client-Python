# -*- coding: utf-8 -*-
"""
Live OTS version migration against a running validator: an identity created by a client at OTS
version 1 moves to version 2 when a client set to version 2 signs in, and stays at version 2 when a
client at version 1 signs in afterwards.

Gated on OTS_MIGRATION_TEST_URL (skips cleanly when unset):
  OTS_MIGRATION_TEST_URL=http://localhost:8081/graphql python -m pytest tests/test_ots_migration_live.py -v
"""
import os
import time
import unittest

from knishioclient.client import KnishIOClient
from knishioclient.libraries import crypto
from knishioclient.models.Wallet import Wallet

URL = os.environ.get('OTS_MIGRATION_TEST_URL')


@unittest.skipUnless(URL, 'OTS_MIGRATION_TEST_URL not set — skipping live OTS migration test')
class OtsMigrationLiveTest(unittest.TestCase):
    def test_client_at_ots_version_2_moves_a_version_1_identity_to_version_2(self):
        secret = crypto.generate_secret()
        bundle = crypto.generate_bundle_hash(secret)

        def client(ots_version):
            knishio = KnishIOClient(URL, ots_version=ots_version)
            knishio.set_cell_slug('public')
            knishio.request_auth_token(secret, 'public', encrypt=False)
            return knishio

        def head(knishio):
            wallet = knishio.query_continu_id(bundle, 'USER').payload()
            self.assertIsNotNone(wallet)
            return wallet

        def version(wallet):
            return Wallet.detect_ots_version(secret, 'USER', wallet.position, wallet.address, 1)

        # A client at version 1 creates the identity
        first = client(1)
        h1 = head(first)
        self.assertEqual(version(h1), 1)

        # A client at version 2 signs in from the version 1 head and leaves a version 2 head
        second = client(2)
        h2 = head(second)
        self.assertNotEqual(h2.position, h1.position)
        self.assertEqual(version(h2), 2)

        # The version 2 head signs a molecule
        meta = second.create_meta('ots-migration', f'ots-migration-{int(time.time() * 1000)}', {'k': 'v'})
        self.assertTrue(meta.success(), meta.reason())
        h3 = head(second)
        self.assertNotEqual(h3.position, h2.position)
        self.assertEqual(version(h3), 2)

        # A client at version 1 signs in and the identity stays at version 2
        third = client(1)
        h4 = head(third)
        self.assertNotEqual(h4.position, h3.position)
        self.assertEqual(version(h4), 2)


if __name__ == '__main__':
    unittest.main()
