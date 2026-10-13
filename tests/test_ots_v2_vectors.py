# -*- coding: utf-8 -*-
"""
OTS v2 (docs/OTS_V2_SPECIFICATION.md): key derivation, address, the normalized hash, ML-KEM
identities of v2 wallets, molecule verdicts and the malformed declared hash.

The vector suite reads the shared master ../shared-test-results/ots-v2-vectors.json (relative to
the SDK root). A standalone checkout of this SDK has no master, so that suite registers one
visible skip. The v2 round trip below needs no vectors and always runs.
"""

import json
import sys
import unittest
from pathlib import Path

SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from unittest import mock

from knishioclient.client import KnishIOClient
from knishioclient.exception import SignatureMalformedException, SignatureMismatchException, WalletCredentialException
from knishioclient.models.AuthToken import AuthToken
from knishioclient.libraries import check, crypto
from knishioclient.models.Molecule import Molecule
from knishioclient.models.Wallet import Wallet

VECTORS_PATH = SDK_ROOT.parent / 'shared-test-results' / 'ots-v2-vectors.json'
VECTORS = json.loads(VECTORS_PATH.read_text(encoding='utf-8'))['vectors'] if VECTORS_PATH.exists() else None

EXCEPTIONS = {
    'SignatureMismatch': SignatureMismatchException,
    'SignatureMalformed': SignatureMalformedException,
}


def _key_vector(name: str) -> dict:
    return next(k for k in VECTORS['key_derivation']['tests'] if k['name'] == name)


@unittest.skipUnless(VECTORS is not None, 'ots-v2-vectors.json not found (standalone checkout)')
class OtsV2VectorTest(unittest.TestCase):

    def test_key_derivation_and_address(self):
        for vector in VECTORS['key_derivation']['tests']:
            with self.subTest(vector['name']):
                secret, token, position = vector['secret'], vector['token'], vector['position']
                self.assertEqual(Wallet.generate_key(secret, token, position), vector['expectedKeyV1'])
                self.assertEqual(Wallet.generate_key(secret, token, position, 2), vector['expectedKeyV2'])
                self.assertEqual(Wallet.generate_address(vector['expectedKeyV1']), vector['expectedAddressV1'])
                self.assertEqual(Wallet.generate_address(vector['expectedKeyV2']), vector['expectedAddressV2'])
                wallet = Wallet(secret=secret, token=token, position=position, ots_version=2)
                self.assertEqual(wallet.address, vector['expectedAddressV2'])
                self.assertEqual(wallet.ots_version, 2)

    def test_unsupported_ots_version_is_refused(self):
        with self.assertRaisesRegex(ValueError, r'^KnishIO: unsupported OTS version 3; expected 1 or 2\.$'):
            Wallet(secret='x', ots_version=3)
        with self.assertRaisesRegex(ValueError, r'^KnishIO: unsupported OTS version 3; expected 1 or 2\.$'):
            Wallet.generate_key('ab', 'USER', 'cd', 3)

    def test_normalized_hash(self):
        for vector in VECTORS['signature']['tests']:
            with self.subTest(vector['name']):
                normalized = Molecule.normalize(Molecule.enumerate(vector['molecularHash']))
                self.assertEqual(list(normalized), vector['expectedNormalized'])

    def test_mlkem_identity(self):
        for vector in VECTORS['mlkem_identity']['tests']:
            with self.subTest(vector['name']):
                source = _key_vector(vector['keyFrom'])

                def pubkey(param_set):
                    return Wallet(secret=source['secret'], token=source['token'], position=source['position'],
                                  ots_version=2, mlkem_param_set=param_set).pubkey

                self.assertEqual(pubkey(1024), vector['expectedMlKem1024Pubkey'])
                self.assertEqual(pubkey(768), vector['expectedMlKem768Pubkey'])

    def test_molecule_verdicts(self):
        for vector in VECTORS['molecules']['tests']:
            with self.subTest(f"{vector['name']} -> {vector['expected']}"):
                molecule = Molecule.from_json(vector['molecule'], include_validation_context=True,
                                              validate_structure=True)
                if vector['expected'] == 'verified':
                    self.assertTrue(molecule.check(molecule.sourceWallet))
                else:
                    with self.assertRaises(EXCEPTIONS[vector['expected']]):
                        molecule.check(molecule.sourceWallet)

    def test_resign_reproduces_every_ots_fragment(self):
        source = _key_vector('hex_secret_user')
        for name in ('genuine_v2', 'genuine_v1_control'):
            with self.subTest(name):
                vector = next(t for t in VECTORS['molecules']['tests'] if t['name'] == name)
                parsed = Molecule.from_json(vector['molecule'])
                source_wallet = Wallet(secret=source['secret'], token='USER', position=source['position'],
                                       ots_version=vector['otsVersion'])
                molecule = Molecule(secret=source['secret'], source_wallet=source_wallet,
                                    remainder_wallet=source_wallet)
                molecule.atoms = parsed.atoms
                molecule.sign()
                self.assertEqual([atom.otsFragment for atom in molecule.atoms],
                                 [atom['otsFragment'] for atom in vector['molecule']['atoms']])

    def test_malformed_declared_hash(self):
        for vector in VECTORS['malformed_hash']['tests']:
            with self.subTest(f"{vector['name']} -> {vector['expected']}"):
                molecule = Molecule.from_json(vector['molecule'])
                with self.assertRaises(EXCEPTIONS[vector['expected']]):
                    check.ots(molecule)


class OtsV2RoundTripTest(unittest.TestCase):
    """A v2 source wallet signs a molecule that verifies; one changed character breaks it."""

    SECRET = crypto.generate_secret('TESTSEED')
    POSITION = '0123456789abcdeffedcba9876543210fedcba9876543210fedcba9876543210'

    def _signed(self):
        source_wallet = Wallet(secret=self.SECRET, token='USER', position=self.POSITION, ots_version=2)
        molecule = Molecule(secret=self.SECRET, source_wallet=source_wallet)
        molecule.init_meta(meta={'name': 'OTS v2 round trip'}, meta_type='TestMeta', meta_id='OTSV2RT')
        molecule.sign(compressed=True)
        return molecule, source_wallet

    def test_v2_round_trip(self):
        molecule, source_wallet = self._signed()
        self.assertEqual(molecule.signing_ots_version(), 2)
        self.assertEqual(molecule.remainderWallet.ots_version, 2)
        self.assertEqual(len(''.join(atom.otsFragment for atom in molecule.atoms)), 5464)
        self.assertTrue(molecule.check(source_wallet))

    def test_changed_fragment_is_a_mismatch(self):
        molecule, source_wallet = self._signed()
        fragment = molecule.atoms[0].otsFragment
        index = next(i for i, c in enumerate(fragment) if c in 'AB')
        flipped = 'B' if fragment[index] == 'A' else 'A'
        molecule.atoms[0].otsFragment = fragment[:index] + flipped + fragment[index + 1:]
        with self.assertRaises(SignatureMismatchException):
            molecule.check(source_wallet)

    def test_malformed_hash_is_refused_before_signing_work(self):
        molecule, _ = self._signed()
        molecule.molecularHash = molecule.molecularHash.upper()
        with self.assertRaises(SignatureMalformedException):
            check.ots(molecule)


class ClientOtsVersionTest(unittest.TestCase):
    """Client-level OTS version: the option, version detection for ledger wallets, snapshots."""

    SECRET = crypto.generate_secret('TESTSEED')
    POSITION = '0123456789abcdeffedcba9876543210fedcba9876543210fedcba9876543210'
    UNRELATED = 'c' * 64

    @classmethod
    def setUpClass(cls):
        cls.key_v1 = Wallet.generate_key(cls.SECRET, 'USER', cls.POSITION, 1)
        cls.key_v2 = Wallet.generate_key(cls.SECRET, 'USER', cls.POSITION, 2)
        cls.address_v1 = Wallet.generate_address(cls.key_v1)
        cls.address_v2 = Wallet.generate_address(cls.key_v2)

    def _ledger_wallet(self, address):
        return Wallet(secret=None, token='USER', position=self.POSITION, address=address)

    def _client_at(self, ots_version):
        client = KnishIOClient('http://127.0.0.1:9/graphql', ots_version=ots_version)
        client.set_secret(self.SECRET)
        return client

    @staticmethod
    def _continu_id_returns(client, wallet):
        return mock.patch.object(client, 'query_continu_id',
                                 return_value=mock.Mock(payload=lambda: wallet, errors=lambda: None))

    def test_detect_ots_version_either_preferred_order(self):
        for preferred in (1, 2):
            detect = lambda address: Wallet.detect_ots_version(  # noqa: E731
                self.SECRET, 'USER', self.POSITION, address, preferred)
            self.assertEqual(detect(self.address_v1), 1)
            self.assertEqual(detect(self.address_v2), 2)
            self.assertIsNone(detect(self.UNRELATED))

    def test_set_ots_version_on_keyless_and_keyed_wallets(self):
        self.assertEqual(self._ledger_wallet(self.address_v2).set_ots_version(2).ots_version, 2)
        keyed = Wallet(secret=self.SECRET, token='USER', position=self.POSITION)
        with self.assertRaisesRegex(ValueError, r'^KnishIO: cannot change the OTS version of a keyed wallet\.$'):
            keyed.set_ots_version(2)
        self.assertEqual(keyed.set_ots_version(1).ots_version, 1)

    def test_client_option_is_validated(self):
        client = self._client_at(2)
        self.assertEqual(client.get_ots_version(), 2)
        self.assertEqual(client.ots_version, 2)
        self.assertEqual(client.set_ots_version(1).get_ots_version(), 1)
        with self.assertRaisesRegex(ValueError, r'^KnishIO: unsupported OTS version 3; expected 1 or 2\.$'):
            KnishIOClient('http://127.0.0.1:9/graphql', ots_version=3)

    def test_new_keys_use_the_client_version(self):
        client = self._client_at(2)

        # getSourceWallet without a ContinuID
        with self._continu_id_returns(client, None):
            source_wallet = client.get_source_wallet()
        self.assertEqual(source_wallet.ots_version, 2)
        self.assertEqual(len(source_wallet.key), 8192)

        # createWallet
        mutation = mock.Mock()
        with mock.patch.object(client, 'create_molecule_mutation', return_value=mutation):
            client.create_wallet('TESTTOKEN')
        new_wallet = mutation.fill_molecule.call_args.args[0]
        self.assertEqual(new_wallet.ots_version, 2)
        self.assertEqual(len(new_wallet.key), 8192)

        # AUTH wallet of a first login (no ContinuID pointer)
        response = mock.Mock(success=lambda: True, auth_token=lambda: 't', pub_key=lambda: None)
        with self._continu_id_returns(client, None), \
                mock.patch.object(client, '_KnishIOClient__propose_profile_authorization',
                                  return_value=response) as propose:
            client.request_profile_auth_token(self.SECRET)
        auth_wallet = propose.call_args.args[0]
        self.assertEqual(auth_wallet.token, 'AUTH')
        self.assertEqual(auth_wallet.ots_version, 2)
        self.assertIs(client.get_authorization_wallet(), auth_wallet)

    def test_login_pointer_is_built_at_its_detected_version(self):
        client = self._client_at(1)
        response = mock.Mock(success=lambda: True, auth_token=lambda: 't', pub_key=lambda: None)
        with self._continu_id_returns(client, self._ledger_wallet(self.address_v2)), \
                mock.patch.object(client, '_KnishIOClient__propose_profile_authorization',
                                  return_value=response) as propose:
            client.request_profile_auth_token(self.SECRET)
        pointer_wallet = propose.call_args.args[0]
        self.assertEqual(pointer_wallet.token, 'USER')
        self.assertEqual(pointer_wallet.ots_version, 2)
        self.assertEqual(pointer_wallet.address, self.address_v2)

    def test_bind_detects_the_version_of_a_ledger_wallet(self):
        client = self._client_at(1)
        with self._continu_id_returns(client, self._ledger_wallet(self.address_v2)):
            source_wallet = client.get_source_wallet()
        self.assertEqual(source_wallet.ots_version, 2)

    def test_bind_refuses_a_wallet_this_secret_does_not_derive(self):
        client = self._client_at(1)
        message = (f'KnishIO: wallet {self.UNRELATED} is not derived from this secret at position '
                   f'{self.POSITION} under OTS version 1 or 2.')
        with self._continu_id_returns(client, self._ledger_wallet(self.UNRELATED)):
            with self.assertRaises(WalletCredentialException) as raised:
                client.get_source_wallet()
        self.assertEqual(str(raised.exception), message)

    def test_auth_token_snapshot_keeps_the_wallet_ots_version(self):
        wallet = Wallet(secret=self.SECRET, token='USER', position=self.POSITION, ots_version=2)
        snapshot = AuthToken.create({'token': 't', 'expiresAt': 0, 'pubkey': None, 'encrypt': False},
                                    wallet).get_snapshot()
        self.assertEqual(snapshot['wallet']['otsVersion'], 2)
        restored = AuthToken.restore(snapshot, self.SECRET).get_wallet()
        self.assertEqual(restored.ots_version, 2)
        self.assertEqual(restored.address, wallet.address)

    def test_snapshot_without_ots_version_restores_at_v1(self):
        wallet = Wallet(secret=self.SECRET, token='USER', position=self.POSITION, ots_version=2)
        snapshot = AuthToken.create({'token': 't', 'expiresAt': 0, 'pubkey': None, 'encrypt': False},
                                    wallet).get_snapshot()
        del snapshot['wallet']['otsVersion']
        self.assertEqual(AuthToken.restore(snapshot, self.SECRET).get_wallet().ots_version, 1)


if __name__ == '__main__':
    unittest.main()
