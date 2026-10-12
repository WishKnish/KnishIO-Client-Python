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

from knishioclient.exception import SignatureMalformedException, SignatureMismatchException
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


if __name__ == '__main__':
    unittest.main()
