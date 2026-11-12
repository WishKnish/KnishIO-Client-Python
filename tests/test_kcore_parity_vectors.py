# -*- coding: utf-8 -*-
"""
kcore parity vectors: full signed molecules that libkcore and the pure-Python path must reproduce byte
for byte.

The fixture tests/fixtures/kcore-parity-vectors.json is vendored from the monorepo's shared master
kcore-parity-vectors.json (scripts/gen-kcore-parity-vectors.mjs). It holds 16
cases: metadata, value transfer, token creation and wallet creation, each under OTS v1 and v2, with
distinct and with colliding createdAt values. For every case the molecule must verify (molecular hash
and OTS signature), and re-signing it from the case's secret and source wallet must reproduce the
molecular hash and every atom's otsFragment.

CI runs pytest with KNISHIO_KCORE=require and then =off, so each run pins one backend against the same
bytes; the backend test below asserts which one actually ran.
"""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from knishioclient.libraries import check, kcore
from knishioclient.models.Atom import Atom
from knishioclient.models.Molecule import Molecule
from knishioclient.models.Wallet import Wallet

VECTORS_PATH = Path(__file__).parent / 'fixtures' / 'kcore-parity-vectors.json'
CASES = json.loads(VECTORS_PATH.read_text(encoding='utf-8'))['vectors']['molecules']['tests']
CASE_COUNT = 16


class KcoreParityVectorTest(unittest.TestCase):

    def test_case_count(self):
        self.assertEqual(len(CASES), CASE_COUNT)
        self.assertEqual(len({case['name'] for case in CASES}), CASE_COUNT)

    def test_backend(self):
        mode = os.environ.get('KNISHIO_KCORE', 'auto').lower()
        if mode == 'require':
            self.assertTrue(kcore.available(), 'KNISHIO_KCORE=require but libkcore is not loaded')
        elif mode == 'off':
            self.assertFalse(kcore.available(), 'KNISHIO_KCORE=off but libkcore is loaded')

    def test_molecules_verify(self):
        ran = 0
        for case in CASES:
            with self.subTest(case['name']):
                molecule = Molecule.from_json(case['molecule'], include_validation_context=False)
                self.assertEqual(Atom.hash_atoms(molecule.atoms), case['expected']['molecularHash'],
                                 f"{case['name']}: recomputed molecular hash")
                self.assertTrue(check.molecular_hash(molecule))
                self.assertTrue(check.ots(molecule))
                ran += 1
        self.assertEqual(ran, CASE_COUNT)

    def test_resign_reproduces_hash_and_every_ots_fragment(self):
        # Under require every chain walk in sign() must come from libkcore (a returned fragment string);
        # under off kcore.chains_hex is still consulted but must return None so the pure loop signs.
        mode = os.environ.get('KNISHIO_KCORE', 'auto').lower()
        original_chains_hex = kcore.chains_hex
        ran = 0
        for case in CASES:
            with self.subTest(case['name']):
                parsed = Molecule.from_json(case['molecule'], include_validation_context=False)
                # Clear every fragment so each compared byte comes from this signing.
                for atom in parsed.atoms:
                    atom.otsFragment = None
                source_wallet = Wallet(secret=case['secret'], token=case['sourceToken'],
                                       position=case['sourcePosition'], ots_version=case['otsVersion'])
                molecule = Molecule(secret=case['secret'], source_wallet=source_wallet,
                                    remainder_wallet=source_wallet)
                molecule.atoms = parsed.atoms
                returned = []

                def recording_chains_hex(chunks, counts):
                    result = original_chains_hex(chunks, counts)
                    returned.append(result)
                    return result

                with mock.patch.object(kcore, 'chains_hex', side_effect=recording_chains_hex):
                    molecule.sign()
                if mode == 'require':
                    self.assertGreaterEqual(len(returned), 1, f"{case['name']}: kcore.chains_hex not called")
                    self.assertNotIn(None, returned, f"{case['name']}: kcore.chains_hex returned None")
                elif mode == 'off':
                    self.assertEqual([r for r in returned if r is not None], [],
                                     f"{case['name']}: libkcore signed under KNISHIO_KCORE=off")
                self.assertEqual(molecule.bundle, case['molecule']['bundle'], f"{case['name']}: bundle")
                self.assertEqual(molecule.molecularHash, case['expected']['molecularHash'],
                                 f"{case['name']}: molecularHash")
                fragments = [atom.otsFragment for atom in molecule.atoms]
                self.assertEqual(len(fragments), len(case['expected']['otsFragments']),
                                 f"{case['name']}: atom count")
                for i, (actual, expected) in enumerate(zip(fragments, case['expected']['otsFragments'])):
                    self.assertEqual(actual, expected, f"{case['name']}: atoms[{i}].otsFragment")
                ran += 1
        self.assertEqual(ran, CASE_COUNT)


if __name__ == '__main__':
    unittest.main()
