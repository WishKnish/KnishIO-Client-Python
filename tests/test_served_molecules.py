# -*- coding: utf-8 -*-
"""
Served-molecule verification and the Version4 atom hash.

Reads the vendored fixtures tests/fixtures/served-molecules.json (molecules exactly as a
validator's GraphQL API serves them) and tests/fixtures/version4-hash-vectors.json (atoms whose
every atom carries a version, with the exact view string hashed and the expected hash).
"""

import copy
import json
import sys
import unittest
from pathlib import Path

SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from knishioclient.exception import MolecularHashMismatchException
from knishioclient.libraries import check
from knishioclient.models.Atom import Atom

FIXTURES = SDK_ROOT / 'tests' / 'fixtures'
SERVED = json.loads((FIXTURES / 'served-molecules.json').read_text(encoding='utf-8'))
VECTORS = json.loads((FIXTURES / 'version4-hash-vectors.json').read_text(encoding='utf-8'))

HASH_MISMATCH = str(MolecularHashMismatchException())


def _served(name: str, version: object = ..., meta_id: str | None = None) -> dict:
    """A deep copy of a served molecule; optionally every atom's version and atom 0's metaId."""
    data = copy.deepcopy(SERVED[name])
    if version is not ...:
        for atom in data['atoms']:
            atom['version'] = version
    if meta_id is not None:
        data['atoms'][0]['metaId'] = meta_id
    return data


class ServedMoleculeTest(unittest.TestCase):

    def assertVerified(self, data: dict) -> None:
        result = check.verify_from_server_data(data)
        self.assertEqual(result, {'molecularHash': data['molecularHash'], 'verified': True, 'error': None})

    def assertHashMismatch(self, data: dict) -> None:
        result = check.verify_from_server_data(data)
        self.assertFalse(result['verified'])
        self.assertEqual(result['error'], HASH_MISMATCH)
        self.assertEqual(result['molecularHash'], data['molecularHash'])

    def test_v1_and_v2_verify(self):
        for name in ('v1', 'v2'):
            with self.subTest(name):
                self.assertVerified(_served(name))

    def test_v2ts_verifies_through_version4_retry(self):
        self.assertVerified(_served('v2ts'))

    def test_v2ts_with_version4_verifies_directly(self):
        data = _served('v2ts', version='4')
        self.assertVerified(data)
        self.assertTrue(check.molecular_hash(check.from_server_data(data)))

    def test_v3rust_served_with_version3_verifies(self):
        self.assertVerified(_served('v3rust'))

    def test_v3rust_without_versions_verifies_through_version3_retry(self):
        self.assertVerified(_served('v3rust', version=None))

    def test_tampered_v3rust_is_a_hash_mismatch(self):
        self.assertHashMismatch(_served('v3rust', meta_id='rust-pre-tampered'))
        self.assertHashMismatch(_served('v3rust', version=None, meta_id='rust-pre-tampered'))

    def test_served_version_disables_the_retry(self):
        self.assertHashMismatch(_served('v1', version='4'))

    def test_created_at_normalization(self):
        cases = (
            ('2026-10-14T20:02:37+00:00', '1792008157000'),
            ('2026-10-14T20:02:37.110Z', '1792008157110'),
            (1792008157110, '1792008157110'),
            ('1792008157110', '1792008157110'),
            ('not-a-date', 'not-a-date'),
            ('2026-10-14T22:02:37.1109+02:00', '1792008157110'),
            (None, None),
            ('', None),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(check.to_signed_timestamp(value), expected)

    def test_served_mapping(self):
        molecule = check.from_server_data(_served('v2'))
        served = SERVED['v2']
        self.assertEqual(molecule.bundle, served['bundleHash'])
        self.assertEqual(molecule.createdAt, check.to_signed_timestamp(served['createdAt']))
        self.assertEqual([atom.index for atom in molecule.atoms], [0, 1])
        for atom in molecule.atoms:
            self.assertIsNone(atom.version)
            self.assertTrue(atom.createdAt.isdigit())
            self.assertIsInstance(atom.meta, list)
        self.assertNotIn('version', molecule.atoms[0].to_json())

    def test_metas_json_shapes(self):
        data = _served('v1')
        data['atoms'][0]['metasJson'] = json.dumps({'a': 1, 'b': True, 'c': None, 'd': 'x', 'e': 1.5})
        data['atoms'][1]['metasJson'] = '{not json'
        molecule = check.from_server_data(data)
        self.assertEqual(molecule.atoms[0].meta, [
            {'key': 'a', 'value': '1'},
            {'key': 'b', 'value': 'true'},
            {'key': 'c', 'value': None},
            {'key': 'd', 'value': 'x'},
            {'key': 'e', 'value': '1.5'},
        ])
        self.assertEqual(molecule.atoms[1].meta, [])

    def test_malformed_input_is_unverified(self):
        for data in (None, 'molecule', {}, {'molecularHash': 'x'}, {'molecularHash': 'x', 'atoms': 'y'}):
            with self.subTest(data=data):
                result = check.verify_from_server_data(data)
                self.assertFalse(result['verified'])
                self.assertTrue(result['error'])

    def test_version4_hash_vectors(self):
        self.assertEqual(VECTORS['alphabet'], '0123456789abcdefg')
        self.assertEqual([case['name'] for case in VECTORS['cases']], [
            'v4-basic', 'v3-basic', 'slash-unicode', 'control-quote', 'line-separators', 'nulls',
            'empty-strings', 'empty-version', 'index-order',
        ])
        for case in VECTORS['cases']:
            with self.subTest(case['name']):
                atoms = [Atom.from_json(atom) for atom in case['atoms']]
                self.assertEqual(Atom.version4_view_json(atoms), case['viewJson'])
                self.assertEqual(Atom.hash_atoms(atoms), case['expectedHash'])

    def test_legacy_hash_vectors(self):
        self.assertEqual([case['name'] for case in VECTORS['legacyCases']], ['legacy-empty-strings', 'legacy-nulls'])
        for case in VECTORS['legacyCases']:
            with self.subTest(case['name']):
                atoms = [Atom.from_json(atom) for atom in case['atoms']]
                self.assertTrue(all(atom.version is None for atom in atoms))
                self.assertEqual(Atom.hash_atoms(atoms), case['expectedHash'])

    def test_atom_version_round_trip(self):
        atom_json = dict(VECTORS['cases'][0]['atoms'][0])
        self.assertEqual(Atom.from_json(atom_json).to_json()['version'], '4')
        atom_json['version'] = 4
        self.assertEqual(Atom.from_json(atom_json).version, '4')
        del atom_json['version']
        atom = Atom.from_json(atom_json)
        self.assertIsNone(atom.version)
        self.assertNotIn('version', atom.to_json())
        self.assertNotIn('"version"', atom.json())


if __name__ == '__main__':
    unittest.main()
