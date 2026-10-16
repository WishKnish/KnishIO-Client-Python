# -*- coding: utf-8 -*-
"""
Atom.set_property matches property names exactly: `meta` (or its alias `metas`) given as a list
is stored as is, and only `metasJson` is decoded from a JSON string.
"""

import sys
import unittest
from pathlib import Path

SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from knishioclient.models.Atom import Atom
from knishioclient.models.MoleculeStructure import MoleculeStructure

META = [{'key': 'check', 'value': 'set-property'}, {'key': 'empty', 'value': ''}]


def _atom_data(index: int, **extra) -> dict:
    return {
        'position': f'{index:064x}',
        'walletAddress': f'{index + 16:064x}',
        'isotope': 'M',
        'token': 'USER',
        'index': index,
        'createdAt': '1792008157000',
        **extra,
    }


class AtomSetPropertyTest(unittest.TestCase):

    def test_meta_list(self):
        for name in ('meta', 'metas'):
            with self.subTest(name):
                atom = Atom('', '', '')
                atom.set_property(name, META)
                self.assertEqual(atom.meta, META)
                self.assertFalse(hasattr(atom, 'metasJson'))

    def test_metas_json_string(self):
        atom = Atom('', '', '')
        atom.set_property('metasJson', '[{"key": "check", "value": "set-property"}]')
        self.assertEqual(atom.meta, META[:1])

    def test_other_substrings_are_plain_properties(self):
        atom = Atom('', '', '')
        atom.set_property('Json', 'x')
        self.assertEqual(atom.Json, 'x')
        self.assertEqual(atom.meta, [])

    def test_molecule_structure_to_object_with_meta_lists(self):
        molecule = MoleculeStructure.to_object({
            'molecularHash': None,
            'bundle': 'b' * 64,
            'atoms': [_atom_data(1, meta=META[:1]), _atom_data(0, meta=META)],
        })
        self.assertEqual([atom.index for atom in molecule.atoms], [0, 1])
        self.assertEqual(molecule.atoms[0].meta, META)
        self.assertEqual(molecule.atoms[1].meta, META[:1])
        self.assertEqual(
            Atom.hash_atoms(molecule.atoms),
            Atom.hash_atoms([Atom.from_json(_atom_data(0, meta=META)), Atom.from_json(_atom_data(1, meta=META[:1]))]),
        )


if __name__ == '__main__':
    unittest.main()
