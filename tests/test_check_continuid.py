# -*- coding: utf-8 -*-
"""
ContinuID check (``check.continu_id``) runs inside ``Molecule.check``.
======================================================================
The JS reference (CheckMolecule.verify) rejects a molecule whose first atom carries the USER
token but which has no ContinuID I-atom. Python defined ``continu_id`` but left it commented
out of ``verify()``, so such a molecule verified. These tests pin the JS behaviour.
"""

import sys
import unittest
from pathlib import Path

# Ensure the SDK root is importable
SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if SDK_ROOT not in sys.path:
    sys.path.insert(0, SDK_ROOT)

from knishioclient.exception import AtomsMissingException
from knishioclient.libraries import check, crypto
from knishioclient.models.Molecule import Molecule
from knishioclient.models.Wallet import Wallet

SECRET = crypto.generate_secret('TESTSEED')
SOURCE_POSITION = '0123456789abcdeffedcba9876543210fedcba9876543210fedcba9876543210'
REMAINDER_POSITION = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'


def signed_meta_molecule(with_continu_id: bool):
    """A signed USER-token M molecule, with or without its ContinuID I-atom."""
    source_wallet = Wallet(secret=SECRET, token='USER', position=SOURCE_POSITION)
    remainder_wallet = Wallet(secret=SECRET, token='USER', position=REMAINDER_POSITION)
    molecule = Molecule(secret=SECRET, source_wallet=source_wallet, remainder_wallet=remainder_wallet)
    molecule.init_meta(meta={'name': 'ContinuID check'}, meta_type='TestMeta', meta_id='CONTINUID1')
    if not with_continu_id:
        molecule.atoms = [atom for atom in molecule.atoms if atom.isotope != 'I']
    molecule.sign()
    return molecule, source_wallet


class ContinuIdCheckTest(unittest.TestCase):

    def test_user_molecule_without_continu_id_atom_is_rejected(self):
        molecule, source_wallet = signed_meta_molecule(with_continu_id=False)
        self.assertEqual([atom.isotope for atom in molecule.atoms], ['M'])
        self.assertEqual(molecule.atoms[0].token, 'USER')
        # Hash and signature are genuine, so the rejection can only come from continu_id.
        self.assertTrue(check.molecular_hash(molecule))
        self.assertTrue(check.ots(molecule))

        with self.assertRaises(AtomsMissingException) as raised:
            molecule.check(source_wallet)
        self.assertIn('ContinuID', str(raised.exception))

    def test_user_molecule_with_continu_id_atom_passes(self):
        molecule, source_wallet = signed_meta_molecule(with_continu_id=True)
        self.assertEqual(sorted(atom.isotope for atom in molecule.atoms), ['I', 'M'])
        self.assertTrue(molecule.check(source_wallet))

    def test_meta_append_molecule_carries_continu_id_and_verifies(self):
        source_wallet = Wallet(secret=SECRET, token='USER', position=SOURCE_POSITION)
        remainder_wallet = Wallet(secret=SECRET, token='USER', position=REMAINDER_POSITION)
        molecule = Molecule(secret=SECRET, source_wallet=source_wallet, remainder_wallet=remainder_wallet)
        molecule.init_meta_append({'action': 'append', 'name': 'ContinuID append'}, 'TestMeta', 'CONTINUID2')
        molecule.sign()
        self.assertTrue(molecule.check(source_wallet))
        self.assertEqual(sorted(atom.isotope for atom in molecule.atoms), ['A', 'I'])


if __name__ == '__main__':
    unittest.main()
