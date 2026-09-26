# -*- coding: utf-8 -*-
"""
signingWallet forgery regression.
=================================
``fixtures/signing-wallet-forgery.json`` holds two molecules built and signed by the published
@wishknish/knishio-client-js 1.2.1, whose ``check()`` accepts both. ``genuine`` is an M-isotope
meta molecule signed normally by wallet B. ``forged`` is the same build, but its first atom claims
the victim's address while carrying B's one-time signature and a ``signingWallet`` meta naming B.
The OTS address check must compare the recovered address only with ``atoms[0].walletAddress``,
so ``forged`` fails with ``SignatureMismatchException``. The fixture is shared byte-for-byte by
all eight SDKs.
"""

import json
import sys
import unittest
from pathlib import Path

# Ensure the SDK root is importable
SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if SDK_ROOT not in sys.path:
    sys.path.insert(0, SDK_ROOT)

from knishioclient.exception import SignatureMismatchException
from knishioclient.models.Molecule import Molecule

FIXTURE_PATH = Path(__file__).resolve().parent / 'fixtures' / 'signing-wallet-forgery.json'


class SigningWalletForgeryTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE_PATH.read_text(encoding='utf-8'))

    def test_genuine_molecule_verifies(self):
        molecule = Molecule.from_json(self.fixture['genuine'])
        self.assertTrue(molecule.check())

    def test_forged_molecule_is_rejected_as_signature_mismatch(self):
        molecule = Molecule.from_json(self.fixture['forged'])
        with self.assertRaises(SignatureMismatchException):
            molecule.check()

    def test_forged_molecule_claims_the_victim_address(self):
        molecule = Molecule.from_json(self.fixture['forged'])
        self.assertEqual(self.fixture['victimAddress'], molecule.atoms[0].walletAddress)
        self.assertNotEqual(self.fixture['attackerAddress'], molecule.atoms[0].walletAddress)


if __name__ == '__main__':
    unittest.main()
