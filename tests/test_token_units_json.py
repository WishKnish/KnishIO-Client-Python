# -*- coding: utf-8 -*-
"""
Stackable ``tokenUnits`` meta serialization.
============================================
The ``tokenUnits`` meta is a JSON string hashed into every stackable V atom, and ``create_token``
sends one for a stackable supply. Both must be the bytes JS ``JSON.stringify`` writes: compact
separators, non-ASCII as-is. The expected strings and digests were printed by a script run against
the published @wishknish/knishio-client-js 1.2.1 with the same inputs (``Wallet.splitUnits``, then
``Molecule.initValue``, each V atom's ``createdAt`` and ``index`` pinned).
"""

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
from knishioclient.models.Atom import Atom
from knishioclient.models.Molecule import Molecule
from knishioclient.models.TokenUnit import TokenUnit
from knishioclient.models.Wallet import Wallet

FIXED_CREATED_AT = '1700000000000'
UNIT_ONE = '[["unit1","Unit One",{"colour":"red","ünïcode":"ß"}]]'
UNIT_TWO = '[["unit2","Unit Two",{}]]'

# position digit -> (tokenUnits meta, Atom.hashAtoms digest), from the JS 1.2.1 script.
JS_VALUE_ATOMS = {
    '1': (UNIT_ONE, '032f48f0a4gab1ea390f781d02abc6232g28d414d0cc8bc63gce987ff2391c04'),
    '2': (UNIT_TWO, '0038c0dded8d4087aa0271b7g8gc9c450c8eb9cef70405a3116d679f5a49062c'),
    '3': (UNIT_ONE, '01551fa3800c5c9c5170e7a09c0c3g0febfe0116a309864536g3f6abe430g7d4'),
}


class TokenUnitsJsonTest(unittest.TestCase):

    def test_stackable_value_atoms_match_js_reference(self):
        secret = crypto.generate_secret('stack-parity-fixed-seed')
        recipient_secret = crypto.generate_secret('stack-parity-recipient-seed')
        batch_id = 'b' * 64

        source = Wallet(secret=secret, token='STACK', position='1' * 64, batch_id=batch_id)
        source.balance = 2
        source.tokenUnits = [
            TokenUnit('unit1', 'Unit One', {'colour': 'red', 'ünïcode': 'ß'}),
            TokenUnit('unit2', 'Unit Two', {}),
        ]
        remainder = Wallet(secret=secret, token='STACK', position='2' * 64, batch_id=batch_id)
        recipient = Wallet(secret=recipient_secret, token='STACK', position='3' * 64, batch_id=batch_id)

        source.split_units(['unit1'], remainder, recipient)
        molecule = Molecule(secret=secret, source_wallet=source, remainder_wallet=remainder)
        molecule.init_value(recipient, 1)

        for digit, (token_units, digest) in JS_VALUE_ATOMS.items():
            atom = next(atom for atom in molecule.atoms
                        if atom.isotope == 'V' and atom.position == digit * 64)
            atom.createdAt = FIXED_CREATED_AT
            atom.index = 0
            meta = {entry['key']: entry['value'] for entry in atom.meta}
            self.assertEqual(meta['tokenUnits'], token_units, f'V atom at position {digit}')
            self.assertEqual(Atom.hash_atoms([atom]), digest, f'V atom at position {digit}')

    def test_create_token_sends_compact_units_json(self):
        client = KnishIOClient('http://offline.invalid/graphql')
        mutation = mock.Mock()
        with mock.patch.object(KnishIOClient, 'create_molecule_mutation', return_value=mutation), \
                mock.patch.object(KnishIOClient, 'secret', return_value=crypto.generate_secret('TESTSEED')):
            client.create_token('STACK1', 0, {'fungibility': 'stackable', 'supply': 'limited', 'name': 'Stack'},
                                units=[['unit1', 'Unit One', {'colour': 'red'}], ['unit2', 'Unit Two', {}]])

        _wallet, amount, data_metas = mutation.fill_molecule.call_args.args
        # JSON.stringify of the same units.
        self.assertEqual(data_metas['tokenUnits'], '[["unit1","Unit One",{"colour":"red"}],["unit2","Unit Two",{}]]')
        self.assertEqual(amount, 2)


if __name__ == '__main__':
    unittest.main()
