# -*- coding: utf-8 -*-
"""
Rule creation (``Molecule.init_rule_creation``) and ``AtomMeta.add_policy``.
===========================================================================
Both must produce the bytes the JS reference produces (``Molecule.createRule`` with
``Rule.toObject`` and ``AtomMeta.addPolicy``), because the rule and policy strings are hashed
into the atom. Inputs are the TS SDK's pinned vectors (tests/unit/rule-molecule-hash.test.ts and
tests/unit/atom-meta-policy.test.ts). The expected strings and the policy digest are the ones TS
pins; the rule digest was computed with @wishknish/knishio-client-js 1.2.1 (see below).
"""

import sys
import unittest
from pathlib import Path

# Ensure the SDK root is importable
SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if SDK_ROOT not in sys.path:
    sys.path.insert(0, SDK_ROOT)

from knishioclient.exception import MetaMissingException, RuleArgumentException
from knishioclient.libraries import crypto
from knishioclient.models.Atom import Atom
from knishioclient.models.AtomMeta import AtomMeta
from knishioclient.models.Molecule import Molecule
from knishioclient.models.Wallet import Wallet

FIXED_CREATED_AT = '1700000000000'

RULE_INPUT = {
    'condition': [
        {'key': 'zeta', 'value': '100', 'comparison': '>='},
        {'key': 'alpha', 'value': 'USER', 'comparison': '='},
    ],
    'callback': [
        {'action': 'meta', 'metaType': 'walletBundle', 'metaId': 'c' * 64,
         'meta': {'zulu': 'last', 'alpha': 'first', 'mike': '42'}},
    ],
}

# rule-molecule-hash.test.ts:90
EXPECTED_RULE = (
    '[{"condition":[{"key":"zeta","value":"100","comparison":">="},'
    '{"key":"alpha","value":"USER","comparison":"="}],'
    '"callback":[{"action":"meta","metaType":"walletBundle","metaId":"' + 'c' * 64 + '",'
    '"meta":{"zulu":"last","alpha":"first","mike":"42"}}]}]'
)

MINIMAL_RULE = {
    'condition': [{'key': 'role', 'value': 'admin', 'comparison': '=='}],
    'callback': [{'action': 'allow'}],
}


def meta_of(atom: Atom) -> dict:
    return {entry['key']: entry['value'] for entry in atom.meta}


def pinned(atom: Atom) -> Atom:
    atom.createdAt = FIXED_CREATED_AT
    atom.index = 0
    return atom


class RuleCreationTest(unittest.TestCase):

    def test_rule_atom_matches_js_reference(self):
        secret = crypto.generate_secret('rule-molecule-hash-fixed-seed')
        source = Wallet(secret=secret, token='TEST', position='1' * 64)
        remainder = Wallet(secret=secret, token='TEST', position='2' * 64)
        molecule = Molecule(secret=secret, source_wallet=source, remainder_wallet=remainder, cell_slug='test')

        molecule.init_rule_creation('walletBundle', 'd' * 64, [RULE_INPUT])

        atom = next(atom for atom in molecule.atoms if atom.isotope == 'R')
        meta = meta_of(atom)
        self.assertEqual(meta['rule'], EXPECTED_RULE)
        self.assertEqual(meta['policy'], '{"read":{"0":["all"]},"write":{"0":["self"]}}')
        # The JS reference (@wishknish/knishio-client-js 1.2.1, same inputs) hashes this atom to the
        # value below. TS pins '038ge57d…' instead: its createRule skips addPolicy for an empty
        # policy (src/core/Molecule.ts:961-964), while JS always adds it (Molecule.js:842).
        self.assertEqual(Atom.hash_atoms([pinned(atom)]),
                         '0044d2d333e085af0bdee84gd6a7e52g516f603f685bdefbfb8044f9af096507')

    def test_policy_atom_matches_js_reference(self):
        secret = crypto.generate_secret('parity-probe-fixed-seed')
        wallet = Wallet(secret=secret, token='TEST', position='1' * 64)
        atom_meta = AtomMeta({'foo': 'bar', 'characters': 'BASE64', 'pubkey': 'abc'})
        atom_meta.add_policy({'read': {'foo': ['all']}})

        atom = Atom.create(isotope='R', wallet=wallet, meta_type='walletBundle', meta_id='d' * 64, meta=atom_meta)

        # JS orders integer-like keys first, so the defaults precede the caller's `foo`.
        self.assertEqual(
            meta_of(atom)['policy'],
            '{"read":{"0":["all"],"1":["all"],"2":["all"],"foo":["all"]},'
            '"write":{"0":["self"],"1":["self"],"2":["self"]}}'
        )
        # atom-meta-policy.test.ts:78-79
        self.assertEqual(Atom.hash_atoms([pinned(atom)]),
                         '03671c54cf0df5d44a0ab752ggb717dddfbga0e744f0289adea6bdca33242b66')

    def test_malformed_rule_is_refused_before_signing(self):
        secret = crypto.generate_secret('TESTSEED')
        molecule = Molecule(secret=secret,
                            source_wallet=Wallet(secret=secret, token='USER', position='1' * 64),
                            remainder_wallet=Wallet(secret=secret, token='USER', position='2' * 64))

        with self.assertRaises(MetaMissingException):
            molecule.init_rule_creation('TestRule', 'R1', [{'callback': [{'action': 'allow'}]}])
        with self.assertRaises(RuleArgumentException):
            molecule.init_rule_creation('TestRule', 'R1', [{
                'condition': MINIMAL_RULE['condition'],
                'callback': [{'metaType': 'm'}],
            }])
        self.assertEqual(molecule.atoms, [])

    def test_rule_molecule_signs_and_checks(self):
        secret = crypto.generate_secret('TESTSEED')
        source_wallet = Wallet(secret=secret, token='USER',
                               position='0123456789abcdeffedcba9876543210fedcba9876543210fedcba9876543210')
        remainder_wallet = Wallet(secret=secret, token='USER',
                                  position='fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210')
        molecule = Molecule(secret=secret, source_wallet=source_wallet, remainder_wallet=remainder_wallet)

        # MutationCreateRule.fill_molecule's sequence.
        molecule.init_rule_creation('TestRule', 'RULE1', [MINIMAL_RULE])
        molecule.sign()

        self.assertTrue(molecule.check(source_wallet))
        self.assertEqual(sorted(atom.isotope for atom in molecule.atoms), ['I', 'R'])


if __name__ == '__main__':
    unittest.main()
