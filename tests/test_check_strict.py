# -*- coding: utf-8 -*-
"""
Molecule verification follows the JS reference (CheckMolecule.js): token and metaType checks are
equality tests, not substring tests; B/F/V values must be numeric; V atoms carry one token and a
consistent batch id; U atoms are AUTH or USER; M-atom policies name existing keys and valid
bundle hashes.
"""

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from knishioclient.exception import (
    BatchIdException,
    MetaMissingException,
    PolicyInvalidException,
    TransferMalformedException,
    TransferMismatchedException,
    TransferUnbalancedException,
    WrongTokenTypeException,
)
from knishioclient.libraries import check
from knishioclient.models.Atom import Atom

BUNDLE = 'a' * 64


def _atom(isotope, index, token='USER', value=None, batch_id=None, meta_type=None, meta_id=None,
          meta=None, address=None):
    return Atom(f'p{index}', address or f'w{index}', isotope, token, value, batch_id, meta_type, meta_id,
                meta or [], None, index)


def _molecule(*atoms):
    return SimpleNamespace(molecularHash='0' * 64, atoms=list(atoms))


def _transfer(values, tokens=('TOKEN', 'TOKEN', 'TOKEN'), batch_ids=(None, None, None)):
    return _molecule(*[
        _atom('V', index, token=token, value=value, batch_id=batch_id,
              meta_type=None if index == 0 else 'walletBundle', meta_id=None if index == 0 else BUNDLE)
        for index, (value, token, batch_id) in enumerate(zip(values, tokens, batch_ids))
    ])


class TokenEqualityTest(unittest.TestCase):

    def test_t_i_m_reject_substrings_of_user(self):
        for token in ('', 'U', 'SER'):
            with self.subTest(isotope='T', token=token):
                molecule = _molecule(_atom('T', 0, token=token, meta_type='walletBundle', meta_id=BUNDLE,
                                           meta=[{'key': 'token', 'value': 'FOO'}]))
                with self.assertRaises(WrongTokenTypeException):
                    check.isotope_t(molecule)
            with self.subTest(isotope='I', token=token):
                with self.assertRaises(WrongTokenTypeException):
                    check.isotope_i(_molecule(_atom('C', 0), _atom('I', 1, token=token)))
            with self.subTest(isotope='M', token=token):
                with self.assertRaises(WrongTokenTypeException):
                    check.isotope_m(_molecule(_atom('M', 0, token=token, meta=[{'key': 'a', 'value': 'b'}])))

    def test_u_accepts_only_auth_and_user(self):
        for token in ('AUTH', 'USER'):
            self.assertTrue(check.isotope_u(_molecule(_atom('U', 0, token=token))))
        for token in ('FOO', '', 'AUT'):
            with self.subTest(token=token), self.assertRaises(WrongTokenTypeException):
                check.isotope_u(_molecule(_atom('U', 0, token=token)))

    def test_t_meta_rules_follow_js(self):
        # metaType null: position/bundle are not required (JS compares metaType === 'wallet')
        no_type = _molecule(_atom('T', 0, meta=[{'key': 'token', 'value': 'FOO'}]))
        self.assertTrue(check.isotope_t(no_type))
        # metaType 'wallet' still requires them
        wallet_type = _molecule(_atom('T', 0, meta_type='wallet', meta_id='x',
                                      meta=[{'key': 'token', 'value': 'FOO'}]))
        with self.assertRaises(MetaMissingException):
            check.isotope_t(wallet_type)
        # an empty token meta is missing
        empty_token = _molecule(_atom('T', 0, meta=[{'key': 'token', 'value': ''}]))
        with self.assertRaises(MetaMissingException):
            check.isotope_t(empty_token)


class ValueTest(unittest.TestCase):

    def test_v_non_numeric_value_is_malformed(self):
        with self.assertRaises(TransferMalformedException):
            check.isotope_v(_transfer(['-100', 'abc', '100']))

    def test_v_non_finite_value_is_malformed(self):
        for bad in ('nan', 'inf', '-Infinity', '1_0'):
            with self.subTest(value=bad), self.assertRaises(TransferMalformedException):
                check.isotope_v(_transfer(['-100', bad, '100']))

    def test_b_and_f_non_numeric_value_is_malformed(self):
        for isotope, checker in (('B', check.isotope_b), ('F', check.isotope_f)):
            with self.subTest(isotope=isotope), self.assertRaises(TransferMalformedException):
                checker(_molecule(_atom('V', 0, token='TOKEN', value='-1'),
                                  _atom(isotope, 1, token='TOKEN', value='abc', meta_type='walletBundle',
                                        meta_id=BUNDLE)))

    def test_v_mixed_tokens_are_rejected(self):
        for tokens in (('TESTTOKEN', 'TOKEN', 'TESTTOKEN'), ('TOKEN', '', 'TOKEN'), ('TOKEN', 'TOKEN', 'TOK')):
            with self.subTest(tokens=tokens), self.assertRaises(TransferMismatchedException):
                check.isotope_v(_transfer(['-100', '40', '60'], tokens=tokens))

    def test_v_address_substring_is_not_a_self_transfer(self):
        molecule = _transfer(['-100', '40', '60'])
        molecule.atoms[0].walletAddress = 'xabcx'
        molecule.atoms[1].walletAddress = 'abc'
        molecule.atoms[2].walletAddress = 'def'
        self.assertTrue(check.isotope_v(molecule, SimpleNamespace(balance=100)))

    def test_balanced_transfer_still_passes(self):
        self.assertTrue(check.isotope_v(_transfer(['-100', '40', '60']), SimpleNamespace(balance=100)))
        with self.assertRaises(TransferUnbalancedException):
            check.isotope_v(_transfer(['-100', '40', '61']), SimpleNamespace(balance=100))


class BatchIdTest(unittest.TestCase):

    def test_matching_batch_ids_pass(self):
        self.assertTrue(check.batch_id(_transfer(['-100', '40', '60'], batch_ids=('b1', 'b2', 'b1'))))
        self.assertTrue(check.batch_id(_transfer(['-100', '40', '60'])))

    def test_remainder_batch_id_must_match_the_signer(self):
        with self.assertRaises(BatchIdException):
            check.batch_id(_transfer(['-100', '40', '60'], batch_ids=('b1', 'b2', 'b3')))

    def test_every_v_atom_needs_a_batch_id_when_the_signer_has_one(self):
        with self.assertRaises(BatchIdException):
            check.batch_id(_transfer(['-100', '40', '60'], batch_ids=('b1', None, 'b1')))

    def test_verify_runs_the_batch_id_check(self):
        molecule = _transfer(['-100', '40', '60'], batch_ids=('b1', 'b2', 'b3'))
        with mock.patch.object(check, 'molecular_hash', return_value=True), \
                mock.patch.object(check, 'ots', return_value=True), \
                self.assertRaises(BatchIdException):
            check.verify(molecule)


class PolicyTest(unittest.TestCase):

    def _m(self, meta):
        return _molecule(_atom('M', 0, meta=[{'key': key, 'value': value} for key, value in meta.items()]))

    def test_valid_policy_passes(self):
        self.assertTrue(check.isotope_m(self._m({
            'name': 'x',
            'readPolicy': json.dumps({'name': ['all', 'self', BUNDLE]}),
        })))

    def test_policy_key_missing_from_meta(self):
        with self.assertRaises(PolicyInvalidException):
            check.isotope_m(self._m({'name': 'x', 'writePolicy': json.dumps({'other': ['all']})}))

    def test_policy_value_not_a_bundle(self):
        with self.assertRaises(PolicyInvalidException):
            check.isotope_m(self._m({'name': 'x', 'readPolicy': json.dumps({'name': ['nobody']})}))


if __name__ == '__main__':
    unittest.main()
