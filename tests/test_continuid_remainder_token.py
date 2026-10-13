# -*- coding: utf-8 -*-
"""
The ContinuID I-atom registers a USER wallet, as in the other SDKs: a missing or non-USER
remainder is replaced with a USER wallet derived from the molecule secret, and the client's
default remainder is a USER wallet.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from knishioclient.client import KnishIOClient
from knishioclient.exception import WalletCredentialException
from knishioclient.libraries import crypto
from knishioclient.models.Molecule import Molecule
from knishioclient.models.Wallet import Wallet
from knishioclient.mutation import MutationProposeMolecule

SECRET = 'f' * 2048
POSITION = 'c0ffee' + '0' * 58


def address_at(token, position, ots_version=1):
    return Wallet.generate_address(Wallet.generate_key(SECRET, token, position, ots_version))


def continu_id_atom(molecule):
    return next(atom for atom in molecule.atoms if atom.isotope == 'I')


class ContinuIdRemainderTokenTest(unittest.TestCase):

    def test_a_non_user_remainder_is_replaced_with_a_user_wallet(self):
        source = Wallet(secret=SECRET, token='USER', position=POSITION)
        remainder = Wallet.create(secret=SECRET, token='TKN', batch_id='batch')
        molecule = Molecule(secret=SECRET, source_wallet=source, remainder_wallet=remainder)
        molecule.init_meta({'k': 'v'}, 'ots', 'remainder')

        head = continu_id_atom(molecule)
        self.assertEqual(head.token, 'USER')
        self.assertNotEqual(head.position, remainder.position)
        self.assertEqual(head.walletAddress, address_at('USER', head.position))
        self.assertIsNone(head.batchId)
        self.assertEqual(molecule.remainderWallet.token, 'USER')

    def test_the_replacement_takes_the_successor_ots_version(self):
        source = Wallet(secret=SECRET, token='USER', position=POSITION)
        remainder = Wallet.create(secret=SECRET, token='TKN')
        molecule = Molecule(secret=SECRET, source_wallet=source, remainder_wallet=remainder, min_ots_version=2)
        molecule.init_meta({'k': 'v'}, 'ots', 'remainder')

        head = continu_id_atom(molecule)
        self.assertEqual(head.walletAddress, address_at('USER', head.position, 2))

    def test_a_missing_remainder_is_replaced_with_a_user_wallet(self):
        source = Wallet(secret=SECRET, token='USER', position=POSITION)
        molecule = Molecule(secret=SECRET, source_wallet=source)
        molecule.remainderWallet = None
        molecule.init_meta({'k': 'v'}, 'ots', 'remainder')

        head = continu_id_atom(molecule)
        self.assertEqual(head.token, 'USER')
        self.assertEqual(head.walletAddress, address_at('USER', head.position))
        self.assertEqual(molecule.remainderWallet.address, head.walletAddress)

    def test_the_replacement_keeps_the_molecule_mlkem_parameter_set(self):
        source = Wallet(secret=SECRET, token='USER', position=POSITION, mlkem_param_set=768)
        remainder = Wallet.create(secret=SECRET, token='TKN', mlkem_param_set=768)
        molecule = Molecule(secret=SECRET, source_wallet=source, remainder_wallet=remainder, mlkem_param_set=768)
        molecule.init_meta({'k': 'v'}, 'ots', 'remainder')

        self.assertEqual(molecule.remainderWallet.mlkem_param_set, 768)
        meta = {item['key']: item['value'] for item in continu_id_atom(molecule).meta}
        self.assertEqual(len(Wallet.deserialize_key(meta['pubkey'])), 1184)

    def test_a_non_user_remainder_without_the_secret_fails_closed(self):
        bundle = crypto.generate_bundle_hash(SECRET)
        source = Wallet(secret=None, bundle=bundle, token='USER', position=POSITION, address=address_at('USER', POSITION))
        remainder = Wallet.create(bundle=bundle, token='TKN')
        molecule = Molecule(bundle=bundle, source_wallet=source, remainder_wallet=remainder)

        with self.assertRaisesRegex(WalletCredentialException, r'^KnishIO: a ContinuID remainder needs the molecule secret\.$'):
            molecule.add_continue_id_atom()

    def test_the_client_default_remainder_is_a_user_wallet(self):
        client = KnishIOClient('http://127.0.0.1:9/graphql', ots_version=2)
        client.set_secret(SECRET)
        source = Wallet(secret=SECRET, token='TKN', position=POSITION, batch_id='batch', characters='BASE64')

        molecule = client.create_molecule(source_wallet=source)

        remainder = client.get_remainder_wallet()
        self.assertEqual(remainder.token, 'USER')
        self.assertEqual(remainder.batchId, 'batch')
        self.assertEqual(remainder.characters, 'BASE64')
        self.assertEqual(remainder.ots_version, 2)
        self.assertIs(molecule.remainderWallet, remainder)

    def test_a_first_login_registers_a_user_head(self):
        client = KnishIOClient('http://127.0.0.1:9/graphql')
        client.set_secret(SECRET)
        molecules = []
        accepted = mock.Mock(success=lambda: True, reason=lambda: None, payload=lambda: None,
                             auth_token=lambda: 't', pub_key=lambda: None)

        def execute(query, variables=None, fields=None):
            molecules.append(query.molecule())
            return accepted

        with mock.patch.object(client, 'query_continu_id',
                               return_value=mock.Mock(payload=lambda: None, errors=lambda: None)), \
                mock.patch.object(MutationProposeMolecule, 'execute', execute):
            client.request_profile_auth_token(SECRET)

        self.assertEqual(len(molecules), 1)
        self.assertEqual(molecules[0].atoms[0].token, 'AUTH')
        head = continu_id_atom(molecules[0])
        self.assertEqual(head.token, 'USER')
        self.assertEqual(head.walletAddress, address_at('USER', head.position))


if __name__ == '__main__':
    unittest.main()
