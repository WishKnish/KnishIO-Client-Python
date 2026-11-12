# -*- coding: utf-8 -*-
"""
Signed bytes match the JS reference (@wishknish/knishio-client-js, src/Molecule.js and
src/KnishIOClient.js). Each case builds a molecule from pinned inputs, writes createdAt on every
atom, and compares Atom.hash_atoms with the digest the JS SDK computed from the same inputs
(KNISHIO_KCORE=off, 2026-11-12):

- secret = generateSecret('fleet-audit-2026-11'), recipient secret = generateSecret('fleet-audit-2026-11-recipient')
- wallet positions 'aa'*32 (source), 'bb'*32 (new / recipient), 'cc'*32 (remainder),
  'dd'*32 (any position the builder generates itself), token 'TEST', createdAt '1700000000000'.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from knishioclient.libraries import crypto
from knishioclient.models.Atom import Atom
from knishioclient.models.AtomMeta import AtomMeta
from knishioclient.models.Molecule import Molecule
from knishioclient.models.Wallet import Wallet
from knishioclient.models.WalletShadow import WalletShadow

SECRET = crypto.generate_secret('fleet-audit-2026-11')
OTHER = crypto.generate_secret('fleet-audit-2026-11-recipient')
BUNDLE = crypto.generate_bundle_hash(SECRET)
A, B, C, D = 'aa' * 32, 'bb' * 32, 'cc' * 32, 'dd' * 32
CREATED = '1700000000000'

# Digests printed by the JS SDK for the cases below
JS_DIGESTS = {
    'createWallet': '02cg6caeb0a7de033debfcg13dc3ga72ga601490dced263a606ba9c3g4209be9',
    'identifier': '029ac4aaccce45d209417adf7ccf6423c7ae1a809257cc9e61f6dfa1d323b7f1',
    'tokenRequestSelf': '00gdf0c2be9365e973ag6618234f60bb556db2g0903b4359326cad69e415525g',
    'tokenRequestWallet': '05457abcdf290b177cdga7eb50d23dgff807f0e6b1da4d183bb6799807a8b602',
    'authorization': '01ab5c7ef47f4169gbf7f9d7d61c4g78e691dbe4e029e6535270a978440fg8d9',
    'peering': '0292ee02791gfd8440ebb29354e8f4e10e178c47bbdd7g4ga7ee4923d55c659c',
    'appendRequest': '0094f615033dc47ffgf894gb483a464d20ba2e84cf3ggb667f7123gafegbf1e4',
    'depositBuffer': '05196e04bcfgg891ee53c24c53fbae43c9a2146cc4f8e4ggdea2d267f4g4g7c4',
    'valueCustomRemainder': '05a3bb2631462feed38618cg1e3e62c5a80g7390063e4902c9a0e61e5cdf53gc',
    'metaScalars': '0149bace4g1cc7d159g3cf52c8795969d044bb73dd4e248d327eae3558455aa7',
    'version4': '038a219980c04gcd7e7450e1b5b4a70df7217a964594egb6a700ef7gc3g12g7c',
}


def _wallet(secret, token, position, **extra):
    return Wallet(secret=secret, token=token, position=position, **extra)


def _digest(molecule, created_at=CREATED):
    for atom in molecule.atoms:
        atom.createdAt = created_at
    return Atom.hash_atoms(molecule.atoms)


def _molecule(source, **extra):
    return Molecule(secret=SECRET, bundle=BUNDLE, source_wallet=source,
                    remainder_wallet=_wallet(SECRET, 'USER', C), **extra)


def _funded(token, position, balance):
    wallet = _wallet(SECRET, token, position)
    wallet.balance = balance
    return wallet


def build_cases():
    """name -> molecular hash, built from the inputs the JS probe used"""
    with mock.patch.object(Wallet, 'generate_position', return_value=D):
        to = _wallet(OTHER, 'TEST', B)
        auth = _wallet(SECRET, 'AUTH', A)
        return {
            'createWallet': _digest(_molecule(_wallet(SECRET, 'USER', A)).init_wallet_creation(_wallet(SECRET, 'FOO', B))),
            'identifier': _digest(_molecule(_wallet(SECRET, 'USER', A)).init_identifier_creation('email', ' a@b.c ', '1234')),
            'tokenRequestSelf': _digest(_molecule(_wallet(SECRET, 'USER', A)).init_token_request(
                'TEST', 100, 'walletBundle', BUNDLE, {})),
            'tokenRequestWallet': _digest(_molecule(_wallet(SECRET, 'USER', A)).init_token_request(
                'TEST', 100, 'wallet', to.address, {'position': to.position, 'bundle': to.bundle})),
            'authorization': _digest(_molecule(auth).init_authorization({'encrypt': 'true', 'walletPubkey': auth.pubkey})),
            'peering': _digest(_molecule(_wallet(SECRET, 'USER', A)).init_peering('https://peer.example')),
            'appendRequest': _digest(_molecule(_wallet(SECRET, 'USER', A)).init_append_request(
                'TestMeta', 'X1', 'append', {'name': 'n'})),
            'depositBuffer': _digest(Molecule(
                secret=SECRET, bundle=BUNDLE, source_wallet=_funded('TEST', A, 100),
                remainder_wallet=_wallet(SECRET, 'TEST', C)).init_deposit_buffer(40, {'USD': 2})),
            'valueCustomRemainder': _digest(Molecule(
                secret=SECRET, bundle=BUNDLE, source_wallet=_funded('TEST', A, 100),
                remainder_wallet=_wallet(SECRET, 'TEST', C, bundle='ee' * 32)).init_value(_wallet(OTHER, 'TEST', B), 30)),
            'metaScalars': _digest(_molecule(_wallet(SECRET, 'USER', A)).init_meta(
                {'z': 'last', '10': 'ten', '2': 'two', 'flag': True, 'off': False, 'f': 10.0, 'g': 0.5, 'h': 1e-5,
                 'i': 1e21}, 'TestMeta', 'S1'), '1000'),
            'version4': _digest(_molecule(_wallet(SECRET, 'USER', A), version=4).init_meta(
                {'name': 'v4'}, 'TestMeta', 'V4')),
        }


class JsParityDigestTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.digests = build_cases()

    def test_secret_matches_the_js_probe(self):
        self.assertEqual('1e2c25ec65edc973', SECRET[:16])

    def test_every_case_hashes_like_js(self):
        self.assertEqual(set(JS_DIGESTS), set(self.digests))
        for name, expected in JS_DIGESTS.items():
            with self.subTest(name):
                self.assertEqual(expected, self.digests[name])


class WalletShapeTest(unittest.TestCase):

    def test_shadow_wallet_has_no_characters(self):
        shadow = WalletShadow(BUNDLE, 'FOO')
        self.assertEqual('FOO', shadow.token)
        self.assertIsNone(shadow.characters)
        meta = AtomMeta().set_meta_wallet(shadow).get()
        self.assertIn({'key': 'walletCharacters', 'value': None}, meta)

    def test_keyed_wallet_defaults_to_base64(self):
        self.assertEqual('BASE64', _wallet(SECRET, 'USER', A).characters)
        self.assertIsNone(Wallet(bundle=BUNDLE, token='FOO').characters)


class MoleculeVersionTest(unittest.TestCase):

    def test_version_4_reaches_every_atom_and_unknown_versions_are_ignored(self):
        molecule = _molecule(_wallet(SECRET, 'USER', A), version=4).init_meta({'a': 'b'}, 'T', '1')
        self.assertEqual(['4', '4'], [atom.version for atom in molecule.atoms])
        legacy = _molecule(_wallet(SECRET, 'USER', A), version=3).init_meta({'a': 'b'}, 'T', '1')
        self.assertEqual([None, None], [atom.version for atom in legacy.atoms])

    def test_parent_hashes_round_trip(self):
        molecule = _molecule(_wallet(SECRET, 'USER', A)).with_parent_hashes(['p1', 'p2'])
        molecule.init_meta({'a': 'b'}, 'T', '1')
        serialized = molecule.to_json()
        self.assertEqual(['p1', 'p2'], serialized['parentHashes'])
        self.assertEqual(['p1', 'p2'], Molecule.from_json(serialized).parentHashes)
        self.assertIn('"parentHashes": ["p1", "p2"]', molecule.json())
        self.assertNotIn('parentHashes', _molecule(_wallet(SECRET, 'USER', A)).init_meta({'a': 'b'}, 'T', '1').to_json())

    def test_sign_keeps_an_existing_bundle(self):
        molecule = _molecule(_wallet(SECRET, 'USER', A)).init_meta({'a': 'b'}, 'T', '1')
        molecule.bundle = 'f' * 64
        molecule.sign()
        self.assertEqual('f' * 64, molecule.bundle)


class ClientBuildsLikeJsTest(unittest.TestCase):
    """The client passes keyword arguments to Wallet and spells metaType 'walletBundle'."""

    def _client(self):
        from knishioclient.client import KnishIOClient
        client = KnishIOClient('https://example.invalid')
        client.set_secret(SECRET)
        return client

    def _captured_fill(self, client, call):
        captured = {}

        class _Query:
            def fill_molecule(self, *args, **kwargs):
                captured['args'] = args
                captured['kwargs'] = kwargs

            def execute(self, *args, **kwargs):
                return 'executed'

        with mock.patch.object(type(client), 'create_molecule_mutation', return_value=_Query()), \
                mock.patch.object(Wallet, 'generate_position', return_value=B):
            call()
        return captured['args']

    def test_create_wallet_builds_the_token_wallet(self):
        client = self._client()
        (new_wallet,) = self._captured_fill(client, lambda: client.create_wallet('FOO'))
        self.assertEqual(('FOO', BUNDLE, B), (new_wallet.token, new_wallet.bundle, new_wallet.position))
        expected = _wallet(SECRET, 'FOO', B, ots_version=client.get_ots_version())
        self.assertEqual(expected.address, new_wallet.address)

    def test_request_tokens_to_a_bundle_uses_wallet_bundle(self):
        client = self._client()
        args = self._captured_fill(client, lambda: client.request_tokens('TEST', 100, to=BUNDLE))
        self.assertEqual(('TEST', 100, 'walletBundle', BUNDLE), args[:4])

    def test_request_tokens_to_a_secret_builds_that_secrets_wallet(self):
        client = self._client()
        args = self._captured_fill(client, lambda: client.request_tokens('TEST', 100, to=OTHER))
        to = _wallet(OTHER, 'TEST', B, ots_version=client.get_ots_version())
        self.assertEqual(('TEST', 100, 'wallet', to.address), args[:4])
        self.assertEqual({'position': B, 'bundle': to.bundle}, args[4])

    def test_extracting_authorization_wallet_keeps_token_and_position(self):
        client = self._client()
        molecule = _molecule(_wallet(SECRET, 'AUTH', A)).init_authorization({'encrypt': 'false'})
        wallet = client.extracting_authorization_wallet(molecule)
        self.assertEqual(('AUTH', A, BUNDLE), (wallet.token, wallet.position, wallet.bundle))

    def test_profile_authorization_meta_is_encrypt_then_wallet_pubkey(self):
        client = self._client()
        auth = _wallet(SECRET, 'AUTH', A)
        captured = {}

        class _Query:
            def fill_molecule(self, meta):
                captured['meta'] = meta

            def execute(self):
                return 'executed'

        with mock.patch.object(type(client), 'create_molecule', return_value=_molecule(auth)), \
                mock.patch.object(type(client), 'create_molecule_mutation', return_value=_Query()):
            client._KnishIOClient__propose_profile_authorization(auth, True)
        self.assertEqual({'encrypt': 'true', 'walletPubkey': auth.pubkey}, captured['meta'])
        self.assertEqual(['encrypt', 'walletPubkey'], list(captured['meta']))

    def test_create_molecule_passes_version_and_continu_id_position(self):
        from knishioclient.client import KnishIOClient
        client = KnishIOClient('https://example.invalid', server_sdk_version=4)
        client.set_secret(SECRET)
        token_wallet = _funded('TEST', A, 10)
        head = _wallet(SECRET, 'USER', D)
        continu_id = mock.Mock()
        continu_id.payload.return_value = head
        with mock.patch.object(type(client), 'query_continu_id', return_value=continu_id):
            molecule = client.create_molecule(source_wallet=token_wallet)
        self.assertEqual('4', molecule.version)
        self.assertEqual(D, molecule.continuIdPosition)


if __name__ == '__main__':
    unittest.main()
