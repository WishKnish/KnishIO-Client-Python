# -*- coding: utf-8 -*-
"""
Client operations that crashed or returned nothing: each is called once against a stubbed
transport (no network) and must return instead of raising.
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock

SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from knishioclient.client import KnishIOClient
from knishioclient.libraries import crypto
from knishioclient.models.Molecule import Molecule
from knishioclient.models.MoleculeStructure import MoleculeStructure
from knishioclient.models.Wallet import Wallet
from knishioclient.mutation import MutationCreateIdentifier, MutationLinkIdentifier
from knishioclient.response.Response import Response
from knishioclient.response.ResponseAtom import ResponseAtom
from knishioclient.response.ResponseAuthorizationGuest import ResponseAuthorizationGuest
from knishioclient.response.ResponseMetaBatch import ResponseMetaBatch
from knishioclient.response.ResponsePolicy import ResponsePolicy
from knishioclient.response.ResponseRequestAuthorization import ResponseRequestAuthorization

SECRET = crypto.generate_secret('fleet-audit-2026-11')
URL = 'https://example.invalid/graphql'


def _query(text='query { Field @fields }'):
    return mock.Mock(query=text)


class _Transport:
    """Answers every request with the reply for the first operation name found in its query."""

    def __init__(self, replies):
        self.replies = replies
        self.sent = []

    def __call__(self, request, options=None):
        self.sent.append(request)
        for name, reply in self.replies.items():
            if name in request['query']:
                return reply
        raise AssertionError(f'unexpected request {request["query"]}')


class ClientOperationsTest(unittest.TestCase):

    def _client(self, replies):
        client = KnishIOClient(URL)
        client.set_secret(SECRET)
        transport = _Transport(replies)
        patcher = mock.patch.object(client.client(), 'send', side_effect=transport)
        patcher.start()
        self.addCleanup(patcher.stop)
        return client, transport

    def test_url_returns_the_endpoint(self):
        self.assertEqual(URL, KnishIOClient(URL).url())

    def test_create_identifier_proposes_an_identifier_molecule(self):
        accepted = {'data': {'ProposeMolecule': {'status': 'accepted', 'molecularHash': 'x', 'reason': None}}}
        client, transport = self._client({'ContinuId': {'data': {'ContinuId': None}}, 'ProposeMolecule': accepted})
        response = client.create_identifier('email', 'a@b.c', '1234')
        self.assertTrue(response.success())
        self.assertIsInstance(response.query, MutationCreateIdentifier)
        molecule = transport.sent[-1]['variables']['molecule']
        self.assertEqual(['C', 'I'], [atom.isotope for atom in molecule.atoms])
        self.assertEqual('identifier', molecule.atoms[0].metaType)

    def test_link_identifier_links_to_the_bundle(self):
        client, transport = self._client({'LinkIdentifier': {'data': {'LinkIdentifier': {'set': True}}}})
        response = client.link_identifier('email', 'a@b.c')
        self.assertTrue(response.success())
        self.assertIsInstance(response.query, MutationLinkIdentifier)
        self.assertEqual({'bundle': client.bundle(), 'type': 'email', 'content': 'a@b.c'},
                         transport.sent[-1]['variables'])

    def test_query_balance_enhanced_returns_the_wallet(self):
        balance = {'data': {'Balance': {'address': 'a' * 64, 'position': 'b' * 64, 'tokenSlug': 'TEST',
                                        'bundleHash': 'c' * 64, 'amount': '10'}}}
        client, _ = self._client({'Balance': balance})
        result = asyncio.run(client.query_balance_enhanced('TEST'))
        self.assertTrue(result.success(), result.reason())
        self.assertEqual(10.0, result.payload().balance)

    def test_create_token_enhanced_proposes_the_token(self):
        accepted = {'data': {'ProposeMolecule': {'status': 'accepted', 'molecularHash': 'x', 'reason': None}}}
        client, transport = self._client({'ContinuId': {'data': {'ContinuId': None}}, 'ProposeMolecule': accepted})
        result = asyncio.run(client.create_token_enhanced({'token': 'FOO', 'amount': 5}))
        self.assertTrue(result.success(), result.reason())
        molecule = transport.sent[-1]['variables']['molecule']
        self.assertEqual(('C', 'FOO', '5'), (molecule.atoms[0].isotope, molecule.atoms[0].metaId,
                                              molecule.atoms[0].value))


class ResponseShapeTest(unittest.TestCase):

    def test_errors_only_reply_is_an_error_not_an_exception(self):
        response = Response(_query(), {'errors': [{'message': 'denied'}]})
        self.assertEqual([{'message': 'denied'}], response.errors())
        self.assertIsNone(response.data())

    def test_response_classes_read_their_field(self):
        cases = [
            (ResponseAtom, 'Atom', {'instances': []}),
            (ResponseAuthorizationGuest, 'AccessToken', {'token': 't', 'time': 1}),
            (ResponseMetaBatch, 'MetaBatch', {'a': 1}),
            (ResponsePolicy, 'Policy', {'callback': '{"read": {}}'}),
        ]
        for response_class, field, value in cases:
            with self.subTest(response_class.__name__):
                response = response_class(_query(), {'data': {field: value}})
                self.assertEqual(value, response.data())
        self.assertEqual({'read': {}}, ResponsePolicy(_query(), {'data': {'Policy': {'callback': '{"read": {}}'}}}).payload())
        self.assertEqual('t', ResponseAuthorizationGuest(_query(), {'data': {'AccessToken': {'token': 't'}}}).token())

    def test_request_authorization_response_has_no_broken_wallet_accessor(self):
        self.assertFalse(hasattr(ResponseRequestAuthorization, 'wallet'))


class CellSlugDelimiterTest(unittest.TestCase):

    def test_delimiter_is_a_class_attribute_and_missing_attributes_raise(self):
        self.assertEqual('.', MoleculeStructure.cellSlugDelimiter)
        self.assertEqual('.', Molecule.cellSlugDelimiter)
        structure = MoleculeStructure('cell')
        for name in ('c', 'id', 'Slug'):
            with self.subTest(name), self.assertRaises(AttributeError):
                getattr(structure, name)
        self.assertEqual(['cell', 'x'], MoleculeStructure('cell.x').cell_slug_base())

    def test_init_bundle_meta_builds_the_cell_slug(self):
        source = Wallet(secret=SECRET, token='USER', position='aa' * 32)
        molecule = Molecule(secret=SECRET, source_wallet=source, cell_slug='cell',
                            remainder_wallet=Wallet(secret=SECRET, token='USER', position='cc' * 32))
        molecule.init_bundle_meta({'name': 'x'})
        self.assertEqual('cell.' + source.bundle, molecule.cellSlug)


if __name__ == '__main__':
    unittest.main()
