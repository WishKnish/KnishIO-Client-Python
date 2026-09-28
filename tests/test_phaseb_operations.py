# -*- coding: utf-8 -*-
"""Client-level behaviour of replenish, fusion and the buffer operations (contracts 9.1, 9.2,
9.6) and the pre-submit molecule check (contract 9.7), against an offline ledger stub.
The canonical molecule shapes are pinned in test_patent_vectors.py."""

import asyncio
import json
import unittest
from unittest import mock

from tests.stub_ledger import POINTER_POSITION, StubLedger, meta_dict, meta_keys, wallet_row

from knishioclient.exception import (
    AtomsMissingException,
    NegativeMeaningException,
    StackableUnitAmountException,
    TransferBalanceException,
)
from knishioclient.libraries import crypto
from knishioclient.models import Molecule, Wallet
from knishioclient.mutation import MutationProposeMolecule


class ReplenishTest(unittest.TestCase):
    TOKEN = "REPLTOK"

    def test_replenish_credits_the_identitys_existing_wallet(self):
        ledger = StubLedger()
        credited = Wallet(secret=ledger.secret, token=self.TOKEN)
        credited.batchId = crypto.generate_batch_id()
        ledger.set_balance(self.TOKEN, wallet_row(credited, 3, ["S1", "S2", "S3"]))

        ledger.client().replenish_token(self.TOKEN, units=[["R1", "R1", {}]])

        c_atom = ledger.proposals[0].atoms[0]
        self.assertEqual((c_atom.token, c_atom.position), ("USER", POINTER_POSITION))
        self.assertEqual(meta_keys(c_atom), ["action", "address", "position", "pubkey", "batchId", "tokenUnits"])
        metas = meta_dict(c_atom)
        self.assertEqual(
            (metas["address"], metas["position"], metas["pubkey"], metas["batchId"]),
            (credited.address, credited.position, credited.pubkey, credited.batchId),
        )
        self.assertEqual(c_atom.batchId, credited.batchId)
        self.assertEqual(json.loads(metas["tokenUnits"]), [["R1", "R1", {}]])

    def test_replenish_without_a_wallet_credits_a_new_wallet_of_the_identity(self):
        ledger = StubLedger()

        ledger.client().replenish_token(self.TOKEN, 500)

        c_atom = ledger.proposals[0].atoms[0]
        metas = meta_dict(c_atom)
        self.assertEqual(meta_keys(c_atom), ["action", "address", "position", "pubkey"])
        self.assertEqual(
            Wallet(secret=ledger.secret, token=self.TOKEN, position=metas["position"]).address,
            metas["address"],
        )
        self.assertIsNone(c_atom.batchId)

    def test_replenish_refuses_invalid_amounts_before_sending(self):
        ledger = StubLedger()
        stackable = Wallet(secret=ledger.secret, token=self.TOKEN)
        ledger.set_balance(self.TOKEN, wallet_row(stackable, 2, ["S1", "S2"]))
        client = ledger.client()

        with self.assertRaises(StackableUnitAmountException):
            client.replenish_token(self.TOKEN, 2)
        with self.assertRaises(StackableUnitAmountException):
            client.replenish_token(self.TOKEN, 3, units=[["R1", "R1", {}]])
        for amount in (0, -5, None):
            with self.assertRaises(NegativeMeaningException):
                StubLedger().client().replenish_token(self.TOKEN, amount)
        self.assertEqual(ledger.proposals, [])


class FusionTest(unittest.TestCase):
    TOKEN = "FUSETOK"
    UNITS = ["U1", "U2", "U3", "U4", "U5"]

    def setUp(self):
        self.ledger = StubLedger()
        self.source = Wallet(secret=self.ledger.secret, token=self.TOKEN)
        self.ledger.set_balance(self.TOKEN, wallet_row(self.source, len(self.UNITS), self.UNITS))
        self.client = self.ledger.client()

    def test_fusion_for_a_foreign_bundle_delivers_to_an_addressless_recipient(self):
        foreign = crypto.generate_bundle_hash(crypto.generate_secret())

        self.client.fuse_token(foreign, self.TOKEN, "FUSED", ["U1", "U3"])

        fusion_atom = self.ledger.proposals[0].atoms[2]
        self.assertEqual((fusion_atom.isotope, fusion_atom.metaId), ("F", foreign))
        self.assertIsNone(fusion_atom.walletAddress)

    def test_fusion_of_an_unbatched_source_carries_no_batch_ids(self):
        self.client.fuse_token(self.ledger.bundle, self.TOKEN, "FUSED", ["U1", "U3"])

        self.assertEqual([atom.batchId for atom in self.ledger.proposals[0].atoms], [None] * 4)

    def test_fusion_refuses_unknown_or_colliding_units_before_sending(self):
        with self.assertRaisesRegex(TransferBalanceException, "U9 not found in the source wallet"):
            self.client.fuse_token(self.ledger.bundle, self.TOKEN, "FUSED", ["U1", "U9"])
        with self.assertRaisesRegex(TransferBalanceException, "already exists in the source wallet"):
            self.client.fuse_token(self.ledger.bundle, self.TOKEN, "U5", ["U1", "U2"])
        self.assertEqual(self.ledger.proposals, [])


class BufferDepositTest(unittest.TestCase):
    def test_deposit_debits_the_regular_wallet_the_balance_query_returns(self):
        ledger = StubLedger()
        regular = Wallet(secret=ledger.secret, token="BUFTOK")
        ledger.set_balance("BUFTOK", wallet_row(regular, 100))

        ledger.client().deposit_buffer_token("BUFTOK", 30)

        self.assertNotIn("type", ledger.balance_requests[-1])
        molecule = ledger.proposals[0]
        self.assertEqual([atom.isotope for atom in molecule.atoms], ["V", "B", "V"])
        self.assertEqual(molecule.atoms[0].position, regular.position)
        self.assertEqual([atom.value for atom in molecule.atoms], ["-100", "30", "70"])


class QueryWalletsTest(unittest.TestCase):
    def test_query_wallets_returns_the_bundles_wallets_with_their_token_units(self):
        ledger = StubLedger()
        stackable = Wallet(secret=ledger.secret, token="FUSETOK")
        fused = Wallet(secret=ledger.secret, token="FUSETOK")
        ledger.wallets = [wallet_row(stackable, 2, ["U1", "U3"]), wallet_row(fused, 1, ["FUSED"])]

        wallets = ledger.client().query_wallets()

        self.assertEqual(
            [(wallet.position, [unit.id for unit in wallet.tokenUnits]) for wallet in wallets],
            [(stackable.position, ["U1", "U3"]), (fused.position, ["FUSED"])],
        )


class PreSubmitCheckTest(unittest.TestCase):
    """Contract 9.7: a high-level operation refuses a molecule its own check rejects and sends
    nothing; the raw propose-molecule path submits a caller-built molecule unchecked."""

    @staticmethod
    def _init_meta_without_continu_id(original):
        def init_meta(molecule, *args, **kwargs):
            original(molecule, *args, **kwargs)
            molecule.atoms = [atom for atom in molecule.atoms if atom.isotope != "I"]
            return molecule
        return init_meta

    def test_create_meta_refuses_a_user_signed_molecule_without_continu_id(self):
        ledger = StubLedger()
        client = ledger.client()
        with mock.patch.object(Molecule, "init_meta", self._init_meta_without_continu_id(Molecule.init_meta)):
            with self.assertRaises(AtomsMissingException):
                client.create_meta("AppAsset", "asset-1", {"appRole": "admin"})
        self.assertEqual(ledger.proposals, [])

    def test_create_meta_enhanced_refuses_a_user_signed_molecule_without_continu_id(self):
        ledger = StubLedger()
        client = ledger.client()
        with mock.patch.object(Molecule, "init_meta", self._init_meta_without_continu_id(Molecule.init_meta)):
            response = asyncio.run(client.create_meta_enhanced(
                {"metaType": "AppAsset", "metaId": "asset-1", "meta": {"appRole": "admin"}}
            ))
        self.assertFalse(response.success())
        self.assertIn("ContinuID", response.reason())
        self.assertEqual(ledger.proposals, [])

    def test_raw_propose_molecule_submits_a_caller_built_molecule_unchecked(self):
        ledger = StubLedger()
        client = ledger.client()
        molecule = client.create_molecule()
        molecule.init_meta({"appRole": "admin"}, "AppAsset", "asset-1")
        molecule.atoms = [atom for atom in molecule.atoms if atom.isotope != "I"]
        molecule.sign()

        client.create_molecule_mutation(MutationProposeMolecule, molecule).execute()

        self.assertEqual(ledger.proposals, [molecule])
        self.assertEqual([atom.isotope for atom in molecule.atoms], ["M"])


if __name__ == "__main__":
    unittest.main()
