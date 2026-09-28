# -*- coding: utf-8 -*-
"""Offline stand-in for the validator's GraphQL transport, for client-level tests.

It answers ``ContinuId`` with the USER wallet at a fixed pointer position (derived from the test
secret, so the client's signature verifies), ``Balance`` from a per-(token, type) table, and
accepts every ``ProposeMolecule``, recording the molecule it was sent. Nothing leaves the process.
"""

import sys
from pathlib import Path

SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if SDK_ROOT not in sys.path:
    sys.path.insert(0, SDK_ROOT)

from knishioclient.client.KnishIOClient import KnishIOClient  # noqa: E402
from knishioclient.libraries import crypto  # noqa: E402
from knishioclient.models import Wallet  # noqa: E402

SECRET = "a1b2c3d4e5f6" * 8
POINTER_POSITION = "c0ffee" + "0" * 58


def wallet_row(wallet: Wallet, amount, units=None) -> dict:
    """The GraphQL Balance/ContinuId row for ``wallet`` (``units`` = list of unit ids)."""
    return {
        "address": wallet.address,
        "bundleHash": wallet.bundle,
        "tokenSlug": wallet.token,
        "batchId": wallet.batchId,
        "position": wallet.position,
        "amount": str(amount),
        "characters": wallet.characters,
        "pubkey": wallet.pubkey,
        "createdAt": None,
        "tokenUnits": [{"id": unit, "name": unit, "metas": None} for unit in (units or [])],
    }


class StubLedger:
    def __init__(self, secret: str = SECRET):
        self.secret = secret
        self.bundle = crypto.generate_bundle_hash(secret)
        self.pointer = Wallet(secret=secret, token="USER", position=POINTER_POSITION)
        self.balances = {}
        self.balance_requests = []
        self.wallets = []
        self.proposals = []

    def set_balance(self, token: str, row, wallet_type: str = None):
        self.balances[(token, wallet_type)] = row

    def client(self) -> KnishIOClient:
        client = KnishIOClient("https://test.local/graphql")
        client.set_cell_slug("public")
        client.set_secret(self.secret)
        client.client().send = self.send
        return client

    def send(self, request, options=None):
        query, variables = request["query"], request["variables"] or {}
        if "ContinuId" in query:
            return {"data": {"ContinuId": wallet_row(self.pointer, 0)}}
        if "Wallet(" in query:
            return {"data": {"Wallet": self.wallets}}
        if "Balance" in query:
            self.balance_requests.append(dict(variables))
            return {"data": {"Balance": self.balances.get((variables.get("token"), variables.get("type")))}}
        if "ProposeMolecule" in query:
            self.proposals.append(variables["molecule"])
            return {"data": {"ProposeMolecule": {
                "molecularHash": variables["molecule"].molecularHash,
                "status": "accepted",
                "reason": None,
                "payload": None,
            }}}
        raise AssertionError("unexpected request: %s" % query)


def meta_dict(atom) -> dict:
    return {item["key"]: item["value"] for item in atom.meta}


def meta_keys(atom) -> list:
    return [item["key"] for item in atom.meta]
