# -*- coding: utf-8 -*-
from ..models import Wallet, TokenUnit
from .Response import Response


def _wallet_from_data(item):
    """Build a Wallet from a GraphQL wallet/balance dict (mirrors ResponseBalance). Returns None
    for a non-dict. Replaces the nonexistent Wallet.json_to_object (which raised AttributeError)."""
    if not isinstance(item, dict):
        return None
    wallet = Wallet(
        bundle=item.get('bundleHash'),
        token=item.get('tokenSlug'),
        address=item.get('address'),
        position=item.get('position'),
        batch_id=item.get('batchId'),
        characters=item.get('characters'),
    )
    wallet.balance = float(item.get('amount') or 0)
    wallet.pubkey = item.get('pubkey')
    # Stackable (NFT) token units (forward-compat; validator resolver stub until gap SDK-001).
    wallet.tokenUnits = [TokenUnit.create_from_graph_ql(u) for u in (item.get('tokenUnits') or [])]
    return wallet


class ResponseWalletList(Response):
    __bundle = None

    def bundle(self):
        return self.__bundle

    def init_response(self, response: dict):
        super(ResponseWalletList, self).init_response(response)

        if self.errors() is not None:
            return

        data = self.data()
        if data is None:
            return

        wallets = data if isinstance(data, list) else [data]
        for item in wallets:
            wallet = _wallet_from_data(item)
            if not isinstance(wallet, Wallet):
                continue

            if wallet.bundle == self.query.variables()["bundleHash"]:
                self.__bundle = wallet.bundle
                return

    def payload(self):
        data = self.data()
        if data is None:
            return []

        wallets = []
        _wallets = data if isinstance(data, list) else [data]
        for item in _wallets:
            wallet = _wallet_from_data(item)
            if not isinstance(wallet, Wallet):
                continue
            if self.__bundle is not None and wallet.bundle != self.__bundle:
                continue
            wallets.append(wallet)

        return wallets