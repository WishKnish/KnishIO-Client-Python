# -*- coding: utf-8 -*-
from ..models import Wallet
from .Response import Response


class ResponseBalance(Response):
    def payload(self):
        data = self.data()
        if data is None:
            return None

        wallet_data = data[0] if isinstance(data, list) and len(data) > 0 else data
        if not isinstance(wallet_data, dict):
            return wallet_data

        # Build a Wallet from the Balance result (the validator returns the wallet's
        # amount/position/address). Previously this returned the raw dict, so every
        # consumer that expected a Wallet (e.g. transfer_token's source resolution and
        # `.balance`) broke. The molecule re-derives the signing key from the client
        # secret + this wallet's position, so no secret/key is needed here.
        wallet = Wallet(
            bundle=wallet_data.get('bundleHash'),
            token=wallet_data.get('tokenSlug'),
            address=wallet_data.get('address'),
            position=wallet_data.get('position'),
            batch_id=wallet_data.get('batchId'),
            characters=wallet_data.get('characters'),
        )
        wallet.balance = float(wallet_data.get('amount') or 0)
        wallet.pubkey = wallet_data.get('pubkey')
        return wallet
