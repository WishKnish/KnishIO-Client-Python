# -*- coding: utf-8 -*-

from typing import Dict
from json import dumps
from .base import Base
from .PolicyMeta import PolicyMeta

USE_META_CONTEXT = False
DEFAULT_META_CONTEXT = 'https://www.schema.org'


class AtomMeta(Base):
    """class AtomMeta"""

    def __init__(self, meta=None):
        self.meta = meta or {}

    def merge(self, meta: dict) -> "AtomMeta":
        self.meta = {**self.meta, **meta}
        return self

    def add_context(self, context: str) -> "AtomMeta":
        if USE_META_CONTEXT:
            self.merge({"context": context or DEFAULT_META_CONTEXT})
        return self

    def set_atom_wallet(self, wallet: "Wallet") -> "AtomMeta":
        # Removed automatic addition of pubkey and characters for cross-SDK compatibility
        # Only add metadata that is explicitly needed for the specific operation
        wallet_meta = {}
        if wallet.tokenUnits:
            wallet_meta.update({"tokenUnits": dumps(wallet.get_token_units_data())})
        if wallet.tradeRates:
            wallet_meta.update({"tradeRates": dumps(wallet.tradeRates)})
        if wallet_meta:
            return self.merge(wallet_meta)
        return self

    def set_meta_wallet(self, wallet: "Wallet") -> "AtomMeta":
        return self.merge({
            "walletTokenSlug": wallet.token,
            "walletBundleHash": wallet.bundle,
            "walletAddress": wallet.address,
            "walletPosition": wallet.position,
            "walletBatchId": wallet.batchId,
            "walletPubkey": wallet.pubkey,
            "walletCharacters": wallet.characters
        })

    def set_shadow_wallet_claim(self, shadow_wallet_claim) -> "AtomMeta":
        return self.merge({"shadowWalletClaim": shadow_wallet_claim * 1})

    def set_signing_wallet(self, signing_wallet: "Wallet") -> "AtomMeta":
        return self.merge({
            "signingWallet": dumps({
                "tokenSlug": signing_wallet.token,
                "bundleHash": signing_wallet.bundle,
                "address": signing_wallet.address,
                "position": signing_wallet.position,
                "pubkey": signing_wallet.pubkey,
                "characters": signing_wallet.characters
            })
        })

    def add_policy(self, policy: Dict) -> "AtomMeta":
        policy_meta = PolicyMeta(policy, list(self.meta.keys()))
        return self.merge(policy_meta.get())

    def get(self) -> Dict:
          return self.meta