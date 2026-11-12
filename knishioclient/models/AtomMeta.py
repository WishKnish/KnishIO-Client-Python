# -*- coding: utf-8 -*-

from typing import Dict, List
from .base import Base
from .Meta import Meta
from ..libraries import strings
from .PolicyMeta import PolicyMeta

USE_META_CONTEXT = False
DEFAULT_META_CONTEXT = 'https://www.schema.org'


class AtomMeta(Base):
    """class AtomMeta

    Holds the meta as the normalized ``[{key, value}]`` list JS ``AtomMeta`` holds: a dict or a
    list is accepted, and ``merge`` appends entries in order (a repeated key is kept twice, as in
    JS), so the hashed meta matches the JS reference entry for entry.
    """

    def __init__(self, meta=None):
        self.meta: List[Dict] = Meta.normalize_meta(meta if meta is not None else [])

    def merge(self, meta) -> "AtomMeta":
        self.meta = self.meta + Meta.normalize_meta(meta)
        return self

    def add_context(self, context: str = None) -> "AtomMeta":
        if USE_META_CONTEXT:
            self.merge({"context": context or DEFAULT_META_CONTEXT})
        return self

    def set_atom_wallet(self, wallet: "Wallet") -> "AtomMeta":
        # JS AtomMeta.setAtomWallet: tokenUnits when the wallet holds units, tradeRates only when
        # they are a non-empty array (JS tests `tradeRates.length`, which an object never has).
        wallet_meta = {}
        if wallet.tokenUnits:
            wallet_meta.update({"tokenUnits": strings.js_json_stringify(wallet.get_token_units_data())})
        if isinstance(wallet.tradeRates, (list, tuple)) and len(wallet.tradeRates) > 0:
            wallet_meta.update({"tradeRates": strings.js_json_stringify(wallet.tradeRates)})
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
        # JS `shadowWalletClaim * 1`: True -> 1 -> "1"
        return self.merge({"shadowWalletClaim": shadow_wallet_claim * 1})

    def add_policy(self, policy: Dict) -> "AtomMeta":
        # JS AtomMeta.addPolicy passes Object.keys() of its normalised meta ARRAY, i.e. the entry
        # indices, and stores the policy as one JSON string under `policy` (hashed into the atom).
        policy_meta = PolicyMeta(policy, [str(index) for index in range(len(self.meta))])
        return self.merge({"policy": policy_meta.to_json()})

    def get(self) -> List[Dict]:
        return self.meta
