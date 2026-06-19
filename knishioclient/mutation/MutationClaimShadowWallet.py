# -*- coding: utf-8 -*-
from ..models import Wallet
from .MutationProposeMolecule import MutationProposeMolecule


class MutationClaimShadowWallet(MutationProposeMolecule):
    def fill_molecule(self, token_slug: str, batch_id):
        # Named args: Wallet.create(secret, bundle, token, batch_id, characters). Positional
        # (secret, token_slug, batch_id) mismapped token_slug->bundle and batch_id->token,
        # building the claimed wallet with the wrong token. Mirror JS fillMolecule({token,batchId}).
        wallet = Wallet.create(self.molecule().secret(), token=token_slug, batch_id=batch_id)

        self.molecule().init_shadow_wallet_claim(wallet)
        self.molecule().sign()
        self.molecule().check()