# -*- coding: utf-8 -*-
from ..models import Wallet
from .MutationProposeMolecule import MutationProposeMolecule


class MutationClaimShadowWallet(MutationProposeMolecule):
    def fill_molecule(self, token_slug: str, batch_id):
        wallet = Wallet.create(self.molecule().secret(), token_slug, batch_id)

        self.molecule().init_shadow_wallet_claim(token_slug, wallet)
        self.molecule().sign()
        self.molecule().check()