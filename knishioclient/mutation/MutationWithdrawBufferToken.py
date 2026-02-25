# -*- coding: utf-8 -*-
from .MutationProposeMolecule import MutationProposeMolecule


class MutationWithdrawBufferToken(MutationProposeMolecule):
    """
    Mutation for withdrawing tokens from buffer
    """
    
    def fill_molecule(self, recipients: dict, signing_wallet=None):
        """
        Fills the Molecule with withdrawal data
        
        :param recipients: Dict of recipient_bundle: amount mappings
        :param signing_wallet: Optional signing wallet
        """
        self.molecule().init_withdraw_buffer(recipients, signing_wallet)
        self.molecule().sign()
        self.molecule().check()