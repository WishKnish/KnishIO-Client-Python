# -*- coding: utf-8 -*-
from .MutationProposeMolecule import MutationProposeMolecule


class MutationWithdrawBufferToken(MutationProposeMolecule):
    """
    Mutation for withdrawing tokens from buffer
    """
    
    def fill_molecule(self, recipients: dict):
        """
        Fills the Molecule with withdrawal data
        
        :param recipients: Dict of recipient_bundle: amount mappings
        """
        self.molecule().init_withdraw_buffer(recipients)
        self.molecule().sign()
        self.molecule().check()