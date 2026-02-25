# -*- coding: utf-8 -*-
from .MutationProposeMolecule import MutationProposeMolecule


class MutationDepositBufferToken(MutationProposeMolecule):
    """
    Mutation for depositing tokens to buffer
    """
    
    def fill_molecule(self, amount: float, trade_rates: dict = None):
        """
        Fills the Molecule with provided wallet and amount data
        
        :param amount: Amount to deposit to buffer
        :param trade_rates: Trade rates for the buffer wallet (optional)
        """
        self.molecule().init_deposit_buffer(amount, trade_rates)
        self.molecule().sign()
        self.molecule().check()