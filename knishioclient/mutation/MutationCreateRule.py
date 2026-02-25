# -*- coding: utf-8 -*-
from ..response import ResponseCreateRule
from .MutationProposeMolecule import MutationProposeMolecule


class MutationCreateRule(MutationProposeMolecule):
    """
    Query for creating new Meta attached to some MetaType
    """
    
    def fill_molecule(self, meta_type: str, meta_id: str, rule: list, policy: dict = None):
        """
        Fill molecule with rule creation data
        
        :param meta_type: Meta type to attach rule to
        :param meta_id: Meta ID to attach rule to
        :param rule: List of rule objects
        :param policy: Policy dict (optional)
        """
        # For now, we'll need to add the create_rule method to Molecule
        # This is a placeholder that will need the Molecule.init_rule_creation method
        self.molecule().init_rule_creation(meta_type, meta_id, rule, policy or {})
        self.molecule().sign()
        self.molecule().check()
    
    def create_response(self, response):
        """
        Builds a new Response object from a JSON response
        
        :param response: JSON response data
        :return: ResponseCreateRule instance
        """
        return ResponseCreateRule(self, response)