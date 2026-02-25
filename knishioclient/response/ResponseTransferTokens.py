# -*- coding: utf-8 -*-
from .ResponseProposeMolecule import ResponseProposeMolecule


class ResponseTransferTokens(ResponseProposeMolecule):
    """
    Response for token transfer queries
    """
    
    def payload(self):
        """
        Returns result of the transfer
        
        :return: dict with reason and status
        """
        result = {
            'reason': None,
            'status': None
        }
        data = self.data()
        
        if data:
            result['reason'] = data.get('reason', 'Invalid response from server')
            result['status'] = data.get('status', 'rejected')
        else:
            result['reason'] = 'Invalid response from server'
            result['status'] = 'rejected'
        
        return result