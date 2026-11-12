# -*- coding: utf-8 -*-
import json
from .Response import Response


class ResponsePolicy(Response):
    """
    Response for Policy Query
    """
    
    def data_key(self):
        return 'Policy'
    
    def payload(self):
        """
        Returns the policy payload
        
        :return: dict or None
        """
        policy = self.data()
        
        if not policy:
            return None
        
        if 'callback' in policy and policy['callback']:
            return json.loads(policy['callback'])
        
        return None