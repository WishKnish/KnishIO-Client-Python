# -*- coding: utf-8 -*-
import json
from .Response import Response


class ResponsePolicy(Response):
    """
    Response for Policy Query
    """
    
    def __init__(self, query, json_data):
        """
        Class constructor
        
        :param query: Query object
        :param json_data: JSON response data
        """
        super().__init__(query, json_data)
        self.data_key = 'data.Policy'
        self.init()
    
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