# -*- coding: utf-8 -*-
import json
from copy import deepcopy
from .Response import Response


class ResponseQueryUserActivity(Response):
    """
    Response for UserActivity Query
    """
    
    def __init__(self, query, json_data):
        """
        Class constructor
        
        :param query: Query object
        :param json_data: JSON response data
        """
        super().__init__(query, json_data, data_key='data.UserActivity')
    
    def payload(self):
        """
        Returns the user activity data with parsed JSON
        
        :return: dict or None
        """
        data = deepcopy(self.data())
        
        if data and 'instances' in data:
            for datum in data['instances']:
                if 'jsonData' in datum and datum['jsonData']:
                    datum['jsonData'] = json.loads(datum['jsonData'])
        
        return data