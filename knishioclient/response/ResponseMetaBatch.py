# -*- coding: utf-8 -*-
from .Response import Response


class ResponseMetaBatch(Response):
    """
    Response for MetaBatch Query
    """
    
    def __init__(self, query, json_data):
        """
        Class constructor
        
        :param query: Query object
        :param json_data: JSON response data
        """
        super().__init__(query, json_data, data_key='data.MetaBatch')