# -*- coding: utf-8 -*-
import json
from .Response import Response


class ResponseAtom(Response):
    """
    Response for MetaType Query
    """
    
    def __init__(self, query, json_data):
        """
        Class constructor
        
        :param query: Query object
        :param json_data: JSON response data
        """
        super().__init__(query, json_data, data_key='data.Atom')
    
    def payload(self):
        """
        Returns meta type instance results
        
        :return: dict or None
        """
        meta_type_data = self.data()
        
        if not meta_type_data:
            return None
        
        response = {
            'instances': [],
            'instanceCount': {},
            'paginatorInfo': {}
        }
        
        if 'instances' in meta_type_data:
            response['instances'] = meta_type_data['instances']
            
            for instance_key in range(len(response['instances'])):
                instance = response['instances'][instance_key]
                if 'metasJson' in instance and instance['metasJson']:
                    response['instances'][instance_key]['metas'] = json.loads(instance['metasJson'])
        
        if 'instanceCount' in meta_type_data:
            response['instanceCount'] = meta_type_data['instanceCount']
        
        if 'paginatorInfo' in meta_type_data:
            response['paginatorInfo'] = meta_type_data['paginatorInfo']
        
        return response
    
    def metas(self):
        """
        Returns all metas from instances
        
        :return: list of metas
        """
        response = self.payload()
        metas = []
        
        if response and 'instances' in response:
            for instance in response['instances']:
                if 'metasJson' in instance and instance['metasJson']:
                    metas.append(json.loads(instance['metasJson']))
        
        return metas