# -*- coding: utf-8 -*-
from .Response import Response


class ResponseMetaType(Response):
    def data_key(self):
        # Override to return the correct key for MetaType queries
        return 'MetaType'
    
    def payload(self):
        data = self.data()
        if data is None or (isinstance(data, list) and len(data) == 0):
            return {
                'instances': [],
                'instanceCount': [],
                'paginatorInfo': {}
            }

        # Return structure matching JavaScript/PHP SDKs
        response = {
            'instances': [],
            'instanceCount': [],
            'paginatorInfo': {}
        }

        # Get the last meta type data (matching JS SDK behavior)
        meta_data = data[-1] if data else {}

        if 'instances' in meta_data:
            response['instances'] = meta_data['instances']
        
        if 'instanceCount' in meta_data:
            response['instanceCount'] = meta_data['instanceCount']
        
        if 'paginatorInfo' in meta_data:
            response['paginatorInfo'] = meta_data['paginatorInfo']

        return response