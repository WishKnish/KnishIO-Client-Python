# -*- coding: utf-8 -*-
from .Response import Response


class ResponseMetaBatch(Response):
    """
    Response for MetaBatch Query
    """
    
    def data_key(self):
        return 'MetaBatch'
