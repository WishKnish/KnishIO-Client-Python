# -*- coding: utf-8 -*-
from .Response import Response


class ResponseActiveSession(Response):
    """
    Response for ActiveSession mutation
    """
    
    def data_key(self):
        return 'ActiveSession'