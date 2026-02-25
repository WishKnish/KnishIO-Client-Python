# -*- coding: utf-8 -*-
import json
from datetime import datetime
from .Response import Response


class ResponseQueryActiveSession(Response):
    """
    Response for QueryActiveSession
    """
    
    def data_key(self):
        return 'ActiveUser'
    
    def payload(self):
        """
        Process and return the list of active sessions
        
        :return: list or None
        """
        data_list = self.data()
        
        if not data_list:
            return None
        
        active_users = []
        
        for item in data_list:
            active_session = dict(item)
            
            # Parse JSON data if present
            if 'jsonData' in active_session and active_session['jsonData']:
                try:
                    active_session['jsonData'] = json.loads(active_session['jsonData'])
                except (json.JSONDecodeError, TypeError):
                    pass  # Keep original value if JSON parsing fails
            
            # Parse dates if present
            if 'createdAt' in active_session and active_session['createdAt']:
                try:
                    active_session['createdAt'] = datetime.fromisoformat(active_session['createdAt'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass  # Keep original value if date parsing fails
            
            if 'updatedAt' in active_session and active_session['updatedAt']:
                try:
                    active_session['updatedAt'] = datetime.fromisoformat(active_session['updatedAt'].replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    pass  # Keep original value if date parsing fails
            
            active_users.append(active_session)
        
        return active_users