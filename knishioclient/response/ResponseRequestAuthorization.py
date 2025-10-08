# -*- coding: utf-8 -*-
from ..models import Wallet
from .ResponseProposeMolecule import ResponseProposeMolecule


class ResponseRequestAuthorization(ResponseProposeMolecule):
    def auth_token(self):
        data = self.data()
        if data is None or 'payload' not in data:
            return None

        payload = data['payload']
        
        # If payload is a JSON string, parse it
        if isinstance(payload, str):
            import json
            try:
                payload = json.loads(payload)
            except (json.JSONDecodeError, ValueError):
                return None
        
        # Now payload should be a dict
        if isinstance(payload, dict):
            return payload.get('token', None)
        
        return None

    def wallet(self):
        token = self.auth_token()
        return Wallet.json_to_object(token) if token is not None else None