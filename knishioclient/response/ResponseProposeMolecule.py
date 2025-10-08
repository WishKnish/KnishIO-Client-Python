# -*- coding: utf-8 -*-
from .Response import Response


class ResponseProposeMolecule(Response):
    def data_key(self):
        return 'ProposeMolecule'

    def status(self):
        data = self.data()
        return data['status'] if data is not None and 'status' in data else None

    def reason(self):
        data = self.data()
        return data['reason'] if data is not None and 'reason' in data else None

    def hash(self):
        data = self.data()
        return data['molecularHash'] if data is not None and 'molecularHash' in data else None

    def success(self):
        return self.status() == 'accepted'

    def __str__(self):
        target = {
            'status': self.status(),
            'reason': self.reason(),
            'hash': self.hash(),
            'query': str(self.query),
        }

        from ..models import Coder
        return Coder().encode(target)