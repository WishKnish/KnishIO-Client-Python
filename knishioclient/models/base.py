# -*- coding: utf-8 -*-

from json import JSONEncoder
from typing import Any, Dict
from ..libraries import strings


class Coder(JSONEncoder):
    """ class Coder """

    def default(self, value: Any) -> Any:
        """
        :param value: Any
        :return: Any
        """
        # Import here to avoid circular dependency
        from . import Atom, Molecule, Meta
        
        if isinstance(value, Atom):
            return {
                'position': value.position,
                'walletAddress': value.walletAddress,
                'isotope': value.isotope,
                'token': value.token,
                'value': value.value,
                'batchId': value.batchId,
                'metaType': value.metaType,
                'metaId': value.metaId,
                'meta': value.meta,
                'index': value.index,
                'otsFragment': value.otsFragment,
                'createdAt': value.createdAt,
            }

        if isinstance(value, Molecule):
            result = {
                'molecularHash': value.molecularHash,
                'cellSlug': value.cellSlug,
                'bundle': value.bundle,
                'status': value.status,
                'createdAt': value.createdAt,
                'atoms': value.atoms,
            }
            # Include remainderWallet if it exists (matching JavaScript)
            if hasattr(value, 'remainderWallet'):
                result['remainderWallet'] = value.remainderWallet.address if value.remainderWallet else None
            # Include sourceWallet for cross-SDK validation
            if hasattr(value, 'sourceWallet') and value.sourceWallet:
                from . import Wallet
                if isinstance(value.sourceWallet, Wallet):
                    result['sourceWallet'] = {
                        'address': value.sourceWallet.address,
                        'position': value.sourceWallet.position,
                        'token': value.sourceWallet.token,
                        'balance': value.sourceWallet.balance
                    }
            return result

        if isinstance(value, Meta):
            return {
                'modelType': value.modelType,
                'modelId': value.modelId,
                'meta': value.meta,
                'snapshotMolecule': value.snapshotMolecule,
                'createdAt': value.createdAt,
            }

        if isinstance(value, bytes):
            return strings.decode(value)

        return super().default(value)


class Base(object):
    def __str__(self) -> str:
        """
        :return: str
        """
        return self.json()

    def __repr__(self) -> str:
        """
        :return: str
        """
        return self.__str__()

    def json(self) -> str:
        """
        :return: str
        """
        return Coder().encode(self)

    @classmethod
    def array_to_object(cls, data: Dict, obj=None):
        thing = obj or cls()

        for prop, value in data.items():
            if hasattr(thing, 'set_property') and callable(getattr(thing, 'set_property')):
                thing.set_property(prop, value)
                continue

            setattr(thing, prop, value)

        return thing