# -*- coding: utf-8 -*-
"""
Query module for KnishIOClient SDK
Contains all query classes for GraphQL operations
"""

# Import all query classes for backward compatibility
from .Query import Query
from .QueryBalance import QueryBalance
from .QueryContinuId import QueryContinuId
from .QueryMetaTypeViaAtom import QueryMetaTypeViaAtom
from .QueryMetaType import QueryMetaType
from .QueryWalletBundle import QueryWalletBundle
from .QueryWalletList import QueryWalletList
from .QueryActiveSession import QueryActiveSession
from .QueryToken import QueryToken
from .QueryAtom import QueryAtom
from .QueryBatch import QueryBatch
from .QueryBatchHistory import QueryBatchHistory
from .QueryPolicy import QueryPolicy
from .QueryUserActivity import QueryUserActivity

# Also maintain backward compatibility with old imports
from ..models import Coder

__all__ = [
    'Query',
    'QueryBalance',
    'QueryContinuId',
    'QueryMetaTypeViaAtom',
    'QueryMetaType',
    'QueryWalletBundle',
    'QueryWalletList',
    'QueryActiveSession',
    'QueryToken',
    'QueryAtom',
    'QueryBatch',
    'QueryBatchHistory',
    'QueryPolicy',
    'QueryUserActivity',
    'Coder',  # For backward compatibility
]