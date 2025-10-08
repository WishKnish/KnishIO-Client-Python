# -*- coding: utf-8 -*-
"""
Mutation module for KnishIOClient SDK
Contains all mutation classes for GraphQL operations
"""

# Import all mutation classes for backward compatibility
from .Mutation import Mutation
from .MutationProposeMolecule import MutationProposeMolecule
from .MutationActiveSession import MutationActiveSession
from .MutationClaimShadowWallet import MutationClaimShadowWallet
from .MutationCreateIdentifier import MutationCreateIdentifier
from .MutationCreateMeta import MutationCreateMeta
from .MutationCreateRule import MutationCreateRule
from .MutationCreateToken import MutationCreateToken
from .MutationCreateWallet import MutationCreateWallet
from .MutationDepositBufferToken import MutationDepositBufferToken
from .MutationLinkIdentifier import MutationLinkIdentifier
from .MutationRequestAuthorization import MutationRequestAuthorization
from .MutationRequestAuthorizationGuest import MutationRequestAuthorizationGuest
from .MutationRequestTokens import MutationRequestTokens
from .MutationTransferTokens import MutationTransferTokens
from .MutationWithdrawBufferToken import MutationWithdrawBufferToken

__all__ = [
    'Mutation',
    'MutationProposeMolecule',
    'MutationActiveSession',
    'MutationClaimShadowWallet',
    'MutationCreateIdentifier',
    'MutationCreateMeta',
    'MutationCreateRule',
    'MutationCreateToken',
    'MutationCreateWallet',
    'MutationDepositBufferToken',
    'MutationLinkIdentifier',
    'MutationRequestAuthorization',
    'MutationRequestAuthorizationGuest',
    'MutationRequestTokens',
    'MutationTransferTokens',
    'MutationWithdrawBufferToken',
]