# -*- coding: utf-8 -*-

from .BaseError import BaseError


class WalletCredentialException(BaseError):
    def __init__(self, message: str = 'Attempting to create a wallet with no credentials (secret or bundle hash)', code: int = 1, *args):
        super(WalletCredentialException, self).__init__(message, code, *args)