# -*- coding: utf-8 -*-

from .BaseError import BaseError


class WalletShadowException(BaseError):
    """
    Class WalletShadowException
    """
    def __init__(self, message: str = 'The shadow wallet does not exist', code: int = 1, *args) -> None:
        super(WalletShadowException, self).__init__(message, code, *args)