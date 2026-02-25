# -*- coding: utf-8 -*-

from .BaseError import BaseError


class TransferUnbalancedException(BaseError):
    """
    Class TransferUnbalancedException
    """
    def __init__(self, message: str = 'Token transfer atoms are unbalanced', code: int = 1, *args) -> None:
        super(TransferUnbalancedException, self).__init__(message, code, *args)