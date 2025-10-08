# -*- coding: utf-8 -*-

from .BaseError import BaseError


class DecryptException(BaseError):
    """
    Class DecryptException
    """
    def __init__(self, message: str = 'Error during decryption.', code: int = 1, *args) -> None:
        super(DecryptException, self).__init__(message, code, *args)