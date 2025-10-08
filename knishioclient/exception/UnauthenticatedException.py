# -*- coding: utf-8 -*-

from .BaseError import BaseError


class UnauthenticatedException(BaseError):
    """
    Class UnauthenticatedException
    """
    def __init__(self, message: str = 'Unauthenticated.', code: int = 1, *args) -> None:
        super(UnauthenticatedException, self).__init__(message, code, *args)