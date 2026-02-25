# -*- coding: utf-8 -*-

from .BaseError import BaseError


class WrongTokenTypeException(BaseError):
    """
    Class WrongTokenTypeException
    """
    def __init__(self, message: str = 'Wrong type of token for this isotope', code: int = 1, *args) -> None:
        super(WrongTokenTypeException, self).__init__(message, code, *args)