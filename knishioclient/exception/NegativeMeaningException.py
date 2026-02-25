# -*- coding: utf-8 -*-

from .BaseError import BaseError


class NegativeMeaningException(BaseError):
    """
    Class NegativeMeaningException
    """
    def __init__(self, message: str = 'Negative meaning.', code: int = 1, *args) -> None:
        super(NegativeMeaningException, self).__init__(message, code, *args)