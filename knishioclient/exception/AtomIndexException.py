# -*- coding: utf-8 -*-

from .BaseError import BaseError


class AtomIndexException(BaseError):
    """
    Class AtomIndexException
    """
    def __init__(self, message: str = 'There is an atom without an index', code: int = 1, *args) -> None:
        super(AtomIndexException, self).__init__(message, code, *args)