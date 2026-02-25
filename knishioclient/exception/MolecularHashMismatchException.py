# -*- coding: utf-8 -*-

from .BaseError import BaseError


class MolecularHashMismatchException(BaseError):
    """
    Class MolecularHashMismatchException
    """
    def __init__(self, message: str = 'The molecular hash does not match', code: int = 1, *args) -> None:
        super(MolecularHashMismatchException, self).__init__(message, code, *args)