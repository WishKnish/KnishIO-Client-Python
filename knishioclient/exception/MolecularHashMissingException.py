# -*- coding: utf-8 -*-

from .BaseError import BaseError


class MolecularHashMissingException(BaseError):
    """
    Class MolecularHashMissingException
    """
    def __init__(self, message: str = 'The molecular hash is missing', code: int = 1, *args) -> None:
        super(MolecularHashMissingException, self).__init__(message, code, *args)