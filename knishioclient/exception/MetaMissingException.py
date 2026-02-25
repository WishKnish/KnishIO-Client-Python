# -*- coding: utf-8 -*-

from .BaseError import BaseError


class MetaMissingException(BaseError):
    """
    Class MetaMissingException
    """
    def __init__(self, message: str = 'Empty meta data.', code: int = 1, *args) -> None:
        super(MetaMissingException, self).__init__(message, code, *args)