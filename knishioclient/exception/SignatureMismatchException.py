# -*- coding: utf-8 -*-

from .BaseError import BaseError


class SignatureMismatchException(BaseError):
    """
    Class SignatureMismatchException
    """
    def __init__(self, message: str = 'OTS mismatch', code: int = 1, *args) -> None:
        super(SignatureMismatchException, self).__init__(message, code, *args)