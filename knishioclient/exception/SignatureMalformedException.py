# -*- coding: utf-8 -*-

from .BaseError import BaseError


class SignatureMalformedException(BaseError):
    """
    Class SignatureMalformedException
    """
    def __init__(self, message: str = 'OTS malformed', code: int = 1, *args) -> None:
        super(SignatureMalformedException, self).__init__(message, code, *args)