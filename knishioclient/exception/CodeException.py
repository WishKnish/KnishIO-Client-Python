# -*- coding: utf-8 -*-

from .BaseError import BaseError


class CodeException(BaseError):
    """
    Class CodeException
    """
    def __init__(self, message: str = 'Code exception', code: int = 1, *args) -> None:
        super(CodeException, self).__init__(message, code, *args)