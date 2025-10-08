# -*- coding: utf-8 -*-

from .BaseError import BaseError


class RuleArgumentException(BaseError):
    def __init__(self, message: str = 'An incorrect argument!', code: int = 1, *args):
        super(RuleArgumentException, self).__init__(message, code, *args)