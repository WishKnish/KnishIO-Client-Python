# -*- coding: utf-8 -*-

from .BaseError import BaseError


class AtomsMissingException(BaseError):
    """
    Class AtomsMissingException
    """
    def __init__(self, message: str = 'The molecule does not contain atoms', code: int = 1, *args) -> None:
        super(AtomsMissingException, self).__init__(message, code, *args)