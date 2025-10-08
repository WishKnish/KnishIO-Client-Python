# -*- coding: utf-8 -*-

from .BaseError import BaseError


class InvalidResponseException(BaseError):
    """
    Class InvalidResponseException
    """
    def __init__(self, message: str = 'GraphQL did not provide a valid response.', code: int = 2, *args) -> None:
        super(InvalidResponseException, self).__init__(message, code, *args)