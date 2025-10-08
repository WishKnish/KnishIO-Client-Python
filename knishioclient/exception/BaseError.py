# -*- coding: utf-8 -*-


class BaseError(Exception):
    """
    Class BaseError
    """
    _message: str
    _code: int

    def __init__(self, message: str = None, code: int = 1, *args) -> None:
        self._message = message
        self._code = code
        super(BaseError, self).__init__(self._message, self._code, *args)

    @property
    def message(self) -> str:
        return self._message

    @property
    def code(self) -> int:
        return self._code

    def __str__(self) -> str:
        return self.message or self.__repr__()

    def __repr__(self) -> str:
        return "<%s: %s>" % (self.__class__.__name__, self.message or '')