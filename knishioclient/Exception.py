# -*- coding: utf-8 -*-

__all__ = (
    'AtomIndexException',
    'AtomsMissingException',
    'BalanceInsufficientException',
    'InvalidResponseException',
    'MolecularHashMismatchException',
    'MolecularHashMissingException',
    'SignatureMalformedException',
    'SignatureMismatchException',
    'TransferBalanceException',
    'TransferMalformedException',
    'TransferMismatchedException',
    'TransferRemainderException',
    'TransferToSelfException',
    'TransferUnbalancedException',
)


class BaseError(Exception):
    """
    Class BaseError
    """
    _message: str = None
    _code: int = 1

    def __int__(self, message: str = None, code: int = 1, *args) -> None:

        if message is not None:
            self._message = message

        self._code = code

        super().__init__(message, code, *args)

    @property
    def message(self) -> str:
        return self._message

    @property
    def code(self) -> int:
        return self._code

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return "<%s: %s>" % (self.__class__.__name__, self.message)


class AtomIndexException(BaseError):
    """
    Class AtomIndexException
    """
    _message: str = 'There is an atom without an index'


class AtomsMissingException(BaseError):
    """
    Class AtomsMissingException
    """
    _message: str = 'The molecule does not contain atoms'


class BalanceInsufficientException(BaseError):
    """
    Class BalanceInsufficientException
    """
    _message: str = 'Insufficient balance for requested transfer'


class InvalidResponseException(BaseError):
    """
    Class InvalidResponseException
    """
    _message: str = 'GraphQL did not provide a valid response.'
    _code: int = 2


class MolecularHashMismatchException(BaseError):
    """
    Class MolecularHashMismatchException
    """
    _message: str = 'The molecular hash does not match'


class MolecularHashMissingException(BaseError):
    """
    Class MolecularHashMissingException
    """
    _message: str = 'The molecular hash is missing'


class SignatureMalformedException(BaseError):
    """
    Class SignatureMalformedException
    """
    _message: str = 'OTS malformed'


class SignatureMismatchException(BaseError):
    """
    Class SignatureMismatchException
    """
    _message: str = 'OTS mismatch'


class TransferBalanceException(BaseError):
    """
    Class TransferBalanceException
    """
    _message: str = 'Insufficient balance to make transfer'


class TransferMalformedException(BaseError):
    """
    Class TransferMalformedException
    """
    _message: str = 'Token transfer atoms are malformed'


class TransferMismatchedException(BaseError):
    """
    Class TransferMismatchedException
    """
    _message: str = 'Token transfer slugs are mismached'


class TransferRemainderException(BaseError):
    """
    Class TransferRemainderException
    """
    _message: str = 'Invalid remainder provided'


class TransferToSelfException(BaseError):
    """
    Class TransferToSelfException
    """
    _message: str = 'Sender and recipient(s) cannot be the same'


class TransferUnbalancedException(BaseError):
    """
    Class TransferUnbalancedException
    """
    _message: str = 'Token transfer atoms are unbalanced'
