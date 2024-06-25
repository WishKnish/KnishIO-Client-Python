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
    'MetaMissingException',
    'NegativeMeaningException',
    'WrongTokenTypeException',
    'UnauthenticatedException',
    'CodeException',
    'WalletShadowException',
    'DecryptException',
    'BaseError'
)


class BaseError(Exception):
    """
    Class BaseError
    """
    _message: str
    _code: int

    def __int__(self, message: str = None, code: int = 1, *args) -> None:
        self._message = message
        self._code = code
        super(Exception, self).__init__(self._message, self._code, *args)

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


class AtomIndexException(BaseError):
    """
    Class AtomIndexException
    """
    def __int__(self, message: str = 'There is an atom without an index', code: int = 1, *args) -> None:
        super(AtomIndexException, self).__int__(message, code, *args)


class AtomsMissingException(BaseError):
    """
    Class AtomsMissingException
    """
    def __int__(self, message: str = 'The molecule does not contain atoms', code: int = 1, *args) -> None:
        super(AtomsMissingException, self).__int__(message, code, *args)


class BalanceInsufficientException(BaseError):
    """
    Class BalanceInsufficientException
    """
    def __int__(self, message: str = 'Insufficient balance for requested transfer', code: int = 1, *args) -> None:
        super(BalanceInsufficientException, self).__int__(message, code, *args)


class InvalidResponseException(BaseError):
    """
    Class InvalidResponseException
    """
    def __int__(self, message: str = 'GraphQL did not provide a valid response.', code: int = 2, *args) -> None:
        super(InvalidResponseException, self).__int__(message, code, *args)


class MolecularHashMismatchException(BaseError):
    """
    Class MolecularHashMismatchException
    """
    def __int__(self, message: str = 'The molecular hash does not match', code: int = 1, *args) -> None:
        super(MolecularHashMismatchException, self).__int__(message, code, *args)


class MolecularHashMissingException(BaseError):
    """
    Class MolecularHashMissingException
    """
    def __int__(self, message: str = 'The molecular hash is missing', code: int = 1, *args) -> None:
        super(MolecularHashMissingException, self).__int__(message, code, *args)


class SignatureMalformedException(BaseError):
    """
    Class SignatureMalformedException
    """
    def __int__(self, message: str = 'OTS malformed', code: int = 1, *args) -> None:
        super(SignatureMalformedException, self).__int__(message, code, *args)


class SignatureMismatchException(BaseError):
    """
    Class SignatureMismatchException
    """
    def __int__(self, message: str = 'OTS mismatch', code: int = 1, *args) -> None:
        super(SignatureMismatchException, self).__int__(message, code, *args)


class TransferBalanceException(BaseError):
    """
    Class TransferBalanceException
    """
    def __int__(self, message: str = 'Insufficient balance to make transfer', code: int = 1, *args) -> None:
        super(TransferBalanceException, self).__int__(message, code, *args)


class TransferMalformedException(BaseError):
    """
    Class TransferMalformedException
    """
    def __int__(self, message: str = 'Token transfer atoms are malformed', code: int = 1, *args) -> None:
        super(TransferMalformedException, self).__int__(message, code, *args)


class TransferMismatchedException(BaseError):
    """
    Class TransferMismatchedException
    """
    def __int__(self, message: str = 'Token transfer slugs are mismached', code: int = 1, *args) -> None:
        super(TransferMismatchedException, self).__int__(message, code, *args)


class TransferRemainderException(BaseError):
    """
    Class TransferRemainderException
    """
    def __int__(self, message: str = 'Invalid remainder provided', code: int = 1, *args) -> None:
        super(TransferRemainderException, self).__int__(message, code, *args)


class TransferToSelfException(BaseError):
    """
    Class TransferToSelfException
    """
    def __int__(self, message: str = 'Sender and recipient(s) cannot be the same', code: int = 1, *args) -> None:
        super(TransferToSelfException, self).__int__(message, code, *args)


class TransferUnbalancedException(BaseError):
    """
    Class TransferUnbalancedException
    """
    def __int__(self, message: str = 'Token transfer atoms are unbalanced', code: int = 1, *args) -> None:
        super(TransferUnbalancedException, self).__int__(message, code, *args)


class MetaMissingException(BaseError):
    """
    Class MetaMissingException
    """
    def __int__(self, message: str = 'Empty meta data.', code: int = 1, *args) -> None:
        super(MetaMissingException, self).__int__(message, code, *args)


class NegativeMeaningException(BaseError):
    """
    Class NegativeMeaningException
    """
    def __int__(self, message: str = 'Negative meaning.', code: int = 1, *args) -> None:
        super(NegativeMeaningException, self).__int__(message, code, *args)


class WrongTokenTypeException(BaseError):
    """
    Class WrongTokenTypeException
    """
    def __int__(self, message: str = 'Wrong type of token for this isotope', code: int = 1, *args) -> None:
        super(WrongTokenTypeException, self).__int__(message, code, *args)


class UnauthenticatedException(BaseError):
    """
    Class UnauthenticatedException
    """
    def __int__(self, message: str = 'Unauthenticated.', code: int = 1, *args) -> None:
        super(UnauthenticatedException, self).__int__(message, code, *args)


class CodeException(BaseError):
    """
    Class CodeException
    """
    def __int__(self, message: str = 'Code exception', code: int = 1, *args) -> None:
        super(CodeException, self).__int__(message, code, *args)


class WalletShadowException(BaseError):
    """
    Class WalletShadowException
    """
    def __int__(self, message: str = 'The shadow wallet does not exist', code: int = 1, *args) -> None:
        super(WalletShadowException, self).__int__(message, code, *args)


class DecryptException(BaseError):
    """
    Class DecryptException
    """
    def __int__(self, message: str = 'Error during decryption.', code: int = 1, *args) -> None:
        super(DecryptException, self).__int__(message, code, *args)
