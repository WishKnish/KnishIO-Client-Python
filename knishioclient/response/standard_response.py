"""
Enhanced Response Framework for Python SDK

Implements JavaScript SDK compatible response interface patterns
with Python-specific enhancements (AsyncIO, type hints, dataclasses)
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Generic, TypeVar, Optional, Any, Callable, Dict, List, Union, Awaitable
import asyncio
import json
import logging
from datetime import datetime

# Type variable for generic response types
T = TypeVar('T')

@dataclass(frozen=True)
class ResponseError:
    """Enhanced error information with detailed context"""
    message: str
    code: Optional[str] = None
    details: List[str] = field(default_factory=list)
    context: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    operation: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'message': self.message,
            'code': self.code,
            'details': self.details,
            'context': self.context,
            'timestamp': self.timestamp,
            'operation': self.operation
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResponseError:
        """Create from dictionary"""
        return cls(
            message=data.get('message', 'Unknown error'),
            code=data.get('code'),
            details=data.get('details', []),
            context=data.get('context'),
            timestamp=data.get('timestamp', datetime.now().isoformat()),
            operation=data.get('operation')
        )

@dataclass(frozen=True)
class ValidationResult(Generic[T]):
    """Enhanced validation result matching TypeScript patterns"""
    success: bool
    data: Optional[T] = None
    error: Optional[ResponseError] = None
    warnings: List[str] = field(default_factory=list)
    
    @classmethod
    def create_success(cls, data: T, warnings: List[str] = None) -> ValidationResult[T]:
        """Create successful validation result"""
        return cls(success=True, data=data, warnings=warnings or [])
    
    @classmethod
    def create_failure(cls, error_message: str, data: Optional[T] = None) -> ValidationResult[T]:
        """Create failed validation result"""
        return cls(
            success=False,
            data=data,
            error=ResponseError(message=error_message)
        )

class UniversalResponse(ABC, Generic[T]):
    """Universal response interface matching JavaScript SDK pattern"""
    
    @abstractmethod
    def success(self) -> bool:
        """Check if operation was successful"""
        pass
    
    @abstractmethod
    def payload(self) -> Optional[T]:
        """Get response payload data"""
        pass
    
    @abstractmethod
    def reason(self) -> Optional[str]:
        """Get error reason/message"""
        pass
    
    @abstractmethod
    def data(self) -> Any:
        """Get raw response data"""
        pass

class EnhancedResponse(UniversalResponse[T], ABC):
    """Enhanced response interface with functional programming support"""
    
    @abstractmethod
    def to_validation_result(self) -> ValidationResult[T]:
        """Convert to ValidationResult for enhanced error handling"""
        pass
    
    @abstractmethod
    def map(self, mapper: Callable[[T], Any]) -> EnhancedResponse[Any]:
        """Functional programming map operation"""
        pass
    
    @abstractmethod
    def filter(self, predicate: Callable[[T], bool]) -> EnhancedResponse[T]:
        """Functional programming filter operation"""
        pass
    
    @abstractmethod
    async def on_success(self, callback: Callable[[T], Awaitable[None]]) -> EnhancedResponse[T]:
        """Async callback for successful responses"""
        pass
    
    @abstractmethod
    async def on_failure(self, callback: Callable[[str], Awaitable[None]]) -> EnhancedResponse[T]:
        """Async callback for failed responses"""
        pass
    
    @abstractmethod
    def debug(self, label: Optional[str] = None) -> EnhancedResponse[T]:
        """Enhanced debugging with optional labels"""
        pass

@dataclass(frozen=True)
class StandardResponse(EnhancedResponse[T]):
    """Standard response implementation with comprehensive Python features"""
    _successful: bool
    _payload_data: Optional[T] = None
    _error_message: Optional[str] = None
    _raw_data: Any = None
    _operation: str = 'unknown'
    _duration: Optional[float] = None
    
    def success(self) -> bool:
        return self._successful
    
    def payload(self) -> Optional[T]:
        return self._payload_data
    
    def reason(self) -> Optional[str]:
        return self._error_message
    
    def data(self) -> Any:
        return self._raw_data
    
    def to_validation_result(self) -> ValidationResult[T]:
        if self._successful and self._payload_data is not None:
            return ValidationResult.create_success(self._payload_data)
        else:
            return ValidationResult.create_failure(
                self._error_message or 'Unknown error',
                self._payload_data
            )
    
    def map(self, mapper: Callable[[T], Any]) -> StandardResponse[Any]:
        if self._successful and self._payload_data is not None:
            try:
                mapped_payload = mapper(self._payload_data)
                return StandardResponse(
                    _successful=True,
                    _payload_data=mapped_payload,
                    _raw_data=self._raw_data,
                    _operation=f"{self._operation}_mapped"
                )
            except Exception as e:
                return StandardResponse(
                    _successful=False,
                    _error_message=f"Mapping failed: {str(e)}",
                    _raw_data=self._raw_data,
                    _operation=f"{self._operation}_map_failed"
                )
        else:
            return StandardResponse(
                _successful=False,
                _error_message=self._error_message,
                _raw_data=self._raw_data,
                _operation=self._operation
            )
    
    def filter(self, predicate: Callable[[T], bool]) -> StandardResponse[T]:
        if self._successful and self._payload_data is not None:
            try:
                if predicate(self._payload_data):
                    return self
                else:
                    return StandardResponse(
                        _successful=False,
                        _error_message="Filter predicate failed",
                        _raw_data=self._raw_data,
                        _operation=f"{self._operation}_filter_failed"
                    )
            except Exception as e:
                return StandardResponse(
                    _successful=False,
                    _error_message=f"Filter failed: {str(e)}",
                    _raw_data=self._raw_data,
                    _operation=f"{self._operation}_filter_error"
                )
        else:
            return self
    
    async def on_success(self, callback: Callable[[T], Awaitable[None]]) -> StandardResponse[T]:
        if self._successful and self._payload_data is not None:
            try:
                await callback(self._payload_data)
            except Exception as e:
                logging.warning(f"StandardResponse.on_success callback failed: {e}")
        return self
    
    async def on_failure(self, callback: Callable[[str], Awaitable[None]]) -> StandardResponse[T]:
        if not self._successful:
            try:
                await callback(self._error_message or 'Unknown error')
            except Exception as e:
                logging.warning(f"StandardResponse.on_failure callback failed: {e}")
        return self
    
    def debug(self, label: Optional[str] = None) -> StandardResponse[T]:
        debug_prefix = label or self.__class__.__name__
        
        if self._successful:
            logging.debug(f"[{debug_prefix}] Success: payload={self._payload_data}, operation={self._operation}")
        else:
            logging.debug(f"[{debug_prefix}] Failure: error={self._error_message}, operation={self._operation}")
        
        return self
    
    # Python-specific enhancements
    
    def __bool__(self) -> bool:
        """Pythonic truth testing"""
        return self.success()
    
    def or_raise(self, exception_class: type = Exception) -> T:
        """Raise exception if not successful, return payload if successful"""
        if not self.success():
            raise exception_class(self.reason() or "Operation failed")
        if self._payload_data is None:
            raise ValueError("Successful response has no payload")
        return self._payload_data
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'success': self._successful,
            'payload': self._payload_data,
            'reason': self._error_message,
            'data': self._raw_data,
            'operation': self._operation,
            'duration': self._duration,
            'timestamp': datetime.now().isoformat()
        }
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def success(
        cls,
        payload: T,
        operation: str = 'unknown',
        raw_data: Any = None,
        duration: Optional[float] = None
    ) -> StandardResponse[T]:
        """Factory method for successful response"""
        return cls(
            _successful=True,
            _payload_data=payload,
            _raw_data=raw_data,
            _operation=operation,
            _duration=duration
        )
    
    @classmethod
    def failure(
        cls,
        error_message: str,
        operation: str = 'unknown',
        raw_data: Any = None,
        duration: Optional[float] = None
    ) -> StandardResponse[T]:
        """Factory method for error response"""
        return cls(
            _successful=False,
            _error_message=error_message,
            _raw_data=raw_data,
            _operation=operation,
            _duration=duration
        )
    
    @classmethod
    def from_legacy_response(
        cls,
        legacy_response: Any,
        operation: str = 'legacy_conversion'
    ) -> StandardResponse[T]:
        """Convert from legacy Python response format"""
        try:
            is_successful = (
                hasattr(legacy_response, 'success') and legacy_response.success()
            ) if hasattr(legacy_response, 'success') else False
            
            if is_successful:
                payload = getattr(legacy_response, 'payload', lambda: None)()
                raw_data = getattr(legacy_response, 'data', lambda: legacy_response)()
                return cls.success(payload, operation, raw_data)
            else:
                error_msg = (
                    getattr(legacy_response, 'reason', lambda: None)() or
                    getattr(legacy_response, 'error', lambda: None)() or
                    'Unknown error'
                )
                raw_data = getattr(legacy_response, 'data', lambda: legacy_response)()
                return cls.failure(error_msg, operation, raw_data)
        except Exception as e:
            return cls.failure(f"Legacy response conversion failed: {str(e)}", operation, legacy_response)

# Type aliases for specific response types  
MetaResponse = StandardResponse[Dict[str, Any]]
TokenResponse = StandardResponse[Dict[str, Any]]
TransferResponse = StandardResponse[Dict[str, Any]]
BalanceResponse = StandardResponse[Dict[str, Any]]
WalletResponse = StandardResponse[Dict[str, Any]]
AuthResponse = StandardResponse[Dict[str, Any]]

class ResponseFactory:
    """Factory for creating standardized responses"""
    
    @staticmethod
    def create_success_response(
        payload: Any,
        operation: str,
        raw_data: Any = None,
        duration: Optional[float] = None
    ) -> StandardResponse[Any]:
        return StandardResponse.success(payload, operation, raw_data, duration)
    
    @staticmethod
    def create_error_response(
        error_message: str,
        operation: str,
        raw_data: Any = None,
        duration: Optional[float] = None
    ) -> StandardResponse[Any]:
        return StandardResponse.failure(error_message, operation, raw_data, duration)

class ResponseUtils:
    """Response utilities for enhanced operations"""
    
    @staticmethod
    async def combine_responses(responses: List[StandardResponse[T]]) -> StandardResponse[List[T]]:
        """Combine multiple responses into a single response"""
        successful = all(response.success() for response in responses)
        
        if successful:
            payloads = [response.payload() for response in responses if response.payload() is not None]
            return StandardResponse.success(payloads, 'combine_responses', responses)
        else:
            errors = [
                response.reason() for response in responses 
                if not response.success() and response.reason()
            ]
            return StandardResponse.failure(
                f"Combined operation failed: {'; '.join(errors)}",
                'combine_responses',
                responses
            )
    
    @staticmethod
    async def sequence_responses(
        operations: List[Callable[[], Awaitable[StandardResponse[T]]]]
    ) -> StandardResponse[List[T]]:
        """Execute operations in sequence, stopping on first failure"""
        results: List[StandardResponse[T]] = []
        
        for i, operation in enumerate(operations):
            try:
                result = await operation()
                results.append(result)
                
                if not result.success():
                    return StandardResponse.failure(
                        f"Sequence failed at operation {i + 1}: {result.reason()}",
                        'sequence_responses',
                        results
                    )
            except Exception as e:
                return StandardResponse.failure(
                    f"Sequence failed with exception: {str(e)}",
                    'sequence_responses',
                    results
                )
        
        payloads = [result.payload() for result in results if result.payload() is not None]
        return StandardResponse.success(payloads, 'sequence_responses')
    
    @staticmethod
    def from_validation_result(
        validation_result: ValidationResult[T],
        operation: str
    ) -> StandardResponse[T]:
        """Convert ValidationResult to StandardResponse"""
        if validation_result.success and validation_result.data is not None:
            return StandardResponse.success(validation_result.data, operation)
        else:
            error_msg = validation_result.error.message if validation_result.error else 'Validation failed'
            return StandardResponse.failure(error_msg, operation, validation_result.error)