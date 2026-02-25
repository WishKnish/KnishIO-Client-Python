"""
Enhanced Configuration System for Python SDK

Implements JavaScript/TypeScript reference patterns using Python dataclasses
with comprehensive type hints, validation, and AsyncIO compatibility.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlparse
import json
import re

@dataclass(frozen=True)
class SocketConfig:
    """Socket configuration for real-time features"""
    socket_uri: Optional[str] = None
    app_key: Optional[str] = None
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> SocketConfig:
        """Create from JavaScript-style dictionary with camelCase conversion"""
        return cls(
            socket_uri=config_dict.get("socketUri") or config_dict.get("socket_uri"),
            app_key=config_dict.get("appKey") or config_dict.get("app_key")
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "socketUri": self.socket_uri,
            "appKey": self.app_key
        }

@dataclass(frozen=True)  
class ClientConfig:
    """Core client configuration (mirrors JavaScript object pattern)"""
    uri: str
    cell_slug: Optional[str] = None
    client: Optional[Any] = None
    socket: Optional[SocketConfig] = None
    server_sdk_version: int = 3
    logging: bool = False
    
    def validate(self) -> ValidationResult[ClientConfig]:
        """Validate configuration with enhanced error messages"""
        errors = []
        
        if not self.uri:
            errors.append("URI cannot be empty")
        else:
            # Validate URI format
            try:
                parsed = urlparse(self.uri)
                if not parsed.scheme or not parsed.netloc:
                    errors.append("Invalid URI format - must include scheme and netloc")
            except Exception as e:
                errors.append(f"Invalid URI format: {str(e)}")
        
        if self.server_sdk_version < 1:
            errors.append("Server SDK version must be positive")
        
        if errors:
            return ValidationResult.create_failure(f"ClientConfig validation failed: {'; '.join(errors)}")
        else:
            return ValidationResult.create_success(self)
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> ClientConfig:
        """Create from JavaScript-style dictionary with camelCase conversion"""
        return cls(
            uri=config_dict["uri"],
            cell_slug=config_dict.get("cellSlug") or config_dict.get("cell_slug"),
            client=config_dict.get("client"),
            socket=SocketConfig.from_dict(config_dict["socket"]) if "socket" in config_dict else None,
            server_sdk_version=config_dict.get("serverSdkVersion") or config_dict.get("server_sdk_version", 3),
            logging=config_dict.get("logging", False)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "uri": self.uri,
            "cellSlug": self.cell_slug,
            "client": self.client,
            "socket": self.socket.to_dict() if self.socket else None,
            "serverSdkVersion": self.server_sdk_version,
            "logging": self.logging
        }
    
    def with_cell_slug(self, cell_slug: str) -> ClientConfig:
        """Builder pattern method for fluent configuration"""
        return self.__class__(
            self.uri, cell_slug, self.client, self.socket, self.server_sdk_version, self.logging
        )
    
    def with_logging(self, logging: bool) -> ClientConfig:
        """Builder pattern method for fluent configuration"""
        return self.__class__(
            self.uri, self.cell_slug, self.client, self.socket, self.server_sdk_version, logging
        )

@dataclass(frozen=True)
class AuthTokenConfig:
    """Authentication configuration"""
    secret: Optional[str] = None
    seed: Optional[str] = None
    cell_slug: Optional[str] = None
    encrypt: bool = False
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> AuthTokenConfig:
        """Create from JavaScript-style dictionary"""
        return cls(
            secret=config_dict.get("secret"),
            seed=config_dict.get("seed"),
            cell_slug=config_dict.get("cellSlug") or config_dict.get("cell_slug"),
            encrypt=config_dict.get("encrypt", False)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret": self.secret,
            "seed": self.seed,
            "cellSlug": self.cell_slug,
            "encrypt": self.encrypt
        }

@dataclass(frozen=True)
class MetaConfig:
    """Metadata operation configuration"""
    meta_type: str
    meta_id: str
    meta: Dict[str, str]
    policy: Optional[Dict[str, Any]] = None
    
    def validate(self) -> ValidationResult[MetaConfig]:
        """Validate configuration with business logic checks"""
        errors = []
        warnings = []
        
        if not self.meta_type:
            errors.append("meta_type cannot be empty")
        
        if not self.meta_id:
            errors.append("meta_id cannot be empty")
        
        if not self.meta:
            warnings.append("Empty metadata - consider adding descriptive metadata")
        
        # Business logic validation
        if len(self.meta_type) > 50:
            warnings.append("meta_type is quite long - consider shorter identifiers for better performance")
        
        if errors:
            return ValidationResult.create_failure(f"MetaConfig validation failed: {'; '.join(errors)}")
        else:
            result = ValidationResult.create_success(self)
            return ValidationResult(
                success=True,
                data=self,
                warnings=warnings
            )
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> MetaConfig:
        """Create from JavaScript-style dictionary with camelCase conversion"""
        meta_data = config_dict.get("meta", {})
        
        # Handle both JavaScript object format and Python structured format
        if isinstance(meta_data, dict) and all(isinstance(v, str) for v in meta_data.values()):
            # JavaScript object format: { "key1": "value1", "key2": "value2" }
            normalized_meta = meta_data
        elif isinstance(meta_data, list):
            # Structured format: [{"key": "key1", "value": "value1"}]
            normalized_meta = {item["key"]: item["value"] for item in meta_data}
        else:
            normalized_meta = {}
        
        return cls(
            meta_type=config_dict["metaType"],
            meta_id=config_dict["metaId"],
            meta=normalized_meta,
            policy=config_dict.get("policy")
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "metaType": self.meta_type,
            "metaId": self.meta_id,
            "meta": self.meta,
            "policy": self.policy
        }

@dataclass(frozen=True)
class TokenConfig:
    """Token creation configuration"""
    token: str
    amount: Optional[int] = None
    meta: Optional[Dict[str, str]] = None
    batch_id: Optional[str] = None
    units: List[str] = field(default_factory=list)
    
    def validate(self) -> ValidationResult[TokenConfig]:
        """Validate token configuration"""
        errors = []
        
        if not self.token:
            errors.append("token cannot be empty")
        
        if self.amount is not None and self.amount < 0:
            errors.append("token amount cannot be negative")
        
        if errors:
            return ValidationResult.create_failure(f"TokenConfig validation failed: {'; '.join(errors)}")
        else:
            return ValidationResult.create_success(self)
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> TokenConfig:
        return cls(
            token=config_dict["token"],
            amount=config_dict.get("amount"),
            meta=config_dict.get("meta", {}),
            batch_id=config_dict.get("batchId"),
            units=config_dict.get("units", [])
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "amount": self.amount,
            "meta": self.meta,
            "batchId": self.batch_id,
            "units": self.units
        }

@dataclass(frozen=True)
class TransferConfig:
    """Transfer configuration"""
    bundle_hash: str
    token: str
    amount: int
    units: List[str] = field(default_factory=list)
    batch_id: Optional[str] = None
    source_wallet: Optional[Any] = None
    
    def validate(self) -> ValidationResult[TransferConfig]:
        """Validate transfer configuration"""
        errors = []
        
        if not self.bundle_hash:
            errors.append("bundle_hash cannot be empty")
        
        if not self.token:
            errors.append("token cannot be empty")
        
        if self.amount <= 0 and not self.units:
            errors.append("either positive amount or units must be provided")
        
        if errors:
            return ValidationResult.create_failure(f"TransferConfig validation failed: {'; '.join(errors)}")
        else:
            return ValidationResult.create_success(self)
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> TransferConfig:
        return cls(
            bundle_hash=config_dict["bundleHash"],
            token=config_dict["token"],
            amount=config_dict["amount"],
            units=config_dict.get("units", []),
            batch_id=config_dict.get("batchId"),
            source_wallet=config_dict.get("sourceWallet")
        )

@dataclass(frozen=True)
class QueryBalanceConfig:
    """Balance query configuration"""
    token: str
    bundle: Optional[str] = None
    type: str = "regular"
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> QueryBalanceConfig:
        return cls(
            token=config_dict["token"],
            bundle=config_dict.get("bundle"),
            type=config_dict.get("type", "regular")
        )

@dataclass(frozen=True)
class WalletConfig:
    """Wallet creation configuration"""
    token: str
    
    def validate(self) -> ValidationResult[WalletConfig]:
        if not self.token:
            return ValidationResult.create_failure("token cannot be empty")
        else:
            return ValidationResult.create_success(self)
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> WalletConfig:
        return cls(token=config_dict["token"])

@dataclass(frozen=True)
class QueryMetaConfig:
    """Metadata query configuration"""
    meta_type: str
    meta_id: Optional[str] = None
    key: Optional[str] = None
    value: Optional[str] = None
    latest: bool = True
    filter: Optional[Dict[str, Any]] = None
    query_args: Optional[Dict[str, Any]] = None
    count: Optional[str] = None
    count_by: Optional[str] = None
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> QueryMetaConfig:
        return cls(
            meta_type=config_dict["metaType"],
            meta_id=config_dict.get("metaId"),
            key=config_dict.get("key"),
            value=config_dict.get("value"),
            latest=config_dict.get("latest", True),
            filter=config_dict.get("filter"),
            query_args=config_dict.get("queryArgs"),
            count=config_dict.get("count"),
            count_by=config_dict.get("countBy")
        )

class ConfigFactory:
    """Factory for creating standardized configurations"""
    
    @staticmethod
    def create_client_config(
        uri: str,
        cell_slug: Optional[str] = None,
        logging: bool = False,
        server_sdk_version: int = 3
    ) -> ClientConfig:
        return ClientConfig(uri, cell_slug, None, None, server_sdk_version, logging)
    
    @staticmethod
    def create_meta_config(
        meta_type: str,
        meta_id: str,
        meta: Dict[str, str],
        policy: Optional[Dict[str, Any]] = None
    ) -> MetaConfig:
        return MetaConfig(meta_type, meta_id, meta, policy)
    
    @staticmethod
    def create_token_config(
        token: str,
        amount: Optional[int] = None,
        meta: Optional[Dict[str, str]] = None
    ) -> TokenConfig:
        return TokenConfig(token, amount, meta)

class ConfigUtils:
    """Configuration utilities for validation and conversion"""
    
    @staticmethod
    def normalize_camel_case(config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Convert JavaScript camelCase keys to Python snake_case"""
        camel_to_snake_mapping = {
            "cellSlug": "cell_slug",
            "metaType": "meta_type",
            "metaId": "meta_id",
            "bundleHash": "bundle_hash", 
            "batchId": "batch_id",
            "sourceWallet": "source_wallet",
            "serverSdkVersion": "server_sdk_version",
            "queryArgs": "query_args",
            "countBy": "count_by"
        }
        
        normalized = config_dict.copy()
        
        for camel_case, snake_case in camel_to_snake_mapping.items():
            if camel_case in config_dict and snake_case not in config_dict:
                normalized[snake_case] = config_dict[camel_case]
                # Keep original for backward compatibility
        
        return normalized
    
    @staticmethod
    def validate_config(config_dict: Dict[str, Any], config_type: str) -> ValidationResult[Dict[str, Any]]:
        """Validate any configuration dictionary"""
        try:
            normalized = ConfigUtils.normalize_camel_case(config_dict)
            
            if config_type == "client":
                config_obj = ClientConfig.from_dict(normalized)
                return config_obj.validate()
            elif config_type == "meta":
                config_obj = MetaConfig.from_dict(normalized)
                return config_obj.validate()
            elif config_type == "token":
                config_obj = TokenConfig.from_dict(normalized)
                return config_obj.validate()
            elif config_type == "transfer":
                config_obj = TransferConfig.from_dict(normalized)
                return config_obj.validate()
            elif config_type == "wallet":
                config_obj = WalletConfig.from_dict(normalized)
                return config_obj.validate()
            else:
                return ValidationResult.create_failure(f"Unknown config type: {config_type}")
                
        except Exception as e:
            return ValidationResult.create_failure(f"Configuration validation failed: {str(e)}")
    
    @staticmethod
    def config_to_json(config: Union[ClientConfig, MetaConfig, TokenConfig, TransferConfig, WalletConfig]) -> str:
        """Convert configuration to JSON for cross-platform compatibility"""
        return json.dumps(config.to_dict())
    
    @staticmethod
    def config_from_json(json_str: str, config_type: str) -> Union[ClientConfig, MetaConfig, TokenConfig, TransferConfig, WalletConfig]:
        """Create configuration from JSON (JavaScript compatibility)"""
        data = json.loads(json_str)
        
        if config_type == "client":
            return ClientConfig.from_dict(data)
        elif config_type == "meta":
            return MetaConfig.from_dict(data)
        elif config_type == "token":
            return TokenConfig.from_dict(data)
        elif config_type == "transfer":
            return TransferConfig.from_dict(data)
        elif config_type == "wallet":
            return WalletConfig.from_dict(data)
        else:
            raise ValueError(f"Unknown config type: {config_type}")

class ConfigValidator:
    """Enhanced configuration validation with detailed error reporting"""
    
    @staticmethod
    def validate_client_config(config_dict: Dict[str, Any]) -> ValidationResult[Dict[str, Any]]:
        """Validate client configuration with detailed error reporting"""
        errors = []
        warnings = []
        
        # Required field validation
        if not config_dict.get("uri"):
            errors.append("URI is required and cannot be empty")
        
        # Optional field validation with warnings
        server_version = config_dict.get("serverSdkVersion") or config_dict.get("server_sdk_version", 3)
        if server_version < 3:
            warnings.append("Server SDK version below 3 may not support all features")
        
        if config_dict.get("logging") and not config_dict.get("cellSlug") and not config_dict.get("cell_slug"):
            warnings.append("Logging enabled without cellSlug may reduce debugging effectiveness")
        
        if errors:
            return ValidationResult(
                success=False,
                error=ResponseError(message=f"ClientConfig validation failed: {'; '.join(errors)}"),
                warnings=warnings
            )
        else:
            try:
                config_obj = ClientConfig.from_dict(config_dict)
                return ValidationResult(
                    success=True,
                    data=config_obj.to_dict(),
                    warnings=warnings
                )
            except Exception as e:
                return ValidationResult.create_failure(f"Configuration creation failed: {str(e)}")
    
    @staticmethod
    def validate_meta_config(config_dict: Dict[str, Any]) -> ValidationResult[Dict[str, Any]]:
        """Validate metadata configuration with business logic checks"""
        errors = []
        warnings = []
        
        # Required field validation
        meta_type = config_dict.get("metaType")
        if not meta_type:
            errors.append("metaType is required and cannot be empty")
        
        meta_id = config_dict.get("metaId")
        if not meta_id:
            errors.append("metaId is required and cannot be empty")
        
        # Metadata validation
        meta = config_dict.get("meta")
        if meta is None:
            errors.append("meta must be provided")
        elif not meta:
            warnings.append("Empty metadata - consider adding descriptive metadata")
        
        # Business logic validation  
        if meta_type and len(meta_type) > 50:
            warnings.append("metaType is quite long - consider shorter identifiers")
        
        if errors:
            return ValidationResult(
                success=False,
                error=ResponseError(message=f"MetaConfig validation failed: {'; '.join(errors)}"),
                warnings=warnings
            )
        else:
            try:
                config_obj = MetaConfig.from_dict(config_dict)
                return ValidationResult(
                    success=True,
                    data=config_obj.to_dict(),
                    warnings=warnings
                )
            except Exception as e:
                return ValidationResult.create_failure(f"MetaConfig creation failed: {str(e)}")

# Import validation result from response module
from ..response.standard_response import ValidationResult, ResponseError