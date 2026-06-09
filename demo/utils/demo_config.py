"""
Demo configuration management for Knish.IO Python SDK demonstrations.
"""

import os
import secrets
from typing import Optional


class DemoConfig:
    """Configuration management for demo scripts with environment variable support."""
    
    def __init__(self):
        self._load_config()
    
    def _load_config(self):
        """Load configuration from environment variables with sensible defaults."""
        # Node configuration
        self.node_uri = os.getenv('KNISHIO_NODE_URI', 'http://localhost:8000/graphql')
        self.cell_slug = os.getenv('KNISHIO_CELL', 'demo-cell')
        
        # Authentication
        self.secret = os.getenv('KNISHIO_SECRET')
        if not self.secret:
            self.secret = self._generate_demo_secret()
        
        # Demo settings
        self.verbose = os.getenv('DEMO_VERBOSE', 'false').lower() == 'true'
        self.demo_mode = os.getenv('DEMO_MODE', 'demo').lower()
        
        # Network settings
        self.timeout = int(os.getenv('DEMO_TIMEOUT', '30'))
        self.retry_attempts = int(os.getenv('DEMO_RETRY_ATTEMPTS', '3'))
        
    def _generate_demo_secret(self) -> str:
        """Generate a demo secret for testing purposes."""
        # Generate a 64-character hex string (256 bits)
        return secrets.token_hex(32)
    
    @property
    def is_production_mode(self) -> bool:
        """Check if running in production mode."""
        return self.demo_mode == 'production'
    
    @property
    def is_demo_mode(self) -> bool:
        """Check if running in demo mode."""
        return self.demo_mode == 'demo'
    
    def validate(self) -> None:
        """Validate configuration settings."""
        if not self.node_uri:
            raise ValueError("Node URI is required")
        
        if not self.secret:
            raise ValueError("Secret is required")
        
        if self.is_production_mode and os.getenv('KNISHIO_SECRET') is None:
            raise ValueError("Production mode requires KNISHIO_SECRET environment variable")
        
        if len(self.secret) < 32:
            raise ValueError("Secret should be at least 32 characters for security")
    
    def print_config(self) -> None:
        """Print current configuration (safe for logging)."""
        print("=== Demo Configuration ===")
        print(f"Node URI: {self.node_uri}")
        print(f"Cell Slug: {self.cell_slug}")
        print(f"Secret: {'*' * len(self.secret[:8]) + self.secret[:8]}..." if self.secret else "Not set")
        print(f"Mode: {self.demo_mode}")
        print(f"Verbose: {self.verbose}")
        print(f"Timeout: {self.timeout}s")
        print("========================")
    
    def get_client_kwargs(self) -> dict:
        """Get keyword arguments for KnishIOClient initialization."""
        kwargs = {
            'uri': self.node_uri,
            'timeout': self.timeout
        }
        return kwargs
    
    def get_auth_kwargs(self) -> dict:
        """Get keyword arguments for authentication."""
        kwargs = {
            'secret': self.secret,
            'cell_slug': self.cell_slug,
            'encrypt': False  # Set to True for production
        }
        return kwargs


# Global config instance
config = DemoConfig()


def get_demo_config() -> DemoConfig:
    """Get the global demo configuration instance."""
    return config


def validate_environment() -> None:
    """Validate the environment is properly configured for demos."""
    try:
        config.validate()
        if config.verbose:
            config.print_config()
    except ValueError as e:
        print(f"Configuration Error: {e}")
        print("\nPlease set the required environment variables:")
        print("  KNISHIO_NODE_URI - GraphQL endpoint")
        print("  KNISHIO_SECRET - Client secret (optional for demo)")
        print("  KNISHIO_CELL - Cell slug (optional)")
        raise


# Convenience functions for common patterns
def get_node_uri() -> str:
    """Get the configured node URI."""
    return config.node_uri


def get_cell_slug() -> str:
    """Get the configured cell slug."""
    return config.cell_slug


def get_secret() -> str:
    """Get the configured secret."""
    return config.secret


def is_verbose() -> bool:
    """Check if verbose mode is enabled."""
    return config.verbose