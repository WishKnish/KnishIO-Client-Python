"""
Helper utilities for Knish.IO Python SDK demonstrations.
"""

import json
import time
import uuid
from datetime import datetime
from typing import Any, Dict, Optional, List
from .demo_config import is_verbose


class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


class DemoHelpers:
    """Helper utilities for demo scripts."""
    
    @staticmethod
    def generate_uuid() -> str:
        """Generate a UUID for demo purposes."""
        return str(uuid.uuid4())
    
    @staticmethod
    def generate_timestamp() -> str:
        """Generate an ISO timestamp."""
        return datetime.now().isoformat()
    
    @staticmethod
    def generate_test_token_slug(prefix: str = "DEMO") -> str:
        """Generate a unique token slug for testing."""
        timestamp = str(int(time.time()))[-6:]  # Last 6 digits
        return f"{prefix}{timestamp}"
    
    @staticmethod
    def generate_test_meta_id(prefix: str = "test") -> str:
        """Generate a unique metadata ID for testing."""
        timestamp = str(int(time.time() * 1000))
        return f"{prefix}-{timestamp}"
    
    @staticmethod
    def safe_json_dump(data: Any, indent: int = 2) -> str:
        """Safely convert data to JSON string."""
        try:
            if hasattr(data, '__dict__'):
                # Convert objects to dict representation
                data = {k: v for k, v in data.__dict__.items() if not k.startswith('_')}
            return json.dumps(data, indent=indent, default=str)
        except (TypeError, ValueError):
            return str(data)
    
    @staticmethod
    def truncate_string(s: str, max_length: int = 50) -> str:
        """Truncate string with ellipsis if too long."""
        if len(s) <= max_length:
            return s
        return s[:max_length-3] + "..."
    
    @staticmethod
    def format_balance(amount: float, token: str) -> str:
        """Format balance for display."""
        return f"{amount:,.2f} {token}"
    
    @staticmethod
    def parse_response_data(response: Any) -> Dict[str, Any]:
        """Parse response object into displayable data."""
        if hasattr(response, 'data'):
            data = response.data()
        elif hasattr(response, '__dict__'):
            data = response.__dict__
        else:
            data = response
        
        if isinstance(data, dict):
            return data
        elif hasattr(data, '__dict__'):
            return data.__dict__
        else:
            return {'response': str(data)}


def print_section(title: str) -> None:
    """Print a section header."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}{title}{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}{'='*60}{Colors.END}")


def print_success(message: str) -> None:
    """Print a success message."""
    print(f"{Colors.GREEN}✓ {message}{Colors.END}")


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"{Colors.RED}✗ {message}{Colors.END}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    print(f"{Colors.YELLOW}⚠ {message}{Colors.END}")


def print_info(message: str) -> None:
    """Print an info message."""
    print(f"{Colors.BLUE}ℹ {message}{Colors.END}")


def print_response(response: Any, title: str = "Response") -> None:
    """Print response data in a formatted way."""
    if not is_verbose():
        # Simple output for non-verbose mode
        if hasattr(response, 'success'):
            if response.success():
                print_success(f"{title}: Success")
            else:
                reason = response.reason() if hasattr(response, 'reason') else 'Unknown error'
                print_error(f"{title}: {reason}")
        else:
            print_info(f"{title}: {DemoHelpers.truncate_string(str(response))}")
        return
    
    print(f"\n{Colors.BOLD}{title}:{Colors.END}")
    
    try:
        # Check if response has success/failure pattern
        if hasattr(response, 'success'):
            if response.success():
                print_success("Operation successful")
                
                # Try to get and display data
                if hasattr(response, 'data'):
                    data = response.data()
                    if data:
                        print(f"Data: {DemoHelpers.safe_json_dump(data, indent=2)}")
                
                # Try to get payload
                if hasattr(response, 'payload'):
                    payload = response.payload()
                    if payload:
                        print(f"Payload: {DemoHelpers.safe_json_dump(payload, indent=2)}")
                        
            else:
                reason = response.reason() if hasattr(response, 'reason') else 'Unknown error'
                print_error(f"Operation failed: {reason}")
        else:
            # Generic response handling
            response_data = DemoHelpers.parse_response_data(response)
            print(DemoHelpers.safe_json_dump(response_data, indent=2))
            
    except Exception as e:
        print_error(f"Error displaying response: {e}")
        print(f"Raw response: {str(response)}")


def handle_demo_error(operation: str, error: Exception) -> None:
    """Handle and display demo errors consistently."""
    print_error(f"{operation} failed: {str(error)}")
    if is_verbose():
        import traceback
        print(f"{Colors.RED}Traceback:{Colors.END}")
        traceback.print_exc()


def wait_for_input(message: str = "Press Enter to continue...") -> None:
    """Wait for user input in interactive demos."""
    try:
        input(f"\n{Colors.YELLOW}{message}{Colors.END}")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Demo interrupted by user{Colors.END}")
        exit(0)


def create_demo_metadata(demo_name: str, additional_data: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
    """Create standard demo metadata."""
    metadata = [
        {'key': 'demo_name', 'value': demo_name},
        {'key': 'created_at', 'value': DemoHelpers.generate_timestamp()},
        {'key': 'sdk', 'value': 'Python'},
        {'key': 'demo_id', 'value': DemoHelpers.generate_uuid()}
    ]
    
    if additional_data:
        for key, value in additional_data.items():
            metadata.append({'key': key, 'value': str(value)})
    
    return metadata


def print_demo_header(demo_name: str, description: str) -> None:
    """Print a standardized demo header."""
    print(f"{Colors.BOLD}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}🐍 Knish.IO Python SDK Demo: {demo_name}{Colors.END}")
    print(f"{Colors.BOLD}{'='*70}{Colors.END}")
    print(f"{description}")
    print()


def print_demo_footer() -> None:
    """Print a standardized demo footer."""
    print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
    print(f"{Colors.GREEN}✓ Demo completed successfully!{Colors.END}")
    print(f"{Colors.BOLD}{'='*70}{Colors.END}")


class DemoStep:
    """Context manager for demo steps with consistent output."""
    
    def __init__(self, step_name: str, description: str = ""):
        self.step_name = step_name
        self.description = description
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        print(f"\n{Colors.BOLD}Step: {self.step_name}{Colors.END}")
        if self.description:
            print(f"      {self.description}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.time() - self.start_time
        if exc_type is None:
            print_success(f"{self.step_name} completed ({elapsed:.2f}s)")
        else:
            print_error(f"{self.step_name} failed ({elapsed:.2f}s): {exc_val}")
        return False  # Don't suppress exceptions