#!/usr/bin/env python3
"""
Event Factory Demo - Knish.IO Python SDK

This demo demonstrates an event creation and management system using
factory patterns for structured event logging and tracking.

Perfect for: Applications requiring event logging and tracking.
"""

import sys
import os
import time
import platform
import uuid

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from knishioclient.client import KnishIOClient
from utils.demo_config import validate_environment, get_demo_config
from utils.demo_helpers import (
    print_demo_header, print_demo_footer, print_section, 
    print_success, print_error, print_response, handle_demo_error,
    DemoStep, DemoHelpers, Colors, create_demo_metadata
)


class PythonEventFactory:
    """
    Event factory for creating and managing events on the Knish.IO ledger.
    Inspired by the JavaScript SDK's event factory pattern.
    """
    
    def __init__(self, client: KnishIOClient, meta_type: str):
        """Initialize the event factory with an authenticated client."""
        if not hasattr(client, '_auth_token') or not client._auth_token:
            raise ValueError("Client must be authenticated before creating event factory")
        
        self.client = client
        self.meta_type = meta_type
        self.host_meta = self._collect_host_metadata()
    
    def _collect_host_metadata(self) -> dict:
        """Collect system metadata for events."""
        return {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'python_version': platform.python_version(),
            'architecture': platform.machine(),
            'hostname': platform.node(),
            'processor': platform.processor() or 'Unknown',
            'sdk': 'Python',
            'factory_version': '1.0.0'
        }
    
    def generate_uuid(self) -> str:
        """Generate a UUID for event identification."""
        return str(uuid.uuid4())
    
    def get_bundle(self) -> str:
        """Get the client's bundle hash."""
        return self.client.bundle()
    
    def create_event(self, event_type: str, event_data: dict = None) -> any:
        """
        Create an event with the specified type and data.
        
        Args:
            event_type: Type of event being created
            event_data: Additional data to include with the event
            
        Returns:
            Response from the create_meta operation
        """
        event_id = self.generate_uuid()
        
        # Merge host metadata with event data
        merged_data = {
            'event_type': event_type,
            'event_id': event_id,
            'timestamp': DemoHelpers.generate_timestamp(),
            **self.host_meta
        }
        
        if event_data:
            merged_data.update(event_data)
        
        # Convert to metadata format
        metadata = []
        for key, value in merged_data.items():
            metadata.append({'key': key, 'value': str(value)})
        
        return self.client.create_meta(
            meta_type=self.meta_type,
            meta_id=event_id,
            metadata=metadata
        )
    
    def query_events(self, event_type: str = None) -> any:
        """
        Query events of a specific type.
        
        Args:
            event_type: Optional event type filter
            
        Returns:
            Response from the query operation
        """
        # Note: This is a simplified implementation
        # Real implementation would use proper filtering
        try:
            return self.client.query_meta(meta_type=self.meta_type)
        except Exception as e:
            print_error(f"Event query failed: {e}")
            return None


def main():
    """Main demo function."""
    print_demo_header(
        "Event Factory", 
        "Event creation and management system demonstration:\n"
        "• Factory pattern for event creation\n"
        "• Automatic metadata collection\n"
        "• Event querying and filtering\n"
        "• UUID generation and tracking"
    )
    
    try:
        # Validate environment and setup
        validate_environment()
        config = get_demo_config()
        
        # Initialize client and authenticate
        with DemoStep("Client Setup", "Initializing client and authenticating"):
            client = KnishIOClient(config.node_uri)
            auth_response = client.request_auth_token(**config.get_auth_kwargs())
            
            if not auth_response or not auth_response.success():
                reason = auth_response.reason() if auth_response else "No response"
                raise Exception(f"Authentication failed: {reason}")
            
            print_success("Client authenticated successfully")
            
            # Store auth token for factory validation
            client._auth_token = True  # Simple flag for demo
        
        # Step 1: Event Factory Creation
        print_section("Event Factory Creation")
        
        with DemoStep("Create Event Factory", "Setting up event factory for demo events"):
            event_factory = PythonEventFactory(client, "DemoEvent")
            
            print_success("Event factory created successfully")
            print(f"  • Meta type: {event_factory.meta_type}")
            print(f"  • Client bundle: {event_factory.get_bundle()[:16]}...")
            print(f"  • Host metadata collected: {len(event_factory.host_meta)} fields")
        
        with DemoStep("Display Host Metadata", "Showing collected system information"):
            print_success("Host metadata collected:")
            for key, value in event_factory.host_meta.items():
                print(f"  • {key}: {value}")
        
        # Step 2: Basic Event Creation
        print_section("Basic Event Creation")
        
        basic_events = [
            ("user_login", {"user_id": "demo_user", "session_id": "sess_001"}),
            ("page_view", {"page": "/dashboard", "user_agent": "Python Demo"}),
            ("api_call", {"endpoint": "/api/balance", "method": "GET", "status": 200}),
            ("user_logout", {"user_id": "demo_user", "session_duration": "300"})
        ]
        
        created_events = []
        
        for event_type, event_data in basic_events:
            with DemoStep(f"Create {event_type} Event", f"Creating {event_type} event"):
                try:
                    response = event_factory.create_event(event_type, event_data)
                    
                    if response and response.success():
                        created_events.append(event_type)
                        print_success(f"{event_type} event created successfully")
                        print_response(response, f"{event_type} Event")
                    else:
                        reason = response.reason() if response else "Unknown error"
                        print_error(f"{event_type} event creation failed: {reason}")
                        
                except Exception as e:
                    handle_demo_error(f"{event_type} event creation", e)
        
        # Step 3: Complex Event Creation
        print_section("Complex Event Creation")
        
        with DemoStep("Create Transaction Event", "Creating complex transaction event"):
            try:
                transaction_data = {
                    'transaction_id': DemoHelpers.generate_uuid(),
                    'transaction_type': 'token_transfer',
                    'from_address': 'addr_123...',
                    'to_address': 'addr_456...',
                    'amount': '100.50',
                    'token': 'USER',
                    'fee': '0.01',
                    'status': 'completed',
                    'block_height': '12345',
                    'confirmation_time': str(int(time.time()))
                }
                
                response = event_factory.create_event("transaction", transaction_data)
                
                if response and response.success():
                    created_events.append("transaction")
                    print_success("Transaction event created successfully")
                    print_response(response, "Transaction Event")
                else:
                    reason = response.reason() if response else "Unknown error"
                    print_error(f"Transaction event creation failed: {reason}")
                    
            except Exception as e:
                handle_demo_error("Transaction event creation", e)
        
        with DemoStep("Create Error Event", "Creating error/exception event"):
            try:
                error_data = {
                    'error_type': 'ValidationError',
                    'error_message': 'Invalid token amount specified',
                    'error_code': 'INVALID_AMOUNT',
                    'stack_trace': 'demo_function() -> validate_amount() -> raise ValidationError',
                    'user_id': 'demo_user',
                    'request_id': DemoHelpers.generate_uuid(),
                    'severity': 'medium',
                    'resolved': 'false'
                }
                
                response = event_factory.create_event("error", error_data)
                
                if response and response.success():
                    created_events.append("error")
                    print_success("Error event created successfully")
                    print_response(response, "Error Event")
                else:
                    reason = response.reason() if response else "Unknown error"
                    print_error(f"Error event creation failed: {reason}")
                    
            except Exception as e:
                handle_demo_error("Error event creation", e)
        
        # Step 4: Batch Event Creation
        print_section("Batch Event Creation")
        
        with DemoStep("Create Batch Events", "Creating multiple events in sequence"):
            batch_size = 3
            batch_events = []
            
            for i in range(batch_size):
                try:
                    batch_data = {
                        'batch_id': f'batch_{int(time.time())}',
                        'item_number': str(i + 1),
                        'item_data': f'item_value_{i}',
                        'processing_status': 'completed'
                    }
                    
                    response = event_factory.create_event("batch_item", batch_data)
                    
                    if response and response.success():
                        batch_events.append(f"batch_item_{i+1}")
                        print_success(f"Batch item {i+1} created")
                    else:
                        print_error(f"Batch item {i+1} failed")
                        
                except Exception as e:
                    print_error(f"Batch item {i+1} error: {e}")
            
            print_success(f"Batch creation completed: {len(batch_events)}/{batch_size} events created")
            created_events.extend(batch_events)
        
        # Step 5: Event Querying
        print_section("Event Querying")
        
        with DemoStep("Query All Events", "Attempting to query created events"):
            try:
                query_response = event_factory.query_events()
                
                if query_response:
                    print_success("Event query executed")
                    print_response(query_response, "Event Query")
                else:
                    print_error("Event query returned no results")
                    
            except Exception as e:
                handle_demo_error("Event querying", e)
        
        # Step 6: Event Analytics
        print_section("Event Analytics")
        
        with DemoStep("Event Summary", "Analyzing created events"):
            print_success("Event creation summary:")
            print(f"  • Total events attempted: {len(basic_events) + 2 + batch_size}")
            print(f"  • Successfully created: {len(created_events)}")
            print(f"  • Event types created: {set([e.split('_')[0] for e in created_events])}")
            print(f"  • Factory meta type: {event_factory.meta_type}")
            
            if created_events:
                print_success("Created event types:")
                for event in created_events:
                    print(f"    - {event}")
        
        with DemoStep("System Information", "Displaying collected system data"):
            print_success("System information captured in events:")
            important_fields = ['platform', 'python_version', 'architecture', 'sdk']
            for field in important_fields:
                if field in event_factory.host_meta:
                    print(f"  • {field}: {event_factory.host_meta[field]}")
        
        # Step 7: Demo Summary
        print_section("Demo Summary")
        
        print_success("Event factory demo completed successfully!")
        print("  • Event factory pattern implemented")
        print("  • Automatic metadata collection working")
        print("  • Multiple event types created:")
        print("    - Basic events (login, page view, API call, logout)")
        print("    - Complex events (transaction, error)")
        print("    - Batch events (multiple items)")
        print("  • Event querying demonstrated")
        print("  • System metadata automatically included")
        
        print_success(f"Total events created: {len(created_events)}")
        
        print_demo_footer()
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Demo interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        handle_demo_error("Event Factory Demo", e)
        sys.exit(1)


if __name__ == "__main__":
    main()