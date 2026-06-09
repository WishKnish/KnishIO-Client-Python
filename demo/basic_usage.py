#!/usr/bin/env python3
"""
Basic Usage Demo - Knish.IO Python SDK

This demo demonstrates the simplest way to get started with the Knish.IO Python SDK.
It covers client initialization, authentication, and basic wallet operations.

Perfect for: First-time users wanting to understand the basics.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from knishioclient.client import KnishIOClient
from knishioclient.exception import UnauthenticatedException
from utils.demo_config import validate_environment, get_demo_config
from utils.demo_helpers import (
    print_demo_header, print_demo_footer, print_section, 
    print_success, print_error, print_response, handle_demo_error,
    DemoStep, wait_for_input, Colors
)


def main():
    """Main demo function."""
    print_demo_header(
        "Basic Usage", 
        "Learn the fundamentals of the Knish.IO Python SDK including\n"
        "client initialization, authentication, and basic operations."
    )
    
    try:
        # Validate environment
        validate_environment()
        config = get_demo_config()
        
        # Step 1: Client Initialization
        with DemoStep("Client Initialization", "Setting up KnishIOClient with node URI"):
            client = KnishIOClient(config.node_uri)
            print_success(f"Client initialized with URI: {config.node_uri}")
            print_success(f"Cell slug: {config.cell_slug}")
        
        # Step 2: Authentication
        print_section("Authentication")
        
        # Demonstrate profile authentication
        with DemoStep("Profile Authentication", "Authenticating with user secret"):
            auth_response = client.request_auth_token(
                secret=config.secret,
                cell_slug=config.cell_slug,
                encrypt=False
            )
            
            if auth_response and auth_response.success():
                print_success("Profile authentication successful!")
                print_response(auth_response, "Authentication Response")
            else:
                reason = auth_response.reason() if auth_response else "No response"
                raise Exception(f"Authentication failed: {reason}")
        
        # Demonstrate guest authentication (if supported)
        with DemoStep("Guest Authentication", "Trying guest authentication mode"):
            try:
                guest_client = KnishIOClient(config.node_uri)
                guest_response = guest_client.request_auth_token(
                    secret=None,  # None triggers guest mode
                    cell_slug=config.cell_slug,
                    encrypt=False
                )
                
                if guest_response and guest_response.success():
                    print_success("Guest authentication successful!")
                    print_response(guest_response, "Guest Auth Response")
                else:
                    print_error("Guest authentication not supported or failed")
                    
            except UnauthenticatedException:
                print_error("Guest authentication not available on this server")
            except Exception as e:
                print_error(f"Guest authentication error: {e}")
        
        # Step 3: Basic Wallet Operations
        print_section("Basic Wallet Operations")
        
        with DemoStep("Bundle Information", "Getting wallet bundle information"):
            bundle_hash = client.bundle()
            print_success(f"Bundle hash: {bundle_hash}")
        
        with DemoStep("Balance Query", "Querying USER token balance"):
            balance_response = client.query_balance("USER")
            print_response(balance_response, "Balance Query")
            
            # Extract balance information if available
            if balance_response and hasattr(balance_response, 'data'):
                wallet_data = balance_response.data()
                if wallet_data and hasattr(wallet_data, 'balance'):
                    print_success(f"Current balance: {wallet_data.balance} USER")
                else:
                    print_error("No balance data found (wallet may not exist)")
        
        with DemoStep("Wallet Query", "Querying wallet information"):
            try:
                wallet_response = client.query_wallets(unspent=True)
                print_response(wallet_response, "Wallet Query")
            except Exception as e:
                handle_demo_error("Wallet query", e)
        
        # Step 4: Basic Metadata Operations
        print_section("Basic Metadata Operations")
        
        with DemoStep("Metadata Creation", "Creating demo metadata"):
            try:
                meta_type = "DemoData"
                meta_id = f"basic-demo-{int(os.times().elapsed * 1000)}"
                
                metadata_response = client.create_meta(
                    meta_type=meta_type,
                    meta_id=meta_id,
                    metadata=[
                        {'key': 'demo_type', 'value': 'basic_usage'},
                        {'key': 'created_by', 'value': 'Python SDK'},
                        {'key': 'timestamp', 'value': str(int(os.times().elapsed * 1000))}
                    ]
                )
                
                if metadata_response and metadata_response.success():
                    print_success(f"Metadata created: {meta_type}/{meta_id}")
                    print_response(metadata_response, "Metadata Creation")
                else:
                    reason = metadata_response.reason() if metadata_response else "Unknown error"
                    print_error(f"Metadata creation failed: {reason}")
                    
            except Exception as e:
                handle_demo_error("Metadata creation", e)
        
        # Step 5: Basic Information Display
        print_section("Client Information")
        
        with DemoStep("Client Status", "Displaying client information"):
            print_success("Client configuration:")
            print(f"  • Node URI: {config.node_uri}")
            print(f"  • Cell Slug: {config.cell_slug}")
            print(f"  • Secret Length: {len(config.secret)} characters")
            print(f"  • Demo Mode: {config.demo_mode}")
            print(f"  • Verbose Mode: {config.verbose}")
        
        # Interactive pause
        if not os.getenv('CI'):  # Skip in CI environments
            wait_for_input("Press Enter to continue to advanced operations or Ctrl+C to exit...")
        
        # Step 6: Advanced Query Example
        print_section("Advanced Query Example")
        
        with DemoStep("Bundle Query", "Querying bundle information"):
            try:
                bundle_response = client.query_bundle()
                print_response(bundle_response, "Bundle Information")
            except Exception as e:
                handle_demo_error("Bundle query", e)
        
        print_demo_footer()
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Demo interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        handle_demo_error("Demo", e)
        sys.exit(1)


if __name__ == "__main__":
    main()