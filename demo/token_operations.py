#!/usr/bin/env python3
"""
Token Operations Demo - Knish.IO Python SDK

This demo demonstrates comprehensive token management including creation,
transfers, burning, and replenishing operations.

Perfect for: Developers building token-based applications.
"""

import sys
import os
import time

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from knishioclient.client import KnishIOClient
from knishioclient.models import Wallet
from knishioclient.exception import (
    TransferBalanceException, 
    BalanceInsufficientException
)
from utils.demo_config import validate_environment, get_demo_config
from utils.demo_helpers import (
    print_demo_header, print_demo_footer, print_section, 
    print_success, print_error, print_response, handle_demo_error,
    DemoStep, DemoHelpers, Colors
)


def main():
    """Main demo function."""
    print_demo_header(
        "Token Operations", 
        "Comprehensive demonstration of token management including:\n"
        "• Token creation (fungible tokens)\n"
        "• Token transfers between wallets\n"
        "• Token burning and replenishing\n"
        "• Balance verification and queries"
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
        
        # Step 1: Token Creation
        print_section("Token Creation")
        
        # Generate unique token slug for demo
        token_slug = DemoHelpers.generate_test_token_slug("DEMO")
        
        with DemoStep("Create Fungible Token", f"Creating token: {token_slug}"):
            try:
                # Note: Token creation may not be available on all servers
                # This demonstrates the API even if it fails
                token_response = client.create_token(
                    token_slug=token_slug,
                    initial_amount=10000,
                    token_metadata={
                        'name': f'Demo Token {token_slug}',
                        'description': 'Token created by Python SDK demo',
                        'fungibility': 'fungible',
                        'supply_type': 'fixed'
                    }
                )
                
                if token_response and token_response.success():
                    print_success(f"Token {token_slug} created successfully!")
                    print_response(token_response, "Token Creation")
                else:
                    reason = token_response.reason() if token_response else "Unknown error"
                    print_error(f"Token creation failed: {reason}")
                    # Continue with demo using existing tokens
                    token_slug = "USER"  # Fall back to USER token
                    print_success(f"Continuing demo with existing token: {token_slug}")
                    
            except Exception as e:
                handle_demo_error("Token creation", e)
                token_slug = "USER"  # Fall back to USER token
                print_success(f"Continuing demo with existing token: {token_slug}")
        
        # Step 2: Balance Queries
        print_section("Balance Operations")
        
        with DemoStep("Query Balance", f"Checking balance for {token_slug}"):
            balance_response = client.query_balance(token_slug)
            print_response(balance_response, "Balance Query")
            
            current_balance = 0
            if balance_response and hasattr(balance_response, 'data'):
                wallet_data = balance_response.data()
                if wallet_data and hasattr(wallet_data, 'balance'):
                    current_balance = float(wallet_data.balance)
                    print_success(f"Current balance: {DemoHelpers.format_balance(current_balance, token_slug)}")
                else:
                    print_error("No balance found - wallet may not exist for this token")
        
        # Step 3: Wallet Creation (if needed)
        print_section("Wallet Operations")
        
        with DemoStep("Create Wallet", f"Ensuring wallet exists for {token_slug}"):
            try:
                wallet_response = client.create_wallet(token_slug)
                if wallet_response and wallet_response.success():
                    print_success(f"Wallet created for {token_slug}")
                    print_response(wallet_response, "Wallet Creation")
                else:
                    # Wallet might already exist
                    print_success(f"Wallet for {token_slug} already exists or creation not needed")
            except Exception as e:
                # Wallet creation might fail if it already exists - this is normal
                print_success(f"Wallet for {token_slug} already exists")
        
        # Step 4: Token Transfers
        print_section("Token Transfer Operations")
        
        with DemoStep("Create Recipient Wallet", "Setting up recipient for transfer"):
            # Create a recipient wallet with different secret
            recipient_secret = DemoHelpers.generate_uuid()[:32] + "00" * 16  # 64 char hex
            recipient_wallet = Wallet(secret=recipient_secret, token=token_slug)
            
            print_success(f"Recipient wallet created:")
            print(f"  • Address: {recipient_wallet.address}")
            print(f"  • Bundle: {recipient_wallet.bundle}")
        
        with DemoStep("Token Transfer", f"Transferring {token_slug} to recipient"):
            try:
                transfer_amount = min(10, current_balance) if current_balance > 0 else 1
                
                transfer_response = client.transfer_token(
                    wallet_object_or_bundle_hash=recipient_wallet.bundle,
                    token_slug=token_slug,
                    amount=transfer_amount
                )
                
                if transfer_response and transfer_response.success():
                    print_success(f"Transfer successful: {transfer_amount} {token_slug}")
                    print_response(transfer_response, "Transfer Response")
                else:
                    reason = transfer_response.reason() if transfer_response else "Unknown error"
                    print_error(f"Transfer failed: {reason}")
                    
            except (TransferBalanceException, BalanceInsufficientException) as e:
                print_error(f"Transfer not possible: {e}")
            except Exception as e:
                handle_demo_error("Token transfer", e)
        
        # Step 5: Advanced Token Operations
        print_section("Advanced Token Operations")
        
        with DemoStep("Token Burning", "Demonstrating token burning operation"):
            try:
                burn_amount = 1.0
                burn_response = client.burn_tokens(
                    token_slug=token_slug,
                    amount=burn_amount
                )
                
                if burn_response and burn_response.success():
                    print_success(f"Successfully burned {burn_amount} {token_slug}")
                    print_response(burn_response, "Burn Response")
                else:
                    reason = burn_response.reason() if burn_response else "Unknown error"
                    print_error(f"Burn operation failed: {reason}")
                    
            except Exception as e:
                handle_demo_error("Token burning", e)
        
        with DemoStep("Token Replenishing", "Demonstrating token replenishing operation"):
            try:
                replenish_amount = 5.0
                replenish_response = client.replenish_token(
                    token_slug=token_slug,
                    amount=replenish_amount,
                    metas={
                        'action': 'demo_replenish',
                        'reason': 'Python SDK demonstration',
                        'timestamp': str(int(time.time()))
                    }
                )
                
                if replenish_response and replenish_response.success():
                    print_success(f"Successfully replenished {replenish_amount} {token_slug}")
                    print_response(replenish_response, "Replenish Response")
                else:
                    reason = replenish_response.reason() if replenish_response else "Unknown error"
                    print_error(f"Replenish operation failed: {reason}")
                    
            except Exception as e:
                handle_demo_error("Token replenishing", e)
        
        # Step 6: Final Balance Check
        print_section("Final Balance Verification")
        
        with DemoStep("Final Balance Check", "Verifying final balance after operations"):
            final_balance_response = client.query_balance(token_slug)
            print_response(final_balance_response, "Final Balance")
            
            if final_balance_response and hasattr(final_balance_response, 'data'):
                wallet_data = final_balance_response.data()
                if wallet_data and hasattr(wallet_data, 'balance'):
                    final_balance = float(wallet_data.balance)
                    print_success(f"Final balance: {DemoHelpers.format_balance(final_balance, token_slug)}")
                    
                    if current_balance > 0:
                        change = final_balance - current_balance
                        if change != 0:
                            change_type = "increase" if change > 0 else "decrease"
                            print_success(f"Balance {change_type}: {abs(change):,.2f} {token_slug}")
        
        # Step 7: Demo Summary
        print_section("Demo Summary")
        
        print_success("Token operations demo completed successfully!")
        print(f"  • Token used: {token_slug}")
        print(f"  • Operations demonstrated:")
        print(f"    - Token creation (if supported)")
        print(f"    - Balance queries")
        print(f"    - Wallet operations")
        print(f"    - Token transfers")
        print(f"    - Token burning")
        print(f"    - Token replenishing")
        
        print_demo_footer()
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Demo interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        handle_demo_error("Token Operations Demo", e)
        sys.exit(1)


if __name__ == "__main__":
    main()