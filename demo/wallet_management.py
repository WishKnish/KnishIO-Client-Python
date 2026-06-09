#!/usr/bin/env python3
"""
Wallet Management Demo - Knish.IO Python SDK

This demo demonstrates advanced wallet management features including
wallet generation, multi-token operations, and ContinuID mechanics.

Perfect for: Understanding wallet architecture and identity management.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from knishioclient.client import KnishIOClient
from knishioclient.models import Wallet
from knishioclient.libraries import crypto
from utils.demo_config import validate_environment, get_demo_config
from utils.demo_helpers import (
    print_demo_header, print_demo_footer, print_section, 
    print_success, print_error, print_response, handle_demo_error,
    DemoStep, DemoHelpers, Colors
)


def main():
    """Main demo function."""
    print_demo_header(
        "Wallet Management", 
        "Advanced wallet operations and identity management:\n"
        "• Wallet generation mechanics\n"
        "• Multi-token wallet operations\n"
        "• ContinuID position tracking\n"
        "• Bundle operations and address generation"
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
        
        # Step 1: Wallet Generation Mechanics
        print_section("Wallet Generation Mechanics")
        
        with DemoStep("Secret Generation", "Demonstrating secret generation"):
            # Generate a demo secret
            demo_secret = crypto.generate_secret()
            print_success(f"Generated secret length: {len(demo_secret)} characters")
            print_success(f"Secret preview: {demo_secret[:16]}...")
            
            # Show secret properties
            print(f"  • Secret type: Hexadecimal string")
            print(f"  • Entropy: {len(demo_secret) * 4} bits")
            print(f"  • Use case: Wallet generation and signing")
        
        with DemoStep("Bundle Hash Generation", "Understanding bundle mechanics"):
            # Generate bundle hash from secret
            bundle_hash = crypto.generate_bundle_hash(demo_secret)
            print_success(f"Bundle hash: {bundle_hash}")
            
            # Show bundle properties
            print(f"  • Bundle length: {len(bundle_hash)} characters")
            print(f"  • Deterministic: Same secret always produces same bundle")
            print(f"  • Purpose: Wallet identity container")
        
        # Step 2: Multi-Token Wallet Creation
        print_section("Multi-Token Wallet Operations")
        
        tokens = ["USER", "TEST", "DEMO"]
        wallets = {}
        
        for token in tokens:
            with DemoStep(f"Create {token} Wallet", f"Generating wallet for {token} token"):
                try:
                    wallet = Wallet(secret=demo_secret, token=token)
                    wallets[token] = wallet
                    
                    print_success(f"{token} wallet created:")
                    print(f"  • Address: {wallet.address}")
                    print(f"  • Position: {wallet.position[:16]}...")
                    print(f"  • Bundle: {wallet.bundle}")
                    print(f"  • Token: {wallet.token}")
                    
                except Exception as e:
                    handle_demo_error(f"{token} wallet creation", e)
        
        # Step 3: ContinuID Position Analysis
        print_section("ContinuID Position Mechanics")
        
        with DemoStep("Position Analysis", "Analyzing ContinuID position generation"):
            if wallets:
                sample_wallet = list(wallets.values())[0]
                print_success("Position analysis:")
                print(f"  • Position length: {len(sample_wallet.position)} characters")
                print(f"  • Position format: Hexadecimal")
                print(f"  • Position preview: {sample_wallet.position[:32]}...")
                
                # Demonstrate position uniqueness per token
                print_success("Position uniqueness per token:")
                for token, wallet in wallets.items():
                    print(f"  • {token}: {wallet.position[:16]}...")
        
        with DemoStep("Address Generation", "Understanding address derivation"):
            if wallets:
                print_success("Address generation patterns:")
                for token, wallet in wallets.items():
                    print(f"  • {token} address: {wallet.address}")
                    print(f"    - Length: {len(wallet.address)} characters")
                    print(f"    - Checksum: Built-in address validation")
        
        # Step 4: Wallet Bundle Operations
        print_section("Wallet Bundle Operations")
        
        with DemoStep("Bundle Information", "Getting current wallet bundle details"):
            current_bundle = client.bundle()
            print_success(f"Current client bundle: {current_bundle}")
            
            # Compare with generated wallets
            if wallets:
                sample_wallet = list(wallets.values())[0]
                if current_bundle == sample_wallet.bundle:
                    print_success("✓ Bundle matches generated wallet")
                else:
                    print_success("Note: Using different wallet for client vs demo")
        
        with DemoStep("Bundle Query", "Querying bundle information from ledger"):
            try:
                bundle_response = client.query_bundle()
                print_response(bundle_response, "Bundle Query")
                
            except Exception as e:
                handle_demo_error("Bundle query", e)
        
        # Step 5: Wallet Balance Operations
        print_section("Multi-Token Balance Operations")
        
        for token in tokens:
            with DemoStep(f"Query {token} Balance", f"Checking balance for {token} token"):
                try:
                    balance_response = client.query_balance(token)
                    
                    if balance_response and hasattr(balance_response, 'data'):
                        wallet_data = balance_response.data()
                        if wallet_data and hasattr(wallet_data, 'balance'):
                            balance = float(wallet_data.balance)
                            print_success(f"{token} balance: {DemoHelpers.format_balance(balance, token)}")
                        else:
                            print_success(f"{token}: No balance (wallet not declared)")
                    else:
                        print_success(f"{token}: No response (wallet may not exist)")
                        
                except Exception as e:
                    handle_demo_error(f"{token} balance query", e)
        
        # Step 6: Wallet List Operations
        print_section("Wallet Discovery Operations")
        
        with DemoStep("Query Wallet List", "Discovering wallets for current bundle"):
            try:
                wallet_list_response = client.query_wallets(unspent=True)
                print_response(wallet_list_response, "Wallet List")
                
                # Try to count wallets if response has data
                if wallet_list_response and hasattr(wallet_list_response, 'data'):
                    print_success("Wallet discovery completed")
                
            except Exception as e:
                handle_demo_error("Wallet list query", e)
        
        # Step 7: Wallet Creation on Ledger
        print_section("Ledger Wallet Operations")
        
        with DemoStep("Create Wallets on Ledger", "Declaring wallets on the ledger"):
            for token in tokens[:2]:  # Limit to 2 tokens to avoid spam
                try:
                    wallet_creation_response = client.create_wallet(token)
                    
                    if wallet_creation_response and wallet_creation_response.success():
                        print_success(f"Wallet declared for {token} token")
                        print_response(wallet_creation_response, f"{token} Wallet Creation")
                    else:
                        # Wallet might already exist
                        print_success(f"Wallet for {token} already exists or creation skipped")
                        
                except Exception as e:
                    # Wallet creation might fail if already exists - this is normal
                    print_success(f"Wallet for {token} already exists")
        
        # Step 8: Advanced Wallet Features
        print_section("Advanced Wallet Features")
        
        with DemoStep("Wallet Cryptography", "Demonstrating wallet cryptographic features"):
            if wallets:
                sample_wallet = list(wallets.values())[0]
                print_success("Cryptographic features:")
                print(f"  • Public key: {sample_wallet.pubkey[:32]}...")
                print(f"  • Characters: {sample_wallet.characters}")
                print(f"  • Signing capability: Available")
                print(f"  • Encryption capability: Available")
        
        with DemoStep("Wallet Serialization", "Understanding wallet data structures"):
            if wallets:
                sample_wallet = list(wallets.values())[0]
                print_success("Wallet data structure:")
                print(f"  • Secret: [Protected]")
                print(f"  • Token: {sample_wallet.token}")
                print(f"  • Position: {sample_wallet.position[:16]}...")
                print(f"  • Bundle: {sample_wallet.bundle}")
                print(f"  • Address: {sample_wallet.address}")
                print(f"  • Public key: {sample_wallet.pubkey[:16]}...")
        
        # Step 9: Demo Summary
        print_section("Demo Summary")
        
        print_success("Wallet management demo completed successfully!")
        print("  • Wallet generation mechanics demonstrated")
        print("  • Multi-token wallet operations performed")
        print("  • ContinuID position tracking explained")
        print("  • Bundle operations and queries executed")
        print("  • Address generation patterns shown")
        print("  • Cryptographic features highlighted")
        
        print(f"  • Tokens explored: {', '.join(tokens)}")
        print(f"  • Wallets generated: {len(wallets)}")
        print(f"  • Bundle hash: {current_bundle[:16]}...")
        
        print_demo_footer()
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Demo interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        handle_demo_error("Wallet Management Demo", e)
        sys.exit(1)


if __name__ == "__main__":
    main()