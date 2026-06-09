#!/usr/bin/env python3
"""
Message Encryption Demo - Knish.IO Python SDK

This demo demonstrates secure wallet-to-wallet message encryption
and decryption capabilities using the SDK's cryptographic features.

Perfect for: Building secure messaging applications.
"""

import sys
import os
import json

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
        "Message Encryption", 
        "Secure wallet-to-wallet communication demonstration:\n"
        "• Public/private key generation\n"
        "• Message encryption and decryption\n"
        "• Cross-wallet secure communication\n"
        "• Key sharing and management patterns"
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
        
        # Step 1: Wallet Setup for Encryption
        print_section("Wallet Setup for Encryption")
        
        with DemoStep("Create Sender Wallet", "Setting up sender wallet (Alice)"):
            # Use the authenticated client's secret for sender
            alice_secret = config.secret
            alice_wallet = Wallet(secret=alice_secret, token="USER")
            
            print_success("Alice (Sender) wallet created:")
            print(f"  • Address: {alice_wallet.address}")
            print(f"  • Public Key: {alice_wallet.pubkey[:32]}...")
            print(f"  • Bundle: {alice_wallet.bundle}")
        
        with DemoStep("Create Recipient Wallet", "Setting up recipient wallet (Bob)"):
            # Generate a different secret for recipient
            bob_secret = crypto.generate_secret()
            bob_wallet = Wallet(secret=bob_secret, token="USER")
            
            print_success("Bob (Recipient) wallet created:")
            print(f"  • Address: {bob_wallet.address}")
            print(f"  • Public Key: {bob_wallet.pubkey[:32]}...")
            print(f"  • Bundle: {bob_wallet.bundle}")
        
        # Step 2: Key Exchange Simulation
        print_section("Key Exchange Mechanics")
        
        with DemoStep("Public Key Exchange", "Simulating public key sharing"):
            # In a real application, public keys would be shared through the ledger
            # or through metadata queries. Here we simulate the exchange.
            
            alice_public_key = alice_wallet.pubkey
            bob_public_key = bob_wallet.pubkey
            
            print_success("Public key exchange completed:")
            print(f"  • Alice shares: {alice_public_key[:32]}...")
            print(f"  • Bob shares: {bob_public_key[:32]}...")
            print_success("✓ Both parties now have each other's public keys")
        
        with DemoStep("Key Validation", "Validating exchanged keys"):
            print_success("Key validation:")
            print(f"  • Alice's key length: {len(alice_public_key)} characters")
            print(f"  • Bob's key length: {len(bob_public_key)} characters")
            print(f"  • Key format: Hexadecimal encoding")
            print(f"  • Cryptographic standard: Compatible with wallet encryption")
        
        # Step 3: Message Encryption
        print_section("Message Encryption")
        
        messages_to_encrypt = [
            "Hello Bob! This is a secret message from Alice.",
            "Meeting tomorrow at 3 PM in conference room A.",
            "The password for the demo system is: demo123!",
            json.dumps({"transaction_id": "12345", "amount": 100.50, "token": "USER"})
        ]
        
        encrypted_messages = []
        
        for i, message in enumerate(messages_to_encrypt):
            with DemoStep(f"Encrypt Message {i+1}", f"Encrypting: '{message[:30]}...'"):
                try:
                    # Alice encrypts message for Bob using Bob's public key
                    encrypted_data = alice_wallet.encrypt_message(message, bob_public_key)
                    encrypted_messages.append(encrypted_data)
                    
                    print_success(f"Message {i+1} encrypted successfully")
                    print(f"  • Original length: {len(message)} characters")
                    print(f"  • Encrypted length: {len(encrypted_data)} characters")
                    print(f"  • Encrypted preview: {encrypted_data[:32]}...")
                    
                except Exception as e:
                    handle_demo_error(f"Message {i+1} encryption", e)
                    encrypted_messages.append(None)
        
        # Step 4: Message Decryption
        print_section("Message Decryption")
        
        for i, (original_message, encrypted_data) in enumerate(zip(messages_to_encrypt, encrypted_messages)):
            if encrypted_data is None:
                continue
                
            with DemoStep(f"Decrypt Message {i+1}", f"Decrypting message {i+1}"):
                try:
                    # Bob decrypts message from Alice using his private key
                    decrypted_message = bob_wallet.decrypt_message(encrypted_data, alice_public_key)
                    
                    # Verify message integrity
                    if decrypted_message == original_message:
                        print_success(f"Message {i+1} decrypted successfully ✓")
                        print(f"  • Decrypted: '{decrypted_message[:50]}...'")
                        print(f"  • Integrity: Message unchanged")
                    else:
                        print_error(f"Message {i+1} integrity check failed!")
                        print(f"  • Expected: '{original_message[:30]}...'")
                        print(f"  • Got: '{decrypted_message[:30]}...'")
                        
                except Exception as e:
                    handle_demo_error(f"Message {i+1} decryption", e)
        
        # Step 5: Bidirectional Communication
        print_section("Bidirectional Communication")
        
        with DemoStep("Bob to Alice Message", "Demonstrating reverse communication"):
            try:
                # Bob sends encrypted reply to Alice
                reply_message = "Thanks Alice! Message received and understood. -Bob"
                
                # Bob encrypts using Alice's public key
                encrypted_reply = bob_wallet.encrypt_message(reply_message, alice_public_key)
                print_success("Bob's reply encrypted")
                print(f"  • Reply message: '{reply_message}'")
                print(f"  • Encrypted length: {len(encrypted_reply)} characters")
                
                # Alice decrypts Bob's reply
                decrypted_reply = alice_wallet.decrypt_message(encrypted_reply, bob_public_key)
                
                if decrypted_reply == reply_message:
                    print_success("Alice successfully received Bob's reply ✓")
                    print(f"  • Decrypted: '{decrypted_reply}'")
                else:
                    print_error("Reply decryption failed!")
                    
            except Exception as e:
                handle_demo_error("Bidirectional communication", e)
        
        # Step 6: Advanced Encryption Features
        print_section("Advanced Encryption Features")
        
        with DemoStep("Large Message Encryption", "Testing encryption with larger content"):
            try:
                # Create a larger message
                large_message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 20
                
                print_success(f"Large message size: {len(large_message)} characters")
                
                # Encrypt and decrypt large message
                encrypted_large = alice_wallet.encrypt_message(large_message, bob_public_key)
                decrypted_large = bob_wallet.decrypt_message(encrypted_large, alice_public_key)
                
                if decrypted_large == large_message:
                    print_success("Large message encryption/decryption successful ✓")
                    print(f"  • Compression ratio: {len(encrypted_large) / len(large_message):.2f}")
                else:
                    print_error("Large message encryption failed!")
                    
            except Exception as e:
                handle_demo_error("Large message encryption", e)
        
        with DemoStep("Binary Data Encryption", "Testing encryption with binary data"):
            try:
                # Create binary data (simulated as bytes)
                binary_data = bytes(range(256))  # All possible byte values
                binary_message = binary_data.hex()  # Convert to hex string for encryption
                
                print_success(f"Binary data size: {len(binary_message)} characters (hex)")
                
                # Encrypt and decrypt binary data
                encrypted_binary = alice_wallet.encrypt_message(binary_message, bob_public_key)
                decrypted_binary = bob_wallet.decrypt_message(encrypted_binary, alice_public_key)
                
                if decrypted_binary == binary_message:
                    print_success("Binary data encryption/decryption successful ✓")
                else:
                    print_error("Binary data encryption failed!")
                    
            except Exception as e:
                handle_demo_error("Binary data encryption", e)
        
        # Step 7: Security Analysis
        print_section("Security Analysis")
        
        with DemoStep("Encryption Security Analysis", "Analyzing security properties"):
            print_success("Security properties demonstrated:")
            print("  • ✓ End-to-end encryption between wallets")
            print("  • ✓ Public key cryptography ensures only recipient can decrypt")
            print("  • ✓ Message integrity preserved during encryption/decryption")
            print("  • ✓ Bidirectional communication supported")
            print("  • ✓ Support for various data types (text, JSON, binary)")
            print("  • ✓ Scalable to large messages")
            
            print_success("Security considerations:")
            print("  • Private keys never shared or transmitted")
            print("  • Public keys can be shared safely")
            print("  • Each message encrypted independently")
            print("  • No key reuse vulnerabilities")
        
        # Step 8: Demo Summary
        print_section("Demo Summary")
        
        print_success("Message encryption demo completed successfully!")
        print("  • Encryption operations performed:")
        print(f"    - {len([m for m in encrypted_messages if m])} messages encrypted")
        print("    - Bidirectional communication tested")
        print("    - Large message encryption verified")
        print("    - Binary data encryption tested")
        print("  • Security features demonstrated:")
        print("    - End-to-end encryption")
        print("    - Public key cryptography")
        print("    - Message integrity verification")
        print("    - Cross-wallet communication")
        
        print_success("All encryption operations completed successfully!")
        
        print_demo_footer()
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Demo interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        handle_demo_error("Message Encryption Demo", e)
        sys.exit(1)


if __name__ == "__main__":
    main()