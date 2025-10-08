#!/usr/bin/env python3
"""
Knish.IO Python SDK Self-Test Script
=====================================
Tests core SDK functionality and cross-platform compatibility.

Test Suite:
1. Crypto Test - Secret generation and bundle hash
2. Metadata Creation Test - M-type atoms with ContinuID
3. Simple Transfer Test - Full balance transfer
4. Complex Transfer Test - Transfer with remainder
5. Cross-SDK Validation - Validate molecules from other SDKs
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from knishioclient.libraries import crypto, strings
from knishioclient.models.Wallet import Wallet
from knishioclient.models.Molecule import Molecule
from knishioclient.models.Atom import Atom
from knishioclient.models.AtomMeta import AtomMeta
from knishioclient.models.Meta import Meta
from knishioclient.libraries.check import verify
from knishioclient.exception import *

# Fixed timestamp for deterministic testing (preserves timestamp in hash while ensuring consistency)
FIXED_TEST_TIMESTAMP_BASE = 1700000000000  # Fixed base timestamp for deterministic testing

def set_fixed_timestamps(molecule):
    """Helper function to set fixed timestamps for deterministic testing"""
    for i, atom in enumerate(molecule.atoms):
        # Set deterministic timestamp: base + (index * 1000) to ensure unique but predictable timestamps
        atom.created_at = str(FIXED_TEST_TIMESTAMP_BASE + (i * 1000))

def create_fixed_remainder_wallet(secret: str, token: str):
    """Helper function to create fixed remainder wallets for deterministic testing"""
    return Wallet(
        secret=secret,
        token=token,
        position='bbbb000000000000cccc111111111111dddd222222222222eeee333333333333'  # Fixed deterministic position
    )


# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'


# Global results storage
results = {
    'sdk': 'Python',
    'version': '1.0.0',  # TODO: Get from package version
    'timestamp': None,
    'tests': {},
    'molecules': {},
    'crossSdkCompatible': True
}


def log(message: str, color: str = None):
    """Print colored log message"""
    if color:
        print(f"{getattr(Colors, color.upper(), '')}{message}{Colors.RESET}")
    else:
        print(message)


def log_test(test_name: str, passed: bool, error: str = None):
    """Log test result with formatting"""
    if passed:
        log(f"  ✅ PASS: {test_name}", 'green')
    else:
        error_msg = f" - {error}" if error else ""
        log(f"  ❌ FAIL: {test_name}{error_msg}", 'red')


def load_config() -> Dict:
    """Load test configuration - embedded for SDK self-containment"""
    default_config = {
        "tests": {
            "crypto": {
                "seed": "TESTSEED",
                "secret": "e8ffc86d60fc6a73234a834166e7436e21df6c3209dfacc8d0bd6595707872c3799abbf7deee0f9c4b58de1fd89b9abb67a207558208d5ccf550c227d197c24e9fcc3707aeb53c4031d38392020ff72bcaa0f728aa8bc3d47d95ff0afc04d8fcdb69bff638ce56646c154fc92aa517d3c40f550d2ccacbd921724e1d94b82aed2c8e172a8a7ed5a6963f5890157fe77222b97af3787741f9d3cec0b40aec6f07ae4b2b24614f0a20e035aee0df04e176175dc100eb1b00dd7ea95c28cdec47958336945333c3bef24719ed949fa56d1541f24c725d4f374a533bf255cf22f4596147bcd1ba05abcecbe9b12095e1fdddb094616894c366498be0b5785c180100efb3c5b689fc1c01131633fe1775df52a970e9472ab7bc0c19f5742b9e9436753cd16024b2d326b763eca68c414755a0d2fdbb927f007e9413f1190578b2033a03d29387f5aea71b07a5ce80fbfd45be4a15440faadeac50e41846022894fc683a52328b470bc1860c8b038d7258f504178918502b93d84d8b0fbef3e02f89f83cb1ff033a2bdbdf2a2ba78d80c12aa8b2d6c10d76c468186bd4a4e9eacc758546bb50ed7b1ee241cc5b93ff924c7bbee6778b27789e1f9104c917fc93f735eee5b25c07a883788f3d2e0771e751c4f59b76f8426027ac2b07a2ca84534433d0a1b86cef3288e7d79e8b175a3955848cfd1dfbdcd6b5bafcf6789e56e8ef40af",
                "bundle": "fee9c2b9a964d060eb4645c4001db805c3c4b0cc9bba12841036eba4bf44b831"
            },
            "metaCreation": {
                "seed": "TESTSEED",
                "token": "USER",
                "sourcePosition": "0123456789abcdeffedcba9876543210fedcba9876543210fedcba9876543210",
                "metaType": "TestMeta",
                "metaId": "TESTMETA123",
                "metadata": {
                    "name": "Test Metadata",
                    "description": "This is a test metadata for SDK testing."
                }
            },
            "simpleTransfer": {
                "sourceSeed": "TESTSEED",
                "recipientSeed": "RECIPIENTSEED",
                "balance": 1000,
                "amount": 1000,
                "token": "TEST",
                "sourcePosition": "0123456789abcdeffedcba9876543210fedcba9876543210fedcba9876543210",
                "recipientPosition": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
            },
            "complexTransfer": {
                "sourceSeed": "TESTSEED",
                "recipient1Seed": "RECIPIENTSEED",
                "recipient2Seed": "RECIPIENT2SEED",
                "sourceBalance": 1000,
                "amount1": 500,
                "amount2": 500,
                "token": "TEST",
                "sourcePosition": "0123456789abcdeffedcba9876543210fedcba9876543210fedcba9876543210",
                "recipient1Position": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                "recipient2Position": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            },
            "mlkem768": {
                "seed": "TESTSEED",
                "token": "ENCRYPT",
                "position": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "plaintext": "Hello ML-KEM768 cross-platform test message!"
            }
        }
    }

    # Support optional external config override via environment variable
    config_path = os.environ.get('KNISHIO_TEST_CONFIG')
    if config_path and Path(config_path).exists():
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            log(f"Failed to load external config from {config_path}: {e}", 'red')
            log("Using embedded configuration", 'yellow')

    return default_config


def generate_secret(seed: str, length: int = 1024) -> str:
    """Generate deterministic secret from seed"""
    return crypto.generate_secret(seed, length)


def generate_bundle_hash(secret: str) -> str:
    """Generate bundle hash from secret"""
    return crypto.generate_bundle_hash(secret)


def inspect_molecule(molecule: Molecule, name: str = "molecule"):
    """Debug utility to inspect molecule structure"""
    log(f"\n🔍 INSPECTING {name.upper()}:", 'blue')
    log(f"  Molecular Hash: {molecule.molecularHash or 'NOT_SET'}")

    # Check if molecule has secret (private attribute)
    secret = getattr(molecule, '_Molecule__secret', None)
    log(f"  Secret: {'SET (length: ' + str(len(secret)) + ')' if secret else 'NOT_SET'}")

    log(f"  Bundle: {molecule.bundle or 'NOT_SET'}")

    source_wallet = molecule.sourceWallet
    log(f"  Source Wallet: {source_wallet.address[:16] + '...' if source_wallet and source_wallet.address else 'NOT_SET'}")

    remainder_wallet = molecule.remainderWallet if hasattr(molecule, 'remainderWallet') else None
    log(f"  Remainder Wallet: {remainder_wallet.address[:16] + '...' if remainder_wallet and remainder_wallet.address else 'NOT_SET'}")

    log(f"  Atoms ({len(molecule.atoms)}):")

    total_value = 0
    for i, atom in enumerate(molecule.atoms):
        value_str = str(atom.value) if atom.value else 'null'
        if atom.value and atom.isotope == 'V':
            try:
                total_value += float(atom.value)
            except (ValueError, TypeError):
                pass
        wallet_snippet = (atom.walletAddress[:16] + '...') if atom.walletAddress else ''
        log(f"    [{i}] {atom.isotope}: {value_str} ({wallet_snippet}) index={atom.index}")

    balance_status = "✅ BALANCED" if abs(total_value) < 0.01 else "❌ UNBALANCED"
    log(f"  Total Value: {total_value} {balance_status}")
    log(f"  Cell Slug: {molecule.cellSlug or 'NOT_SET'}")
    log(f"  Status: {molecule.status or 'NOT_SET'}")


def diagnose_validation(molecule: Molecule, sender_wallet: Optional[Wallet], name: str = "molecule"):
    """Step-by-step validation diagnostic"""
    log(f"\n🔬 VALIDATING {name.upper()} STEP-BY-STEP:", 'blue')
    log(f"  Molecule has {len(molecule.atoms)} atoms")
    log(f"  First atom isotope: {molecule.atoms[0].isotope if molecule.atoms else 'N/A'}")
    log(f"  Molecular hash present: {bool(molecule.molecularHash)}")
    log(f"  Source wallet provided: {bool(sender_wallet)}")

    # Check atom indices
    for i, atom in enumerate(molecule.atoms):
        if atom.index is not None:
            log(f"    ✅ Atom {i} index: {atom.index}", 'green')
        else:
            log(f"    ❌ Atom {i} index: None", 'red')

    # Try basic validation
    try:
        result = molecule.check(sender_wallet)
        log(f"  Basic validation result: {result}", 'green' if result else 'red')
    except Exception as e:
        log(f"  Validation exception: {str(e)}", 'red')


def test_crypto(config: Dict) -> bool:
    """Test 1: Crypto Test - Secret generation and bundle hash"""
    log('\n1. Crypto Test', 'blue')
    test_config = config['tests']['crypto']

    try:
        # Generate secret from seed
        secret = generate_secret(test_config['seed'])
        secret_match = secret == test_config['secret']
        log_test(f'Secret generation (seed: "{test_config["seed"]}")', secret_match)

        if not secret_match:
            log(f'  Expected: {test_config["secret"][:50]}...', 'yellow')
            log(f'  Got:      {secret[:50]}...', 'yellow')

        # Generate bundle hash
        bundle = generate_bundle_hash(secret)
        bundle_match = bundle == test_config['bundle']
        log_test('Bundle hash generation', bundle_match)

        if not bundle_match:
            log(f'  Expected: {test_config["bundle"]}', 'yellow')
            log(f'  Got:      {bundle}', 'yellow')

        results['tests']['crypto'] = {
            'passed': secret_match and bundle_match,
            'secret': secret,
            'bundle': bundle,
            'expectedSecret': test_config['secret'],
            'expectedBundle': test_config['bundle']
        }

        return secret_match and bundle_match

    except Exception as e:
        log(f"  ❌ ERROR: {str(e)}", 'red')
        results['tests']['crypto'] = {
            'passed': False,
            'error': str(e)
        }
        return False


def test_metadata_creation(config: Dict) -> bool:
    """Test 2: Metadata Creation Test"""
    log('\n2. Metadata Creation Test', 'blue')
    test_config = config['tests']['metaCreation']

    try:
        # Create source wallet
        source_secret = generate_secret(test_config['seed'])
        source_bundle = generate_bundle_hash(source_secret)

        source_wallet = Wallet(
            secret=source_secret,
            bundle=source_bundle,
            token=test_config['token'],
            position=test_config['sourcePosition']
        )
        log_test('Source wallet creation', True)

        # Create fixed remainder wallet for deterministic testing
        remainder_wallet = create_fixed_remainder_wallet(source_secret, test_config['token'])

        # Create molecule for metadata with fixed remainder wallet
        molecule = Molecule(
            secret=source_secret,
            source_wallet=source_wallet,
            remainder_wallet=remainder_wallet
        )

        # Initialize metadata molecule
        metadata_dict = test_config['metadata']

        molecule.init_meta(
            meta=metadata_dict,
            meta_type=test_config['metaType'],
            meta_id=test_config['metaId']
        )

        # ContinuID atom is already added by init_meta, no need to add again

        log_test('Metadata molecule initialization', True)

        # Set fixed timestamps for deterministic testing (before signing)
        set_fixed_timestamps(molecule)

        # Sign the molecule
        molecule.sign()
        log_test('Molecule signing', True)

        # Debug: Inspect molecule
        inspect_molecule(molecule, 'metadata molecule')

        # Validation diagnostic
        diagnose_validation(molecule, source_wallet, 'metadata molecule')

        # Validate the molecule
        is_valid = False
        validation_error = None
        try:
            is_valid = molecule.check(source_wallet)
            if not is_valid:
                validation_error = "Validation returned False (no exception thrown)"
        except Exception as e:
            is_valid = False
            validation_error = str(e)

        log_test('Molecule validation', is_valid, validation_error)

        # Store serialized molecule for cross-SDK verification using centralized method
        results['molecules']['metadata'] = json.dumps(molecule.to_json())

        results['tests']['metaCreation'] = {
            'passed': is_valid,
            'molecularHash': molecule.molecularHash,
            'atomCount': len(molecule.atoms),
            'validationError': validation_error
        }

        return is_valid

    except Exception as e:
        log(f"  ❌ ERROR: {str(e)}", 'red')
        results['tests']['metaCreation'] = {
            'passed': False,
            'error': str(e)
        }
        return False


def test_simple_transfer(config: Dict) -> bool:
    """Test 3: Simple Transfer Test"""
    log('\n3. Simple Transfer Test', 'blue')
    test_config = config['tests']['simpleTransfer']

    try:
        # Create source wallet
        source_secret = generate_secret(test_config['sourceSeed'])
        source_bundle = generate_bundle_hash(source_secret)

        source_wallet = Wallet(
            secret=source_secret,
            bundle=source_bundle,
            token=test_config['token'],
            position=test_config['sourcePosition']
        )

        # Set balance manually for testing
        source_wallet.balance = test_config['balance']
        log_test('Source wallet creation', True)

        # Create recipient wallet
        recipient_secret = generate_secret(test_config['recipientSeed'])

        recipient_wallet = Wallet(
            secret=recipient_secret,
            token=test_config['token'],
            position=test_config['recipientPosition']
        )
        log_test('Recipient wallet creation', True)

        # Create fixed remainder wallet for deterministic testing
        remainder_wallet = create_fixed_remainder_wallet(source_secret, test_config['token'])

        # Create molecule for value transfer with fixed remainder wallet
        molecule = Molecule(
            secret=source_secret,
            bundle=source_bundle,
            source_wallet=source_wallet,
            remainder_wallet=remainder_wallet
        )

        # Initialize value transfer (full balance)
        molecule.init_value(
            recipient=recipient_wallet,
            value=test_config['amount']
        )
        log_test('Value transfer initialization', True)

        # Set fixed timestamps for deterministic testing (before signing)
        set_fixed_timestamps(molecule)

        # Sign the molecule
        molecule.sign()
        log_test('Molecule signing', True)

        # Debug: Inspect molecule
        inspect_molecule(molecule, 'simple transfer molecule')

        # Validate the molecule
        is_valid = False
        validation_error = None
        try:
            is_valid = molecule.check(source_wallet)
            if not is_valid:
                validation_error = "Validation returned False (no exception thrown)"
        except Exception as e:
            is_valid = False
            validation_error = str(e)

        log_test('Molecule validation', is_valid, validation_error)

        # Store serialized molecule using centralized method
        results['molecules']['simpleTransfer'] = json.dumps(molecule.to_json())

        results['tests']['simpleTransfer'] = {
            'passed': is_valid,
            'molecularHash': molecule.molecularHash,
            'atomCount': len(molecule.atoms),
            'validationError': validation_error
        }

        return is_valid

    except Exception as e:
        log(f"  ❌ ERROR: {str(e)}", 'red')
        results['tests']['simpleTransfer'] = {
            'passed': False,
            'error': str(e)
        }
        return False


def test_complex_transfer(config: Dict) -> bool:
    """Test 4: Complex Transfer Test"""
    log('\n4. Complex Transfer Test', 'blue')
    test_config = config['tests']['complexTransfer']

    try:
        # Create source wallet
        source_secret = generate_secret(test_config['sourceSeed'])
        source_bundle = generate_bundle_hash(source_secret)

        source_wallet = Wallet(
            secret=source_secret,
            bundle=source_bundle,
            token=test_config['token'],
            position=test_config['sourcePosition']
        )

        # Set balance manually
        source_wallet.balance = test_config['sourceBalance']
        log_test('Source wallet creation', True)

        # Create fixed remainder wallet for deterministic testing
        remainder_wallet = create_fixed_remainder_wallet(source_secret, test_config['token'])
        log_test('Remainder wallet creation', True)

        # Create first recipient wallet
        recipient_secret = generate_secret(test_config['recipient1Seed'])

        recipient_wallet = Wallet(
            secret=recipient_secret,
            token=test_config['token'],
            position=test_config['recipient1Position']
        )
        log_test('Recipient wallet creation', True)

        # Create molecule with remainder wallet
        molecule = Molecule(
            secret=source_secret,
            bundle=source_bundle,
            source_wallet=source_wallet,
            remainder_wallet=remainder_wallet
        )

        # Initialize value transfer with remainder (sending amount1 to recipient)
        molecule.init_value(
            recipient=recipient_wallet,
            value=test_config['amount1']
        )
        log_test('Value transfer with remainder initialization', True)

        # Set fixed timestamps for deterministic testing (before signing)
        set_fixed_timestamps(molecule)

        # Sign the molecule
        molecule.sign()
        log_test('Molecule signing', True)

        # Debug: Inspect molecule
        inspect_molecule(molecule, 'complex transfer molecule')

        # Step-by-step validation diagnostic
        diagnose_validation(molecule, source_wallet, 'complex transfer molecule')

        # Validate the molecule
        is_valid = False
        validation_error = None
        try:
            is_valid = molecule.check(source_wallet)
            if not is_valid:
                validation_error = "Validation returned False (no exception thrown)"
        except Exception as e:
            is_valid = False
            validation_error = str(e)

        log_test('Molecule validation', is_valid, validation_error)

        # Store serialized molecule using centralized method
        results['molecules']['complexTransfer'] = json.dumps(molecule.to_json())

        results['tests']['complexTransfer'] = {
            'passed': is_valid,
            'molecularHash': molecule.molecularHash,
            'atomCount': len(molecule.atoms),
            'hasRemainder': True,
            'validationError': validation_error
        }

        return is_valid

    except Exception as e:
        log(f"  ❌ ERROR: {str(e)}", 'red')
        results['tests']['complexTransfer'] = {
            'passed': False,
            'error': str(e)
        }
        return False


def test_mlkem768(config: Dict) -> bool:
    """Test 5: ML-KEM768 Encryption Test"""
    log('\n5. ML-KEM768 Encryption Test', 'blue')
    test_config = config['tests']['mlkem768']

    try:
        # Create encryption wallet from seed
        secret = generate_secret(test_config['seed'])
        bundle = generate_bundle_hash(secret)

        encryption_wallet = Wallet(
            secret=secret,
            bundle=bundle,
            token=test_config['token'],
            position=test_config['position']
        )

        log_test('Encryption wallet creation', True)

        # 🔬 DETERMINISM TEST: Create second identical wallet and verify keys match
        log('\n  🔬 Testing ML-KEM768 determinism...', 'cyan')
        identical_wallet = Wallet(
            secret=secret,
            bundle=bundle,
            token=test_config['token'],
            position=test_config['position']
        )

        keys_identical = encryption_wallet.pubkey == identical_wallet.pubkey
        log(f"  🔑 ML-KEM768 keys identical: {'✅ YES' if keys_identical else '❌ NO'}",
            'green' if keys_identical else 'red')

        if not keys_identical:
            pubkey1_sample = encryption_wallet.pubkey[:50] if encryption_wallet.pubkey else 'None'
            pubkey2_sample = identical_wallet.pubkey[:50] if identical_wallet.pubkey else 'None'
            log(f"  📊 Wallet 1 pubkey: {pubkey1_sample}...", 'yellow')
            log(f"  📊 Wallet 2 pubkey: {pubkey2_sample}...", 'yellow')
            log(f"  🚨 CRITICAL: Python ML-KEM768 is NOT deterministic!", 'red')
            log(f"  💡 This explains cross-platform compatibility failures!", 'yellow')
        else:
            log(f"  ✅ Python ML-KEM768 is deterministic", 'green')

        # Get ML-KEM768 public key
        public_key = encryption_wallet.pubkey
        public_key_generated = bool(public_key)
        log_test('ML-KEM768 public key generation', public_key_generated)
        log_test('ML-KEM768 determinism check', keys_identical)

        # Encrypt plaintext message for ourselves (non-deterministic)
        encrypted_data = encryption_wallet.encrypt_message(
            test_config['plaintext'],
            public_key
        )

        encryption_success = bool(encrypted_data and
                                 encrypted_data.get('cipherText') and
                                 encrypted_data.get('encryptedMessage'))
        log_test('Message encryption (self-encryption)', encryption_success)

        # Decrypt the encrypted message
        decrypted_message = encryption_wallet.decrypt_message(encrypted_data)

        decryption_success = decrypted_message == test_config['plaintext']
        log_test('Message decryption and verification', decryption_success)

        test_passed = public_key_generated and encryption_success and decryption_success and keys_identical

        # Store ML-KEM768 data for cross-SDK verification (non-deterministic outputs)
        results['molecules']['mlkem768'] = json.dumps({
            'publicKey': public_key,
            'encryptedData': encrypted_data,
            'originalPlaintext': test_config['plaintext'],
            'sdk': 'Python'
        })

        results['tests']['mlkem768'] = {
            'passed': test_passed,
            'publicKeyGenerated': public_key_generated,
            'encryptionSuccess': encryption_success,
            'decryptionSuccess': decryption_success,
            'plaintextLength': len(test_config['plaintext'])
        }

        return test_passed

    except Exception as e:
        log(f"  ❌ ERROR: {str(e)}", 'red')
        results['tests']['mlkem768'] = {
            'passed': False,
            'error': str(e)
        }
        return False


def test_negative_cases() -> bool:
    """Test 6: Negative Test Cases - Anti-Cheating Validation"""
    log('\n6. Negative Test Cases (Anti-Cheating)', 'blue')

    test_config = load_config()['tests']['crypto']
    all_negative_tests_passed = True

    try:
        secret = generate_secret(test_config['seed'])
        bundle = generate_bundle_hash(secret)

        source_wallet = Wallet(
            secret=secret,
            token='TEST',
            position='0123456789abcdeffedcba9876543210fedcba9876543210fedcba9876543210'
        )
        source_wallet.balance = 1000

        # Test 1: Missing Molecular Hash (should fail)
        try:
            invalid_molecule = Molecule(
                secret=secret,
                bundle=bundle,
                source_wallet=source_wallet
            )

            # Add a valid atom but don't sign (no molecular hash)
            from knishioclient.models.Atom import Atom
            atom = Atom(
                position=source_wallet.position,
                wallet_address=source_wallet.address,
                isotope='V',
                token='TEST',
                value=-100
            )
            invalid_molecule.atoms.append(atom)

            # This should fail because there's no molecular hash
            should_fail = invalid_molecule.check(source_wallet)
            if should_fail:
                log_test('Missing molecular hash validation (should FAIL)', False, 'Invalid molecule passed validation')
                all_negative_tests_passed = False
            else:
                log_test('Missing molecular hash validation (should FAIL)', True)
        except Exception:
            # Exception is expected for missing molecular hash
            log_test('Missing molecular hash validation (should FAIL)', True)

        # Test 2: Invalid Molecular Hash (should fail)
        try:
            invalid_molecule = Molecule(
                secret=secret,
                bundle=bundle,
                source_wallet=source_wallet
            )

            atom = Atom(
                position=source_wallet.position,
                wallet_address=source_wallet.address,
                isotope='V',
                token='TEST',
                value=-100
            )
            invalid_molecule.atoms.append(atom)

            # Sign normally
            invalid_molecule.sign()

            # Then corrupt the molecular hash
            invalid_molecule.molecular_hash = 'invalid_hash_that_should_fail_validation_check_12345678'

            should_fail = invalid_molecule.check(source_wallet)
            if should_fail:
                log_test('Invalid molecular hash validation (should FAIL)', False, 'Corrupted molecule passed validation')
                all_negative_tests_passed = False
            else:
                log_test('Invalid molecular hash validation (should FAIL)', True)
        except Exception:
            # Exception is expected for invalid molecular hash
            log_test('Invalid molecular hash validation (should FAIL)', True)

        # Test 3: Unbalanced Transfer (should fail)
        try:
            invalid_molecule = Molecule(
                secret=secret,
                bundle=bundle,
                source_wallet=source_wallet
            )

            # Create unbalanced atoms (doesn't sum to zero)
            debit_atom = Atom(
                position=source_wallet.position,
                wallet_address=source_wallet.address,
                isotope='V',
                token='TEST',
                value=-1000  # Debit full balance
            )
            invalid_molecule.atoms.append(debit_atom)

            credit_atom = Atom(
                position=source_wallet.position,
                wallet_address=source_wallet.address,
                isotope='V',
                token='TEST',
                value=500    # Credit only half - unbalanced!
            )
            invalid_molecule.atoms.append(credit_atom)

            invalid_molecule.sign()

            should_fail = invalid_molecule.check(source_wallet)
            if should_fail:
                log_test('Unbalanced transfer validation (should FAIL)', False, 'Unbalanced molecule passed validation')
                all_negative_tests_passed = False
            else:
                log_test('Unbalanced transfer validation (should FAIL)', True)
        except Exception:
            # Exception is expected for unbalanced transfers
            log_test('Unbalanced transfer validation (should FAIL)', True)

        results['tests']['negativeCases'] = {
            'passed': all_negative_tests_passed,
            'description': 'Anti-cheating validation tests',
            'testCount': 3
        }

        return all_negative_tests_passed

    except Exception as e:
        log(f'  ❌ ERROR: {str(e)}', 'red')
        results['tests']['negativeCases'] = {
            'passed': False,
            'error': str(e)
        }
        return False


def test_cross_sdk_validation() -> bool:
    """Test 7: Cross-SDK Validation"""
    log('\n7. Cross-SDK Validation', 'blue')

    # Check if cross-validation is disabled (Round 1 molecule generation only)
    if os.environ.get('KNISHIO_DISABLE_CROSS_VALIDATION') == 'true':
        log('  ⏭️  Cross-validation disabled for Round 1 (molecule generation only)', 'yellow')
        return True

    shared_results_dir = os.environ.get('KNISHIO_SHARED_RESULTS', '../shared-test-results')
    results_dir = Path(shared_results_dir).resolve()

    if not results_dir.exists():
        log('  ⏭️  No other SDK results found for cross-validation', 'yellow')
        return True

    result_files = [f for f in results_dir.glob('*.json')
                   if 'python' not in f.name.lower()]

    if not result_files:
        log('  ⏭️  No other SDK results found for cross-validation', 'yellow')
        return True

    all_valid = True

    for file_path in result_files:
        sdk_name = file_path.stem.replace('-results', '')

        try:
            with open(file_path, 'r') as f:
                other_results = json.load(f)

            molecules = other_results.get('molecules', {})

            for molecule_type, molecule_data in molecules.items():
                try:
                    if molecule_type == 'mlkem768':
                        # Special handling for ML-KEM768 cross-SDK compatibility
                        mlkem_data = json.loads(molecule_data)

                        # Create our own encryption wallet using the same configuration
                        test_config = load_config()['tests']['mlkem768']
                        secret = generate_secret(test_config['seed'])
                        bundle = generate_bundle_hash(secret)
                        our_wallet = Wallet(
                            secret=secret,
                            bundle=bundle,
                            token=test_config['token'],
                            position=test_config['position']
                        )

                        mlkem_valid = False
                        try:
                            # Test: Can we encrypt a message for their public key?
                            test_message = "Cross-SDK ML-KEM768 compatibility test"
                            encrypted_for_them = our_wallet.encrypt_message(
                                test_message,
                                mlkem_data['publicKey']
                            )

                            # If encryption succeeded, that means their public key format is compatible
                            mlkem_valid = bool(encrypted_for_them and
                                             encrypted_for_them.get('cipherText') and
                                             encrypted_for_them.get('encryptedMessage'))

                            if mlkem_valid:
                                log(f"    Successfully encrypted for {sdk_name} public key", 'green')

                        except Exception as e:
                            log(f"    Failed to encrypt for {sdk_name}: {str(e)}", 'red')
                            mlkem_valid = False

                        log_test(f'{sdk_name} {molecule_type} encryption compatibility', mlkem_valid)

                        if not mlkem_valid:
                            all_valid = False
                    else:
                        # Standard molecule validation for non-ML-KEM768 types
                        molecule = Molecule.from_json(
                            molecule_data,
                            include_validation_context=True,
                            validate_structure=True
                        )

                        # Source wallet is automatically reconstructed by from_json() method
                        source_wallet = getattr(molecule, 'sourceWallet', None)

                        # Validate using check method
                        is_valid = False
                        try:
                            is_valid = molecule.check(source_wallet)
                        except Exception as e:
                            log(f"    Validation error: {str(e)}", 'red')
                            is_valid = False

                        log_test(f'{sdk_name} {molecule_type} molecule validation', is_valid)

                        if not is_valid:
                            all_valid = False

                except Exception as e:
                    log_test(f'{sdk_name} {molecule_type} validation', False)
                    log(f"    Error: {str(e)}", 'red')
                    all_valid = False

        except Exception as e:
            log(f"  ❌ Failed to load {sdk_name} results: {str(e)}", 'red')

    results['crossSdkCompatible'] = all_valid
    return all_valid


def save_results():
    """Save test results to file"""
    shared_results_dir = os.environ.get('KNISHIO_SHARED_RESULTS', '../shared-test-results')
    results_dir = Path(shared_results_dir).resolve()
    results_dir.mkdir(parents=True, exist_ok=True)

    results_file = results_dir / 'python-results.json'

    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)

    log(f'\n📁 Results saved to: {results_file}', 'blue')


def print_summary():
    """Print test summary report"""
    log('\n' + '=' * 43, 'blue')
    log('            TEST SUMMARY REPORT', 'blue')
    log('=' * 43, 'blue')

    total_tests = len(results['tests'])
    passed_tests = sum(1 for t in results['tests'].values() if t.get('passed', False))

    log(f"\nSDK: {results['sdk']} v{results['version']}")
    log(f"Timestamp: {results['timestamp']}")

    color = 'green' if passed_tests == total_tests else 'red'
    log(f"\nTests Passed: {passed_tests}/{total_tests}", color)

    status = '✅ YES' if results['crossSdkCompatible'] else '❌ NO'
    color = 'green' if results['crossSdkCompatible'] else 'red'
    log(f"\nCross-SDK Compatible: {status}", color)

    log('\n' + '=' * 43, 'blue')


def main():
    """Main test runner"""

    # Set timestamp first
    results['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    # Check for cross-validation-only mode (Round 2)
    if os.environ.get('KNISHIO_CROSS_VALIDATION_ONLY') == 'true':
        log('=' * 43, 'blue')
        log('    Knish.IO Python SDK Cross-Validation Only', 'blue')
        log('=' * 43, 'blue')

        # Load existing Round 1 results before cross-validation
        shared_dir = os.environ.get('KNISHIO_SHARED_RESULTS', '../shared-test-results')
        existing_path = Path(shared_dir).resolve() / 'python-results.json'

        if existing_path.exists():
            try:
                with open(existing_path, 'r') as f:
                    existing_data = json.load(f)

                # Preserve tests
                if 'tests' in existing_data:
                    results['tests'].update(existing_data['tests'])

                # Preserve molecules
                if 'molecules' in existing_data:
                    results['molecules'].update(existing_data['molecules'])

                log('✅ Preserved Round 1 molecules for cross-validation', 'green')
            except Exception as e:
                log(f'⚠️  Could not load existing results: {str(e)}', 'yellow')

        # Only run cross-SDK validation
        cross_sdk_result = test_cross_sdk_validation()

        # Save results and print summary (cross-validation only)
        save_results()
        log('\n' + '=' * 43, 'blue')
        log('            CROSS-VALIDATION SUMMARY', 'blue')
        log('=' * 43, 'blue')
        compat_status = '✅ YES' if cross_sdk_result else '❌ NO'
        compat_color = 'green' if cross_sdk_result else 'red'
        log(f'Cross-SDK Compatible: {compat_status}', compat_color)
        log('=' * 43, 'blue')

        # Exit based on cross-validation results only
        sys.exit(0 if cross_sdk_result else 1)

    # Normal mode: Run all tests (Round 1 or standalone)
    log('=' * 43, 'blue')
    log('    Knish.IO Python SDK Self-Test', 'blue')
    log('=' * 43, 'blue')

    # Set timestamp
    results['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    # Load configuration
    config = load_config()

    # Run tests
    test_crypto(config)
    test_metadata_creation(config)
    test_simple_transfer(config)
    test_complex_transfer(config)
    test_mlkem768(config)
    test_negative_cases()
    test_cross_sdk_validation()

    # Save results and print summary
    save_results()
    print_summary()

    # Exit with appropriate code
    all_passed = all(t.get('passed', False) for t in results['tests'].values())
    sys.exit(0 if (all_passed and results['crossSdkCompatible']) else 1)


if __name__ == '__main__':
    main()