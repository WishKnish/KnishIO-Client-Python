# -*- coding: utf-8 -*-
"""
NobleMLKEMBridge - Python bridge to @noble/post-quantum via Node.js subprocess

This module provides a bridge between Python and the JavaScript @noble/post-quantum
library, ensuring 100% compatibility with the JavaScript SDK's ML-KEM-768 implementation.

This is a proven pattern also used by the PHP SDK to guarantee cross-SDK compatibility.
"""

import json
import subprocess
import os
from pathlib import Path
from typing import Dict, Tuple, Optional


class NobleMLKEMBridge:
    """
    Bridge to @noble/post-quantum JavaScript library via Node.js subprocess.

    Ensures 100% cryptographic compatibility with all other SDKs by using
    the exact same @noble/post-quantum implementation.
    """

    _node_command: Optional[str] = None
    _bridge_script: Optional[Path] = None
    _initialized: bool = False

    @classmethod
    def _initialize(cls) -> None:
        """Initialize bridge configuration and verify dependencies."""
        if cls._initialized:
            return

        # Find Node.js command
        node_commands = ['node', 'nodejs']
        for cmd in node_commands:
            try:
                result = subprocess.run(
                    ['which', cmd],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    cls._node_command = result.stdout.strip()
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        if cls._node_command is None:
            raise RuntimeError(
                'Node.js not found. Please install Node.js to use ML-KEM-768 cryptography. '
                'Visit https://nodejs.org/ for installation instructions.'
            )

        # Find bridge script
        module_dir = Path(__file__).parent.parent.parent  # Go up to KnishIO-Client-Python/
        possible_paths = [
            module_dir / 'bin' / 'noble-mlkem-bridge.js',
            module_dir / 'knishioclient' / 'bin' / 'noble-mlkem-bridge.js',
        ]

        for path in possible_paths:
            if path.exists():
                cls._bridge_script = path.resolve()
                break

        if cls._bridge_script is None:
            raise RuntimeError(
                f'Noble ML-KEM bridge script not found. Expected at: {possible_paths[0]}'
            )

        # Verify @noble/post-quantum is installed (check bin/node_modules)
        bin_node_modules_path = cls._bridge_script.parent / 'node_modules' / '@noble' / 'post-quantum'

        if not bin_node_modules_path.exists():
            package_dir = cls._bridge_script.parent
            raise RuntimeError(
                f'@noble/post-quantum not installed. Please run:\n'
                f'  cd {package_dir}\n'
                f'  npm install'
            )

        cls._initialized = True

    @classmethod
    def _execute_command(cls, args: list) -> Dict:
        """
        Execute bridge command via Node.js subprocess.

        Args:
            args: Command arguments (e.g., ['keygen', seedHex])

        Returns:
            Decoded JSON response from bridge

        Raises:
            RuntimeError: If command fails or returns error
        """
        cls._initialize()

        # Build command
        command = [cls._node_command, str(cls._bridge_script)] + args

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError('Noble ML-KEM bridge command timed out after 30 seconds')
        except Exception as e:
            raise RuntimeError(f'Failed to execute Noble ML-KEM bridge: {e}')

        # Parse output - look for JSON in stdout
        output_lines = result.stdout.strip().split('\n')
        json_line = None

        for line in output_lines:
            if line.startswith('{'):
                json_line = line
                break

        if json_line is None:
            # Try parsing entire output as JSON
            json_line = result.stdout.strip()

        # Parse JSON response
        try:
            response = json.loads(json_line) if json_line else None
        except json.JSONDecodeError:
            response = None

        # Check for errors
        if result.returncode != 0 or response is None:
            error_msg = response.get('error') if isinstance(response, dict) else None
            if error_msg:
                raise RuntimeError(f'Noble ML-KEM bridge error: {error_msg}')

            stderr_output = result.stderr.strip() if result.stderr else 'No error output'
            raise RuntimeError(
                f'Noble ML-KEM bridge command failed (exit code: {result.returncode})\n'
                f'Command: {" ".join(command)}\n'
                f'Stdout: {result.stdout}\n'
                f'Stderr: {stderr_output}'
            )

        if isinstance(response, dict) and 'error' in response:
            raise RuntimeError(f'Noble ML-KEM error: {response["error"]}')

        return response

    @classmethod
    def generate_keypair_from_seed(cls, seed_hex: str) -> Tuple[bytes, bytes]:
        """
        Generate ML-KEM-768 key pair from seed (deterministic).

        Uses JavaScript @noble/post-quantum library to ensure exact compatibility
        with JavaScript SDK implementation.

        Args:
            seed_hex: 128 hex characters (64 bytes)

        Returns:
            Tuple of (public_key, secret_key) as bytes

        Raises:
            ValueError: If seed is invalid
            RuntimeError: If bridge command fails
        """
        if len(seed_hex) != 128:
            raise ValueError('Seed must be exactly 128 hex characters for ML-KEM-768')

        result = cls._execute_command(['keygen', seed_hex])

        if 'publicKey' not in result or 'secretKey' not in result:
            raise RuntimeError('Invalid response from Noble ML-KEM bridge: missing keys')

        import base64
        public_key = base64.b64decode(result['publicKey'])
        secret_key = base64.b64decode(result['secretKey'])

        return public_key, secret_key

    @classmethod
    def encapsulate(cls, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate - generate shared secret and ciphertext from public key.

        This is used for key exchange - the sender uses the recipient's public key
        to generate a shared secret and encrypted ciphertext.

        Args:
            public_key: Public key bytes

        Returns:
            Tuple of (ciphertext, shared_secret) as bytes

        Raises:
            RuntimeError: If bridge command fails
        """
        import base64
        public_key_b64 = base64.b64encode(public_key).decode('utf-8')

        result = cls._execute_command(['encaps', public_key_b64])

        if 'ciphertext' not in result or 'sharedSecret' not in result:
            raise RuntimeError('Invalid response from Noble ML-KEM bridge: missing encapsulation data')

        ciphertext = base64.b64decode(result['ciphertext'])
        shared_secret = base64.b64decode(result['sharedSecret'])

        return ciphertext, shared_secret

    @classmethod
    def decapsulate(cls, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate - recover shared secret from ciphertext using secret key.

        This is used by the recipient to recover the shared secret from the
        ciphertext using their private key.

        Args:
            ciphertext: Ciphertext bytes
            secret_key: Secret key bytes

        Returns:
            Shared secret as bytes

        Raises:
            RuntimeError: If bridge command fails
        """
        import base64
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        secret_key_b64 = base64.b64encode(secret_key).decode('utf-8')

        result = cls._execute_command(['decaps', ciphertext_b64, secret_key_b64])

        if 'sharedSecret' not in result:
            raise RuntimeError('Invalid response from Noble ML-KEM bridge: missing shared secret')

        shared_secret = base64.b64decode(result['sharedSecret'])

        return shared_secret

    @classmethod
    def is_available(cls) -> bool:
        """
        Check if Noble ML-KEM bridge is available.

        Returns:
            True if bridge is available, False otherwise
        """
        try:
            cls._initialize()
            return True
        except Exception:
            return False

    @classmethod
    def get_status(cls) -> Dict:
        """
        Get bridge status and version information.

        Returns:
            Dictionary with status information
        """
        try:
            cls._initialize()

            # Get Node.js version
            try:
                result = subprocess.run(
                    [cls._node_command, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                node_version = result.stdout.strip() if result.returncode == 0 else 'unknown'
            except Exception:
                node_version = 'unknown'

            return {
                'available': True,
                'nodeCommand': cls._node_command,
                'nodeVersion': node_version,
                'bridgeScript': str(cls._bridge_script),
                'method': 'Node.js subprocess bridge to @noble/post-quantum'
            }
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }
