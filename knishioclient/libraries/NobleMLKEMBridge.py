# -*- coding: utf-8 -*-
"""
NobleMLKEMBridge - Python bridge to @noble/post-quantum via Node.js subprocess

This module provides a bridge between Python and the JavaScript @noble/post-quantum
library, ensuring 100% compatibility with the JavaScript SDK's ML-KEM implementation.

This is a proven pattern also used by the PHP SDK to guarantee cross-SDK compatibility.
"""

import json
import shutil
import subprocess
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

        # Find Node.js command (shutil.which also works where there is no `which`, e.g. Windows)
        for cmd in ('node', 'nodejs'):
            found = shutil.which(cmd)
            if found:
                cls._node_command = found
                break

        if cls._node_command is None:
            raise RuntimeError(
                'Node.js not found. Please install Node.js to use ML-KEM cryptography. '
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
    def _execute_command(cls, command: str, args: list) -> Dict:
        """
        Execute bridge command via Node.js subprocess.

        The request travels as one JSON object on the child's stdin, never in its argv: seeds and
        secret keys in argv are readable by every local user (ps, /proc/<pid>/cmdline).

        Args:
            command: 'keygen', 'encaps' or 'decaps'
            args: Command arguments (e.g., [seedHex, '1024'])

        Returns:
            Decoded JSON response from bridge

        Raises:
            RuntimeError: If command fails or returns error. The message never contains the
                request or the bridge's stdout, which may hold key material.
        """
        cls._initialize()

        try:
            result = subprocess.run(
                [cls._node_command, str(cls._bridge_script)],
                input=json.dumps({'command': command, 'args': [str(arg) for arg in args]}),
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f'Noble ML-KEM bridge {command} timed out after 30 seconds')
        except Exception as e:
            raise RuntimeError(f'Failed to execute Noble ML-KEM bridge {command}: {type(e).__name__}')

        try:
            response = json.loads(result.stdout.strip()) if result.returncode == 0 else None
        except json.JSONDecodeError:
            response = None

        if not isinstance(response, dict):
            # The bridge reports failures as {"error": message} on stderr
            try:
                error_msg = json.loads(result.stderr.strip()).get('error')
            except (ValueError, AttributeError):
                error_msg = None
            raise RuntimeError(
                f'Noble ML-KEM bridge {command} failed (exit code: {result.returncode}): '
                f'{error_msg or "no error message"}'
            )

        if 'error' in response:
            raise RuntimeError(f'Noble ML-KEM error: {response["error"]}')

        return response

    @classmethod
    def generate_keypair_from_seed(cls, seed_hex: str, param_set: int | str = 1024) -> Tuple[bytes, bytes]:
        """
        Generate ML-KEM key pair from seed (deterministic).

        Uses JavaScript @noble/post-quantum library to ensure exact compatibility
        with JavaScript SDK implementation.

        Args:
            seed_hex: 128 hex characters (64 bytes)
            param_set: ML-KEM parameter set (1024 or 768)

        Returns:
            Tuple of (public_key, secret_key) as bytes

        Raises:
            ValueError: If seed is invalid
            RuntimeError: If bridge command fails
        """
        if len(seed_hex) != 128:
            raise ValueError('Seed must be exactly 128 hex characters')

        result = cls._execute_command('keygen', [seed_hex, str(param_set)])

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

        result = cls._execute_command('encaps', [public_key_b64])

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

        result = cls._execute_command('decaps', [ciphertext_b64, secret_key_b64])

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
