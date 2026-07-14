# -*- coding: utf-8 -*-
"""
Cross-Platform Vector Validation for the KnishIO Python SDK
===========================================================
Validates the Python SDK against the shared cross-platform-test-vectors.json
(the cross-SDK master): SHAKE256 / bundle_hash / wallet_generation / ML-KEM768.

Sibling of the family's cross-platform tests (JS cross-platform-canonical.test.js,
TS cross-platform-canonical.test.ts, PHP/Kotlin CrossPlatformVectorsTest, Rust
cross_platform_vectors.rs) — one of the two unified cross-SDK vector tests every
package shares (the other is test_patent_vectors.py over canonical-patent-vectors.json).

Vector source: tests/fixtures/cross-platform-test-vectors.json (vendored copy of the
monorepo master, so this runs in a standalone checkout).
"""

import json
import sys
import unittest
from pathlib import Path

# Ensure the SDK root is importable
SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if SDK_ROOT not in sys.path:
    sys.path.insert(0, SDK_ROOT)

from knishioclient.libraries import crypto
from knishioclient.models.Wallet import Wallet


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------
VECTORS_PATH = Path(__file__).parent / "fixtures" / "cross-platform-test-vectors.json"


def _load_vectors():
    """Load the cross-platform test vectors once."""
    with open(VECTORS_PATH, "r") as fh:
        return json.load(fh)["vectors"]


VECTORS = _load_vectors()


class Shake256VectorTest(unittest.TestCase):
    def test_shake256(self):
        for v in VECTORS["shake256"]["tests"]:
            with self.subTest(name=v["name"]):
                # vector outputLength is in BYTES; Python shake256() takes BITS
                self.assertEqual(
                    v["expected"],
                    crypto.shake256(v["input"], v["outputLength"] * 8),
                    f"SHAKE256 mismatch for vector: {v['name']}",
                )


class BundleHashVectorTest(unittest.TestCase):
    def test_bundle_hash(self):
        for v in VECTORS["bundle_hash"]["tests"]:
            with self.subTest(name=v["name"]):
                self.assertEqual(
                    v["expected"],
                    crypto.generate_bundle_hash(v["secret"]),
                    f"Bundle hash mismatch for vector: {v['name']}",
                )


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


class WalletAddressVectorTest(unittest.TestCase):
    def test_wallet_address(self):
        # FIXED (cycle 142): Wallet.generate_key() now normalizes a non-hex secret/position via
        # shake256 (isHex(s) ? s : shake256(s)), mirroring JS/TS/Rust — so the arbitrary-string
        # vectors (user_wallet='test-user-secret' / bitcoin_wallet='btc-wallet-secret') derive a
        # wallet address byte-identically. ALL wallet_generation cases are asserted, no filter.
        for v in VECTORS["wallet_generation"]["tests"]:
            with self.subTest(name=v["name"]):
                self.assertEqual(
                    v["expectedBundle"],
                    crypto.generate_bundle_hash(v["secret"]),
                    f"Bundle hash mismatch for wallet: {v['name']}",
                )
                wallet = Wallet(secret=v["secret"], token=v["token"], position=v["position"])
                self.assertEqual(
                    v["expectedAddress"],
                    wallet.address,
                    f"Wallet address mismatch for wallet: {v['name']}",
                )


class Mlkem768VectorTest(unittest.TestCase):
    # Keygen-from-seed is deterministic (FIPS-203) → byte-frozen pubkey, like a SHAKE vector.
    def test_mlkem768_keygen(self):
        v = VECTORS["mlkem768"]["keygen"]
        wallet = Wallet(secret=v["secret"], token=v["token"], position=v["position"])
        self.assertEqual(v["expectedPubkey"], wallet.pubkey, "ML-KEM768 keygen pubkey mismatch")

    # Encapsulation is non-deterministic, but decapsulation + AES-256-GCM decrypt is deterministic →
    # one frozen {cipherText, encryptedMessage} sample must decrypt to the canonical plaintext.
    def test_mlkem768_decrypt(self):
        v = VECTORS["mlkem768"]["decrypt"]
        wallet = Wallet(secret=v["secret"], token=v["token"], position=v["position"])
        plaintext = wallet.decrypt_message(
            {"cipherText": v["cipherText"], "encryptedMessage": v["encryptedMessage"]}
        )
        self.assertEqual(v["expectedPlaintext"], plaintext, "ML-KEM768 decrypt plaintext mismatch")

    # PQ-transport hardening: a stale/non-PQ validator advertises a ~48-byte `key`; encrypt_message
    # must fail with an actionable error, not a cryptic bridge crash.
    def test_mlkem768_encrypt_rejects_non_1184_key(self):
        v = VECTORS["mlkem768"]["keygen"]
        wallet = Wallet(secret=v["secret"], token=v["token"], position=v["position"])
        short_key = Wallet.serialize_key(bytes(48))
        with self.assertRaises(ValueError) as ctx:
            wallet.encrypt_message({"q": 1}, short_key)
        self.assertIn("expected 1184 (ML-KEM-768)", str(ctx.exception))


class NaClVectorTest(unittest.TestCase):
    """Classical NaCl (X25519 scalarmult_base + crypto_box/secretbox + sealed-box),
    byte-frozen against the reference tweetnacl. libnacl (ctypes → libsodium) must
    reproduce these byte-for-byte, proving classical cross-SDK parity."""

    def test_nacl_scalarmult_base(self):
        import base64, libnacl
        for v in VECTORS["nacl"]["scalarMultBase"]:
            with self.subTest(sk=v["secretKeyHex"][:8]):
                pk = libnacl.crypto_scalarmult_base(bytes.fromhex(v["secretKeyHex"]))
                self.assertEqual(
                    v["expectedPublicKey"], base64.b64encode(pk).decode(),
                    "X25519 scalarmult_base mismatch",
                )

    def test_nacl_crypto_box(self):
        import base64, libnacl
        v = VECTORS["nacl"]["cryptoBox"]
        boxed = libnacl.crypto_box(
            v["plaintext"].encode(),
            base64.b64decode(v["nonce"]),
            base64.b64decode(v["recipientPublicKey"]),
            bytes.fromhex(v["senderSecretKeyHex"]),
        )
        self.assertEqual(
            v["expectedBox"], base64.b64encode(boxed).decode(),
            "crypto_box ciphertext mismatch",
        )

    def test_nacl_sealed_box_open(self):
        import base64, libnacl
        v = VECTORS["nacl"]["sealedBox"]
        pt = libnacl.crypto_box_seal_open(
            base64.b64decode(v["sealed"]),
            base64.b64decode(v["recipientPublicKey"]),
            bytes.fromhex(v["recipientSecretKeyHex"]),
        )
        self.assertEqual(v["expectedPlaintext"], pt.decode(), "sealed-box open mismatch")


if __name__ == "__main__":
    unittest.main()
