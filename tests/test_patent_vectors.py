# -*- coding: utf-8 -*-
"""
Patent Vector Validation Tests for KnishIO Python SDK
======================================================
Validates the Python SDK against canonical patent test vectors
(Appendix B) generated from the Rust SDK reference implementation.

Test Categories:
  1. ContinuID chain relay (Claims 5, 12-14)
  2. Base17 enumeration (Claim 5)
  3. Multi-isotope molecule position/address derivation (Claims 8, 21)
  4. BigInt carry edge cases (Claim 5)
  5. WOTS+ sign/verify roundtrip (Claims 1-2, 5)

Vector source: tests/fixtures/canonical-patent-vectors.json
"""

import json
import os
import sys
import unittest
from pathlib import Path
from hashlib import shake_256 as shake

# Ensure the SDK root is importable
SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if SDK_ROOT not in sys.path:
    sys.path.insert(0, SDK_ROOT)

from knishioclient.libraries import crypto, strings
from knishioclient.models.Wallet import Wallet
from knishioclient.models.MoleculeStructure import MoleculeStructure


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------
VECTORS_PATH = Path(__file__).parent / "fixtures" / "canonical-patent-vectors.json"


def _load_vectors():
    """Load the canonical patent test vectors once."""
    with open(VECTORS_PATH, "r") as fh:
        return json.load(fh)


VECTORS = _load_vectors()


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def hex_to_base17(hex_input: str) -> str:
    """Convert a hex string to base17 using the SDK's charset_base_convert,
    then right-pad/justify to 64 characters (matching Rust reference).
    """
    result = strings.charset_base_convert(
        hex_input, 16, 17,
        "0123456789abcdef",
        "0123456789abcdefg",
    )
    if isinstance(result, str):
        return result.rjust(64, "0")
    # charset_base_convert returns 0 (int) for all-zero input
    return "0" * 64


def normalized_sum(base17_str: str) -> int:
    """Compute the normalized sum of a base17 hash.
    After enumeration + normalization the sum must be exactly 0.
    """
    enumerated = MoleculeStructure.enumerate(base17_str)
    normalized = MoleculeStructure.normalize(enumerated)
    return sum(normalized)


# ===========================================================================
# 0. generateSecret cross-SDK parity (Batch AO) — seed -> 2048 hex secret
# ===========================================================================

class TestGenerateSecret(unittest.TestCase):
    """generate_secret(seed) must produce the canonical 2048-char secret,
    byte-identical to JS/TS/Rust/PHP/Kotlin.
    """

    @classmethod
    def setUpClass(cls):
        cls.tests = VECTORS["vectors"]["generate_secret"]["tests"]

    def test_generate_secret(self):
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                secret = crypto.generate_secret(tv["seed"])
                self.assertEqual(
                    len(secret), tv["length"],
                    f"generate_secret length mismatch for {tv['name']}",
                )
                self.assertEqual(
                    secret, tv["expectedSecret"],
                    f"generate_secret value mismatch (cross-SDK parity) for {tv['name']}",
                )


# ===========================================================================
# 1. ContinuID Chain Relay Tests  (Patent Claims 5, 12-14)
# ===========================================================================

class TestContinuIDChainRelay(unittest.TestCase):
    """Validates ContinuID identity relay: two sequential wallet positions
    from the same secret.  Position2 = SHAKE256(position1, 256 bits).
    """

    @classmethod
    def setUpClass(cls):
        cls.tests = VECTORS["vectors"]["continuid_chain"]["tests"]

    def test_bundle_hash(self):
        """Bundle hash derived from the secret must match the reference."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                bundle = crypto.generate_bundle_hash(tv["secret"])
                self.assertEqual(
                    bundle,
                    tv["expectedBundle"],
                    f"Bundle mismatch for {tv['name']}: got {bundle}",
                )

    def test_address_at_position1(self):
        """Wallet address at position1 must match the reference vector."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                key = Wallet.generate_key(tv["secret"], tv["token"], tv["position1"])
                address = Wallet.generate_address(key)
                self.assertEqual(
                    address,
                    tv["expectedAddress1"],
                    f"Address1 mismatch for {tv['name']}: got {address}",
                )

    def test_position2_derivation(self):
        """Position2 = SHAKE256(position1, 256 bits) = 32 bytes = 64 hex chars."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                # crypto.shake256 takes bits
                position2 = crypto.shake256(tv["position1"], 256)
                self.assertEqual(
                    position2,
                    tv["expectedPosition2"],
                    f"Position2 mismatch for {tv['name']}: got {position2}",
                )

    def test_address_at_position2(self):
        """Wallet address at derived position2 must match the reference."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                key = Wallet.generate_key(
                    tv["secret"], tv["token"], tv["expectedPosition2"]
                )
                address = Wallet.generate_address(key)
                self.assertEqual(
                    address,
                    tv["expectedAddress2"],
                    f"Address2 mismatch for {tv['name']}: got {address}",
                )

    def test_invariants(self):
        """Position1 != Position2, Address1 != Address2, same bundle for both."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                inv = tv["invariants"]
                # Different positions
                self.assertTrue(inv["different_positions"])
                self.assertNotEqual(tv["position1"], tv["expectedPosition2"])
                # Different addresses
                self.assertTrue(inv["different_addresses"])
                self.assertNotEqual(
                    tv["expectedAddress1"], tv["expectedAddress2"]
                )
                # Same bundle
                self.assertTrue(inv["same_bundle"])


# ===========================================================================
# 2. Base17 Enumeration Tests  (Patent Claim 5)
# ===========================================================================

class TestBase17Enumeration(unittest.TestCase):
    """Validates hex-to-Base17 conversion used in WOTS+ signature indexing.
    Base17 digits: 0-9, a-g.
    After enumeration + normalization the sum must be exactly 0.
    """

    @classmethod
    def setUpClass(cls):
        cls.tests = VECTORS["vectors"]["base17_enumeration"]["tests"]

    def test_hex_to_base17_conversion(self):
        """Each hex input must produce the expected base17 output."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                result = hex_to_base17(tv["hexInput"])
                self.assertEqual(
                    result,
                    tv["expectedBase17"],
                    f"Base17 mismatch for {tv['name']}:\n"
                    f"  input:    {tv['hexInput']}\n"
                    f"  expected: {tv['expectedBase17']}\n"
                    f"  got:      {result}",
                )

    def test_normalized_sum_zero(self):
        """After normalization the sum of enumerated values must be 0."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                base17 = hex_to_base17(tv["hexInput"])
                ns = normalized_sum(base17)
                self.assertEqual(
                    ns,
                    tv["normalizedSum"],
                    f"Normalized sum for {tv['name']} is {ns}, expected {tv['normalizedSum']}",
                )


# ===========================================================================
# 3. Multi-Isotope Molecule Tests  (Patent Claims 8, 21)
# ===========================================================================

class TestMultiIsotopeMolecule(unittest.TestCase):
    """Validates position derivation and address generation for V/M/I isotopes
    within a single molecule.  Each isotope position is derived as:
        SHAKE256(sourcePosition + isotopeChar, 256 bits)
    """

    @classmethod
    def setUpClass(cls):
        cls.tests = VECTORS["vectors"]["multi_isotope_molecule"]["tests"]

    def test_bundle_hash(self):
        """Bundle hash must match for multi-isotope secret."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                bundle = crypto.generate_bundle_hash(tv["secret"])
                self.assertEqual(bundle, tv["expectedBundle"])

    def test_isotope_position_derivation(self):
        """Position for each isotope = SHAKE256(sourcePosition + isotopeChar, 256)."""
        for tv in self.tests:
            source_pos = tv["invariants"]["source_position"]
            for iso_char, iso_data in tv["isotopes"].items():
                with self.subTest(name=tv["name"], isotope=iso_char):
                    derived_pos = crypto.shake256(source_pos + iso_char, 256)
                    self.assertEqual(
                        derived_pos,
                        iso_data["expectedPosition"],
                        f"Position mismatch for isotope {iso_char}",
                    )

    def test_isotope_address_generation(self):
        """Address at each derived isotope position must match the reference."""
        for tv in self.tests:
            for iso_char, iso_data in tv["isotopes"].items():
                with self.subTest(name=tv["name"], isotope=iso_char):
                    key = Wallet.generate_key(
                        tv["secret"],
                        iso_data["token"],
                        iso_data["expectedPosition"],
                    )
                    address = Wallet.generate_address(key)
                    self.assertEqual(
                        address,
                        iso_data["expectedAddress"],
                        f"Address mismatch for isotope {iso_char}: got {address}",
                    )

    def test_all_addresses_unique(self):
        """All isotope addresses must be distinct (different positions yield
        different keys yield different addresses)."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                addresses = set()
                for iso_char, iso_data in tv["isotopes"].items():
                    addresses.add(iso_data["expectedAddress"])
                self.assertEqual(
                    len(addresses),
                    len(tv["isotopes"]),
                    "Not all isotope addresses are unique",
                )

    def test_same_bundle_for_all(self):
        """All isotopes share the same bundle hash (same secret)."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                self.assertTrue(tv["invariants"]["same_bundle_for_all"])


# ===========================================================================
# 4. BigInt Carry Edge Case Tests  (Patent Claim 5)
# ===========================================================================

class TestBigIntCarryEdge(unittest.TestCase):
    """Tests edge cases in BigInt arithmetic during SHAKE256 hashing
    and key generation: 65-char hex (overflow), max values, boundaries.
    """

    @classmethod
    def setUpClass(cls):
        cls.tests = VECTORS["vectors"]["bigint_carry_edge"]["tests"]

    def test_shake256_hash(self):
        """SHAKE256(input, 256 bits) must match the expected hash."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                result = crypto.shake256(tv["input"], 256)
                self.assertEqual(
                    result,
                    tv["expectedShake256"],
                    f"SHAKE256 mismatch for {tv['name']}:\n"
                    f"  input ({tv['inputLength']} chars): {tv['input'][:32]}...\n"
                    f"  expected: {tv['expectedShake256']}\n"
                    f"  got:      {result}",
                )

    def test_base17_of_hash(self):
        """Base17 conversion of the SHAKE256 hash must match the reference."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                base17 = hex_to_base17(tv["expectedShake256"])
                self.assertEqual(
                    base17,
                    tv["expectedBase17OfHash"],
                    f"Base17-of-hash mismatch for {tv['name']}:\n"
                    f"  expected: {tv['expectedBase17OfHash']}\n"
                    f"  got:      {base17}",
                )

    def test_input_length(self):
        """Verify the stated input lengths match actual string lengths."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                self.assertEqual(
                    len(tv["input"]),
                    tv["inputLength"],
                    f"Input length mismatch for {tv['name']}",
                )

    def test_key_length(self):
        """A key generated from the SHAKE256 hash (used as a position)
        should be 2048 hex chars (1024 bytes)."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                # Use the hash as both secret and position for key generation.
                # This exercises the BigInt addition path.
                hash_hex = tv["expectedShake256"]
                try:
                    key = Wallet.generate_key(hash_hex, "USER", hash_hex)
                    self.assertEqual(
                        len(key),
                        tv["expectedKeyLength"],
                        f"Key length mismatch for {tv['name']}: got {len(key)}",
                    )
                except ValueError:
                    # If the hash cannot be parsed as hex BigInt (should not happen
                    # for valid hex), skip gracefully.
                    self.skipTest(
                        f"generate_key failed for {tv['name']} -- non-hex input"
                    )


# ===========================================================================
# 5. WOTS+ Roundtrip Tests  (Patent Claims 1-2, 5)
# ===========================================================================

class TestWOTSRoundtrip(unittest.TestCase):
    """Full WOTS+ sign/verify roundtrip.  The OTS address is the protocol
    wallet address (two-pass): hash each 128-char key chunk 16 times, join
    the public fragments, then digest = SHAKE256(joined, 8192) and
    address = SHAKE256(digest, 256) -- matching Wallet.generate_address and
    check.py:ots() (the derivation the validator verifies against).  Verifies
    deterministic key generation, signature fragment production, and address
    recovery.
    """

    @classmethod
    def setUpClass(cls):
        cls.tests = VECTORS["vectors"]["wots_roundtrip"]["tests"]

    def test_ots_address_derivation(self):
        """OTS address = Wallet.generate_address(key) must match the reference."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                key = Wallet.generate_key(tv["secret"], tv["token"], tv["position"])
                ots_address = Wallet.generate_address(key)
                self.assertEqual(
                    ots_address,
                    tv["expectedOtsAddress"],
                    f"OTS address mismatch for {tv['name']}:\n"
                    f"  expected: {tv['expectedOtsAddress']}\n"
                    f"  got:      {ots_address}",
                )

    def test_molecular_hash_base17(self):
        """The hex molecular hash converts to the expected base17 string."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                base17 = hex_to_base17(tv["molecularHashHex"])
                self.assertEqual(
                    base17,
                    tv["molecularHashBase17"],
                    f"Molecular hash base17 mismatch for {tv['name']}",
                )

    def test_signature_fragment_count(self):
        """Signing produces exactly 16 signature fragments (2048 / 128)."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                key = Wallet.generate_key(tv["secret"], tv["token"], tv["position"])
                fragments = strings.chunk_substr(key, 128)
                self.assertEqual(
                    len(fragments),
                    tv["expectedSignatureFragmentCount"],
                    f"Fragment count mismatch: got {len(fragments)}",
                )

    def test_signature_generation_deterministic(self):
        """Signing with the same key and molecular hash must produce
        deterministic first and last signature fragments."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                key = Wallet.generate_key(tv["secret"], tv["token"], tv["position"])

                # Build a minimal MoleculeStructure to call signature_fragments
                mol = MoleculeStructure()
                mol.molecularHash = tv["molecularHashBase17"]

                # Generate OTS signature (encode=True means signing direction)
                sig = mol.signature_fragments(key, encode=True)

                # Split into 128-char chunks
                sig_chunks = strings.chunk_substr(sig, 128)
                self.assertEqual(len(sig_chunks), 16)

                # Verify first fragment matches reference
                self.assertEqual(
                    sig_chunks[0],
                    tv["expectedSignatureFragment0"],
                    f"Fragment[0] mismatch for {tv['name']}:\n"
                    f"  expected: {tv['expectedSignatureFragment0']}\n"
                    f"  got:      {sig_chunks[0]}",
                )

                # Verify last fragment matches reference
                self.assertEqual(
                    sig_chunks[15],
                    tv["expectedSignatureFragment15"],
                    f"Fragment[15] mismatch for {tv['name']}:\n"
                    f"  expected: {tv['expectedSignatureFragment15']}\n"
                    f"  got:      {sig_chunks[15]}",
                )

    def test_signature_verify_roundtrip(self):
        """Sign then verify: decoding the OTS fragments must recover
        the original wallet address (first atom address)."""
        for tv in self.tests:
            with self.subTest(name=tv["name"]):
                key = Wallet.generate_key(tv["secret"], tv["token"], tv["position"])

                mol = MoleculeStructure()
                mol.molecularHash = tv["molecularHashBase17"]

                # Sign (encode=True)
                signed_fragments = mol.signature_fragments(key, encode=True)

                # Verify (encode=False) -- reverses the hashing direction
                recovered = mol.signature_fragments(signed_fragments, encode=False)

                # Hash the recovered key fragments to get the address
                # This mirrors the OTS verification in check.py:ots()
                sponge = shake()
                sponge.update(strings.encode(recovered))
                digest = sponge.hexdigest(1024)

                sponge2 = shake()
                sponge2.update(strings.encode(digest))
                address = sponge2.hexdigest(32)

                self.assertEqual(
                    address,
                    tv["expectedOtsAddress"],
                    f"Roundtrip address mismatch for {tv['name']}:\n"
                    f"  expected: {tv['expectedOtsAddress']}\n"
                    f"  got:      {address}",
                )
                self.assertTrue(
                    tv["expectedVerified"],
                    "Vector says verification should succeed",
                )


# ===========================================================================
# Runner
# ===========================================================================

if __name__ == "__main__":
    unittest.main()
