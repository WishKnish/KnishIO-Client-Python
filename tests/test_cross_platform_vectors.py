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

import base64
import json
import sys
import unittest
from pathlib import Path

# Ensure the SDK root is importable
SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if SDK_ROOT not in sys.path:
    sys.path.insert(0, SDK_ROOT)

from knishioclient.libraries import crypto
from knishioclient.models.Atom import Atom
from knishioclient.models.AuthToken import AuthToken
from knishioclient.models.Molecule import Molecule
from knishioclient.models.Wallet import Wallet
from knishioclient.storage import AesGcmSecretStorageProvider, MemoryStorageBackend


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
        wallet = Wallet(secret=v["secret"], token=v["token"], position=v["position"], mlkem_param_set=768)
        self.assertEqual(v["expectedPubkey"], wallet.pubkey, "ML-KEM768 keygen pubkey mismatch")

    # Encapsulation is non-deterministic, but decapsulation + AES-256-GCM decrypt is deterministic →
    # one frozen {cipherText, encryptedMessage} sample must decrypt to the canonical plaintext.
    def test_mlkem768_decrypt(self):
        v = VECTORS["mlkem768"]["decrypt"]
        wallet = Wallet(secret=v["secret"], token=v["token"], position=v["position"], mlkem_param_set=768)
        plaintext = wallet.decrypt_message(
            {"cipherText": v["cipherText"], "encryptedMessage": v["encryptedMessage"]}
        )
        self.assertEqual(v["expectedPlaintext"], plaintext, "ML-KEM768 decrypt plaintext mismatch")

    # PQ-transport hardening: a stale/non-PQ validator advertises a ~48-byte `key`; encrypt_message
    # must fail with an actionable error, not a cryptic bridge crash.
    def test_mlkem768_encrypt_rejects_non_1184_key(self):
        v = VECTORS["mlkem768"]["keygen"]
        wallet = Wallet(secret=v["secret"], token=v["token"], position=v["position"], mlkem_param_set=768)
        short_key = Wallet.serialize_key(bytes(48))
        with self.assertRaises(ValueError) as ctx:
            wallet.encrypt_message({"q": 1}, short_key)
        self.assertIn("expected 1184 (ML-KEM-768)", str(ctx.exception))


class Mlkem1024VectorTest(unittest.TestCase):
    def test_mlkem1024_keygen(self):
        v = VECTORS["mlkem1024"]["keygen"]
        wallet = Wallet(secret=v["secret"], token=v["token"], position=v["position"])
        self.assertEqual(v["expectedPubkey"], wallet.pubkey, "ML-KEM1024 keygen pubkey mismatch")

    def test_mlkem1024_decrypt(self):
        v = VECTORS["mlkem1024"]["decrypt"]
        wallet = Wallet(secret=v["secret"], token=v["token"], position=v["position"])
        plaintext = wallet.decrypt_message(
            {"cipherText": v["cipherText"], "encryptedMessage": v["encryptedMessage"]}
        )
        self.assertEqual(v["expectedPlaintext"], plaintext, "ML-KEM1024 decrypt plaintext mismatch")

    def test_mlkem1024_encrypt_rejects_non_1568_key(self):
        v = VECTORS["mlkem1024"]["keygen"]
        wallet = Wallet(secret=v["secret"], token=v["token"], position=v["position"])
        short_key = Wallet.serialize_key(bytes(48))
        with self.assertRaises(ValueError) as ctx:
            wallet.encrypt_message({"q": 1}, short_key)
        self.assertIn("expected 1568 (ML-KEM-1024)", str(ctx.exception))

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


class Mlkem768StepBackTest(unittest.TestCase):
    """A wallet at the shipped default (ML-KEM-1024) must still READ records addressed to its
    own ML-KEM-768 identity. The 64-byte ML-KEM seed is parameter-set-independent, so the 768
    identity is derived on demand from material the wallet already holds. Inbound is permissive;
    outbound encapsulation stays strict (see test_mlkem1024_encrypt_rejects_non_1568_key)."""

    def setUp(self):
        self.v = VECTORS["mlkem768"]["decrypt"]
        # No mlkem_param_set → the shipped default, ML-KEM-1024.
        self.wallet = Wallet(
            secret=self.v["secret"], token=self.v["token"], position=self.v["position"]
        )

    def test_default_wallet_decrypts_frozen_768_envelope(self):
        plaintext = self.wallet.decrypt_message(
            {"cipherText": self.v["cipherText"], "encryptedMessage": self.v["encryptedMessage"]}
        )
        self.assertEqual(
            self.v["expectedPlaintext"], plaintext,
            "ML-KEM-1024 default wallet failed to read its own ML-KEM-768 record",
        )

    def test_default_wallet_still_advertises_1024_pubkey(self):
        # Dual-identity decryption must not move the advertised key: it goes into signed
        # molecule meta and into auth, so changing it would change hashed bytes.
        self.assertEqual(1568, len(base64.b64decode(self.wallet.pubkey)))

    def test_ciphertext_matching_neither_parameter_set_still_fails(self):
        self.assertIsNone(
            self.wallet.decrypt_message({
                "cipherText": Wallet.serialize_key(bytes(64)),
                "encryptedMessage": self.v["encryptedMessage"],
            })
        )

    def test_map_addressed_768_envelope_is_found(self):
        # A pre-bump sender addressed the CipherHash envelope to hash_share(our 768 pubkey);
        # a 1024 wallet must still find it, or the length dispatch above is unreachable.
        legacy = Wallet(
            secret=self.v["secret"], token=self.v["token"], position=self.v["position"],
            mlkem_param_set=768,
        )
        mapping = {
            self.wallet.hash_share(legacy.pubkey): {
                "cipherText": self.v["cipherText"],
                "encryptedMessage": self.v["encryptedMessage"],
            }
        }
        self.assertEqual(self.v["expectedPlaintext"], self.wallet.decrypt_my_message_ml(mapping))


class AuthTokenSnapshotParameterSetTest(unittest.TestCase):
    """A restored session must keep the parameter set it was persisted with. Falling back to
    the constructor default (now 1024) makes a pre-bump session advertise a public key the
    validator never recorded for that token, and breaks outbound against the stored 1184-byte
    validator key."""

    def setUp(self):
        keygen = VECTORS["mlkem768"]["keygen"]
        self.secret = keygen["secret"]
        self.position = keygen["position"]
        # A 1184-byte-decoding key, i.e. what a pre-bump validator stored for the session.
        self.validator_pubkey_768 = keygen["expectedPubkey"]
        self.wallet_768 = Wallet(
            secret=self.secret, token="AUTH", position=self.position, mlkem_param_set=768
        )

    def test_explicit_768_session_round_trips(self):
        auth = AuthToken.create({
            "token": "jwt-768",
            "expiresAt": 1700000000,
            "pubkey": self.validator_pubkey_768,
            "encrypt": True,
        }, self.wallet_768)
        snapshot = auth.get_snapshot()
        self.assertEqual(768, snapshot["wallet"]["mlKemParameterSet"])

        restored = AuthToken.restore(snapshot, self.secret)
        self.assertEqual(self.wallet_768.pubkey, restored.get_wallet().pubkey)

    def test_legacy_snapshot_without_parameter_set_restores_as_768(self):
        # The literal shape an 0.9.x build persisted: no parameter-set field at all.
        legacy_snapshot = {
            "token": "jwt-legacy",
            "expiresAt": 1700000000,
            "pubkey": self.validator_pubkey_768,
            "encrypt": True,
            "wallet": {"position": self.position, "characters": "BASE64"},
        }
        restored_wallet = AuthToken.restore(legacy_snapshot, self.secret).get_wallet()

        self.assertEqual(self.wallet_768.pubkey, restored_wallet.pubkey)
        decoded = len(base64.b64decode(restored_wallet.pubkey))
        self.assertEqual(1184, decoded)
        self.assertNotEqual(1568, decoded)


class LegacyMlkem768AuthMoleculeTest(unittest.TestCase):
    """A signed U+I auth molecule whose U-atom walletPubkey meta is an ML-KEM-768 key — the
    shape a pre-bump 0.9.x client produced. A build defaulting to ML-KEM-1024 must still
    validate it, hash and WOTS+ signature alike."""

    def setUp(self):
        self.v = VECTORS["legacyMlkem768AuthMolecule"]

    def test_wallet_pubkey_meta_really_is_768(self):
        # Fails loudly if the fixture is ever regenerated at ML-KEM-1024.
        u_atom = next(a for a in self.v["molecule"]["atoms"] if a["isotope"] == "U")
        pubkey = next(m["value"] for m in u_atom["meta"] if m["key"] == "walletPubkey")
        self.assertEqual(
            self.v["expectedWalletPubkeyBytes"], len(base64.b64decode(pubkey)),
            "frozen molecule no longer carries an ML-KEM-768 walletPubkey",
        )

    def test_molecular_hash(self):
        atoms = [Atom.from_json(atom_data) for atom_data in self.v["atoms"]]
        self.assertEqual(
            self.v["expectedMolecularHash"], Atom.hash_atoms(atoms),
            "molecular hash of the frozen pre-bump 768 molecule does not reproduce",
        )

    def test_full_check(self):
        molecule = Molecule.from_json(
            self.v["molecule"], include_validation_context=True, validate_structure=True
        )
        self.assertTrue(molecule.check(molecule.sourceWallet))


class SecretStorageEnvelopeVectorTest(unittest.TestCase):
    """
    secret_storage_envelope: decrypt an envelope produced by a peer SDK (TypeScript).
    Validates cross-SDK envelope compatibility and emitted metadata casing contract.
    """

    def test_secret_storage_envelope_vectors(self):
        v = VECTORS.get("secret_storage_envelope")
        if not v:
            self.skipTest("secret_storage_envelope vectors not found")

        for test in v["tests"]:
            payload = test["payload"]
            bundle_hash = test["bundleHash"]

            backend = MemoryStorageBackend()
            backend.set_item(test["storageKey"], json.dumps(payload))
            provider = AesGcmSecretStorageProvider(backend=backend)

            decrypted = provider.retrieve_secret(
                bundle_hash,
                options={"passphrase": test["passphrase"]}
            )
            self.assertEqual(
                test["expectedPlaintext"],
                decrypted,
                f"failed to decrypt envelope from {test.get('producedBy')}"
            )

            # Assert what Python emits
            our_backend = MemoryStorageBackend()
            our_provider = AesGcmSecretStorageProvider(backend=our_backend)
            our_provider.store_secret(
                bundle_hash,
                test["expectedPlaintext"],
                options={"passphrase": test["passphrase"]}
            )
            raw_stored = our_backend.get_item(test["storageKey"])
            self.assertIsNotNone(raw_stored)
            emitted_metadata = json.loads(raw_stored or "{}")["metadata"]

            for req in test["requiredMetadataKeys"]:
                self.assertIn(req, emitted_metadata, f"Python must emit `{req}`; emitted {list(emitted_metadata.keys())}")

            for forb in test["forbiddenMetadataKeys"]:
                self.assertNotIn(forb, emitted_metadata, f"`{forb}` is snake_case and must never be emitted")

            if test.get("optionalKeyConvention") == "omit-when-absent":
                for opt in test["optionalMetadataKeys"]:
                    self.assertNotIn(opt, emitted_metadata, f"Python must omit unset optional key `{opt}`")

            self.assertFalse(emitted_metadata["hardwareBacked"], "software provider must never emit hardwareBacked=true")
            self.assertEqual("aes-gcm", emitted_metadata["providerType"])


if __name__ == "__main__":
    unittest.main()
