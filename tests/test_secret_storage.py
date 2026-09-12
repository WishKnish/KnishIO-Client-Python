# -*- coding: utf-8 -*-
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from knishioclient.exception.SecretStorageException import SecretStorageException
from knishioclient.exception.BaseError import BaseError
from knishioclient.libraries import crypto
from knishioclient.models.Wallet import Wallet
from knishioclient.models.Atom import Atom
from knishioclient.client.KnishIOClient import KnishIOClient
from knishioclient.storage import (
    MemoryStorageBackend,
    FileStorageBackend,
    SecretStorageMetadata,
    EncryptedSecretPayload,
    StorageOptions,
    MemorySecretStorageProvider,
    AesGcmSecretStorageProvider,
    create_default_secret_storage,
    RECOVERY_KEY_PREFIX,
    SECRET_KEY_PREFIX,
    KEY_PREFIX,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cross-platform-test-vectors.json"


def load_fixtures():
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class SecretStorageExceptionTest(unittest.TestCase):
    def test_inheritance(self):
        exc = SecretStorageException("test error")
        self.assertIsInstance(exc, BaseError)
        self.assertIsInstance(exc, Exception)

    def test_not_found(self):
        exc = SecretStorageException.not_found("deadbeef123")
        self.assertIn("deadbeef123", str(exc))
        self.assertEqual(exc.error_code, "SECRET_NOT_FOUND")
        self.assertIsNotNone(exc.details)
        if exc.details:
            self.assertEqual(exc.details["bundleHash"], "deadbeef123")

    def test_decryption_failed(self):
        exc = SecretStorageException.decryption_failed("Invalid tag")
        self.assertIn("Invalid tag", str(exc))
        self.assertEqual(exc.error_code, "DECRYPTION_FAILED")
        self.assertIsNotNone(exc.details)
        if exc.details:
            self.assertEqual(exc.details["reason"], "Invalid tag")

    def test_unavailable(self):
        exc = SecretStorageException.unavailable("tpm2", "No TPM device")
        self.assertIn("tpm2", str(exc))
        self.assertIn("No TPM device", str(exc))
        self.assertEqual(exc.error_code, "STORAGE_UNAVAILABLE")
        self.assertIsNotNone(exc.details)
        if exc.details:
            self.assertEqual(exc.details["provider"], "tpm2")


class SecureMemoryTest(unittest.TestCase):
    def test_zeroize_bytearray(self):
        buf = bytearray([1, 2, 3, 4, 5])
        crypto.zeroize(buf)
        self.assertEqual(list(buf), [0, 0, 0, 0, 0])

    def test_zeroize_list(self):
        arr = [10, 20, 30]
        crypto.zeroize(arr)
        self.assertEqual(arr, [0, 0, 0])

    def test_constant_time_compare(self):
        self.assertTrue(crypto.constant_time_compare("secret123", "secret123"))
        self.assertFalse(crypto.constant_time_compare("secret123", "secret124"))
        self.assertFalse(crypto.constant_time_compare("secret123", "secret12"))

        self.assertTrue(crypto.constant_time_compare(b"\x01\x02\x03", b"\x01\x02\x03"))
        self.assertFalse(crypto.constant_time_compare(b"\x01\x02\x03", b"\x01\x02\x04"))

    def test_with_secure_bytes(self):
        buf = bytearray([42, 43, 44])
        observed = []

        def callback(b):
            observed.append(b[0])
            return b[0] * 2

        result = crypto.with_secure_bytes(buf, callback)
        self.assertEqual(result, 84)
        self.assertEqual(observed, [42])
        self.assertEqual(list(buf), [0, 0, 0])

    def test_with_secure_bytes_zeroizes_on_exception(self):
        buf = bytearray([99, 98, 97])

        with self.assertRaises(ValueError):
            def callback(b):
                raise ValueError("Crash")
            crypto.with_secure_bytes(buf, callback)

        self.assertEqual(list(buf), [0, 0, 0])


class StorageBackendTest(unittest.TestCase):
    def test_memory_backend(self):
        backend = MemoryStorageBackend()
        self.assertIsNone(backend.get_item("k1"))
        self.assertEqual(backend.keys(), [])

        backend.set_item("k1", "v1")
        self.assertEqual(backend.get_item("k1"), "v1")
        self.assertEqual(backend.keys(), ["k1"])

        removed = backend.remove_item("k1")
        self.assertTrue(removed)
        self.assertIsNone(backend.get_item("k1"))

        self.assertFalse(backend.remove_item("k1"))

    def test_file_backend(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "test_store.json"
            backend = FileStorageBackend(file_path)

            self.assertIsNone(backend.get_item("k1"))
            backend.set_item("k1", "v1")
            self.assertEqual(backend.get_item("k1"), "v1")

            # Check file permissions (0o600 on Unix)
            file_stat = os.stat(str(file_path))
            mode = stat.S_IMODE(file_stat.st_mode)
            self.assertEqual(mode & 0o077, 0, f"File permissions {oct(mode)} should restrict group/others")

            # Verify reload from disk
            backend2 = FileStorageBackend(file_path)
            self.assertEqual(backend2.get_item("k1"), "v1")
            self.assertEqual(backend2.keys(), ["k1"])

            backend2.remove_item("k1")
            self.assertIsNone(backend2.get_item("k1"))

            # Reload again, should be empty
            backend3 = FileStorageBackend(file_path)
            self.assertIsNone(backend3.get_item("k1"))


class StorageModelsTest(unittest.TestCase):
    def test_metadata_camel_case(self):
        meta = SecretStorageMetadata(
            bundle_hash="abc",
            label="test_label",
            created_at=123456789,
            hardware_backed=False,
            provider_type="aes-gcm"
        )
        d = meta.to_dict()
        self.assertEqual(d["bundleHash"], "abc")
        self.assertEqual(d["label"], "test_label")
        self.assertEqual(d["createdAt"], 123456789)
        self.assertEqual(d["hardwareBacked"], False)
        self.assertEqual(d["providerType"], "aes-gcm")

        # Forbidden keys absent
        for forbidden in ["bundle_hash", "created_at", "hardware_backed", "provider_type"]:
            self.assertNotIn(forbidden, d)

    def test_metadata_omits_label_when_none(self):
        meta = SecretStorageMetadata(
            bundle_hash="abc",
            label=None,
            hardware_backed=False,
            provider_type="aes-gcm"
        )
        d = meta.to_dict()
        self.assertNotIn("label", d)

    def test_payload_roundtrip(self):
        meta = SecretStorageMetadata(bundle_hash="abc", label="test")
        payload = EncryptedSecretPayload(
            ciphertext="dGVzdA==",
            iv="MTIzNDU2Nzg5MDEy",
            salt="MTIzNDU2Nzg5MDEyMzQ1Ng==",
            metadata=meta
        )
        payload_json = payload.to_json()
        restored = EncryptedSecretPayload.from_json(payload_json)

        self.assertEqual(restored.version, 1)
        self.assertEqual(restored.algorithm, "AES-GCM")
        self.assertEqual(restored.iterations, 100000)
        self.assertEqual(restored.ciphertext, "dGVzdA==")
        self.assertEqual(restored.metadata.bundleHash, "abc")
        self.assertEqual(restored.metadata.label, "test")

    def test_storage_options_recovery(self):
        opts = StorageOptions(
            label="MyLabel",
            passphrase="pass",
            recovery_passphrase="rec_pass",
            allow_unrecoverable=True
        )
        self.assertEqual(opts.label, "MyLabel")
        self.assertEqual(opts.passphrase, "pass")
        self.assertEqual(opts.recovery_passphrase, "rec_pass")
        self.assertEqual(opts.recoveryPassphrase, "rec_pass")
        self.assertTrue(opts.allow_unrecoverable)
        self.assertTrue(opts.allowUnrecoverable)

        # Test setter & camelCase args
        opts2 = StorageOptions(recoveryPassphrase="rec2", allowUnrecoverable=False)
        self.assertEqual(opts2.recovery_passphrase, "rec2")
        self.assertFalse(opts2.allow_unrecoverable)

        opts2.recoveryPassphrase = "rec3"
        self.assertEqual(opts2.recovery_passphrase, "rec3")
        opts2.allowUnrecoverable = True
        self.assertTrue(opts2.allow_unrecoverable)

        # Constant verification
        self.assertEqual(RECOVERY_KEY_PREFIX, "knishio:recovery:")
        self.assertEqual(SECRET_KEY_PREFIX, "knishio:secret:")
        self.assertEqual(KEY_PREFIX, "knishio:secret:")


class MemorySecretStorageProviderTest(unittest.TestCase):
    def test_crud_operations(self):
        provider = MemorySecretStorageProvider()
        self.assertEqual(provider.provider_type, "memory")
        self.assertFalse(provider.is_hardware_backed())
        self.assertTrue(provider.is_available())

        bundle = "bundle_123"
        secret = "super_secret_value"

        self.assertFalse(provider.has_secret(bundle))
        self.assertIsNone(provider.retrieve_secret(bundle))

        # Empty validation
        with self.assertRaises(SecretStorageException):
            provider.store_secret("", secret)
        with self.assertRaises(SecretStorageException):
            provider.store_secret(bundle, "")

        # Store
        provider.store_secret(bundle, secret, options={"label": "MyKey"})
        self.assertTrue(provider.has_secret(bundle))
        self.assertEqual(provider.retrieve_secret(bundle), secret)

        # List
        secrets = provider.list_secrets()
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0].bundleHash, bundle)
        self.assertEqual(secrets[0].label, "MyKey")

        # with_secret
        res = provider.with_secret(bundle, lambda s: s.upper())
        self.assertEqual(res, "SUPER_SECRET_VALUE")

        # Delete
        self.assertTrue(provider.delete_secret(bundle))
        self.assertFalse(provider.has_secret(bundle))
        self.assertIsNone(provider.retrieve_secret(bundle))

    def test_with_secret_not_found(self):
        provider = MemorySecretStorageProvider()
        with self.assertRaises(SecretStorageException):
            provider.with_secret("nonexistent", lambda s: s)


class AesGcmSecretStorageProviderTest(unittest.TestCase):
    def test_canonical_test_vector_decrypt(self):
        """
        Decrypt the frozen TypeScript vector from cross-platform-test-vectors.json
        """
        fixtures = load_fixtures()
        vector = fixtures["vectors"]["secret_storage_envelope"]["tests"][0]

        backend = MemoryStorageBackend()
        backend.set_item(vector["storageKey"], json.dumps(vector["payload"]))

        provider = AesGcmSecretStorageProvider(backend=backend)
        decrypted = provider.retrieve_secret(
            vector["bundleHash"],
            options={"passphrase": vector["passphrase"]}
        )

        self.assertEqual(
            decrypted,
            vector["expectedPlaintext"],
            f"Failed to decrypt vector produced by {vector.get('producedBy')}"
        )
        self.assertEqual(decrypted, "MASTER-SECRET-CROSS-SDK-PROBE")

    def test_emitted_metadata_keys_contract(self):
        """
        Verify emitted metadata strictly satisfies the cross-SDK contract:
        - requiredMetadataKeys present
        - forbiddenMetadataKeys absent
        - optionalMetadataKeys omitted when unset per optionalKeyConvention
        - hardwareBacked is False
        - providerType is 'aes-gcm'
        """
        fixtures = load_fixtures()
        vector = fixtures["vectors"]["secret_storage_envelope"]["tests"][0]

        backend = MemoryStorageBackend()
        provider = AesGcmSecretStorageProvider(backend=backend)

        bundle_hash = vector["bundleHash"]
        passphrase = vector["passphrase"]
        plaintext = vector["expectedPlaintext"]

        # Store without label
        provider.store_secret(bundle_hash, plaintext, options={"passphrase": passphrase})

        raw_stored = backend.get_item(vector["storageKey"])
        self.assertIsNotNone(raw_stored)
        stored_dict = json.loads(raw_stored or "{}")
        emitted_metadata = stored_dict["metadata"]

        # Assert required keys
        for req in vector["requiredMetadataKeys"]:
            self.assertIn(req, emitted_metadata, f"Emitted metadata missing required key: {req}")

        # Assert forbidden keys (snake_case)
        for forb in vector["forbiddenMetadataKeys"]:
            self.assertNotIn(forb, emitted_metadata, f"Emitted metadata contains forbidden key: {forb}")

        # Assert optional keys omitted when unset
        if vector.get("optionalKeyConvention") == "omit-when-absent":
            for opt in vector["optionalMetadataKeys"]:
                self.assertNotIn(opt, emitted_metadata, f"Unset optional key should be omitted: {opt}")

        self.assertFalse(emitted_metadata["hardwareBacked"])
        self.assertEqual(emitted_metadata["providerType"], "aes-gcm")

    def test_roundtrip_encryption_and_decryption(self):
        backend = MemoryStorageBackend()
        provider = AesGcmSecretStorageProvider(backend=backend, default_passphrase="default-pass")

        bundle = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        secret = "canonical-master-secret-payload-test-string"

        provider.store_secret(bundle, secret, options={"label": "Production Seed"})
        self.assertTrue(provider.has_secret(bundle))

        # Retrieve with default passphrase
        retrieved = provider.retrieve_secret(bundle)
        self.assertEqual(retrieved, secret)

        # Retrieve with with_secret
        transformed = provider.with_secret(bundle, lambda s: s[:10])
        self.assertEqual(transformed, "canonical-")

        # List secrets
        listed = provider.list_secrets()
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0].bundleHash, bundle)
        self.assertEqual(listed[0].label, "Production Seed")
        self.assertEqual(listed[0].providerType, "aes-gcm")

        # Delete
        self.assertTrue(provider.delete_secret(bundle))
        self.assertFalse(provider.has_secret(bundle))
        self.assertIsNone(provider.retrieve_secret(bundle))

    def test_wrong_passphrase_fails(self):
        backend = MemoryStorageBackend()
        provider = AesGcmSecretStorageProvider(backend=backend)

        bundle = "bundle_wrong_pass"
        secret = "secret_to_protect"

        provider.store_secret(bundle, secret, options={"passphrase": "correct-pass"})

        with self.assertRaises(SecretStorageException) as cm:
            provider.retrieve_secret(bundle, options={"passphrase": "wrong-pass"})
        self.assertEqual(cm.exception.error_code, "DECRYPTION_FAILED")

    def test_corrupted_payload_fails(self):
        backend = MemoryStorageBackend()
        provider = AesGcmSecretStorageProvider(backend=backend)

        bundle = "bundle_corrupt"
        backend.set_item(f"knishio:secret:{bundle}", "invalid-non-json-data")

        with self.assertRaises(SecretStorageException) as cm:
            provider.retrieve_secret(bundle, options={"passphrase": "pass"})
        self.assertEqual(cm.exception.error_code, "DECRYPTION_FAILED")

    def test_hardware_custody_cannot_be_faked(self):
        backend = MemoryStorageBackend()
        provider = AesGcmSecretStorageProvider(backend=backend, hardwareBacked=True)
        self.assertFalse(provider.is_hardware_backed())

        provider.store_secret("b", "s", options={"passphrase": "p"})
        raw_stored = backend.get_item("knishio:secret:b")
        self.assertIsNotNone(raw_stored)
        stored = json.loads(raw_stored or "{}")
        self.assertFalse(stored["metadata"]["hardwareBacked"])


class FactoryTest(unittest.TestCase):
    def test_create_default_secret_storage(self):
        mem = create_default_secret_storage({"type": "memory"})
        self.assertIsInstance(mem, MemorySecretStorageProvider)

        aes = create_default_secret_storage({"defaultPassphrase": "abc"})
        self.assertIsInstance(aes, AesGcmSecretStorageProvider)
        self.assertEqual(getattr(aes, 'default_passphrase', None), "abc")


class KnishIOClientSecretStorageIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.seed = "knishio-hardware-secret-storage-seed"
        self.secret = crypto.generate_secret(self.seed)
        self.bundle = crypto.generate_bundle_hash(self.secret)

    def test_client_with_secret_storage_unwraps_just_in_time(self):
        storage = AesGcmSecretStorageProvider(default_passphrase="client-secure-passphrase")
        storage.store_secret(self.bundle, self.secret, options={"label": "Hardware Key"})

        # Initialize client with secret_storage without holding cleartext secret
        client = KnishIOClient(
            url="https://api.test.knish.io",
            secret_storage=storage
        )
        client.set_secret_storage(storage, bundle_hash=self.bundle)

        self.assertTrue(client.has_secret())
        self.assertTrue(client.has_bundle())
        self.assertEqual(client.get_bundle(), self.bundle)

        # Cleartext secret remains None in client to prevent long-term heap retention
        self.assertIsNone(client.get_secret())

        # Retrieve secret from client
        retrieved = client.retrieve_secret()
        self.assertEqual(retrieved, self.secret)

        # Create a source wallet
        source_wallet = Wallet(
            secret=self.secret,
            bundle=self.bundle,
            token="USER",
            position="0" * 64
        )

        # create_molecule should unwrap secret just-in-time from storage
        molecule = client.create_molecule(source_wallet=source_wallet)
        self.assertIsNotNone(molecule)
        self.assertEqual(molecule.bundle, self.bundle)
        self.assertEqual(molecule.sourceWallet, source_wallet)
        self.assertIsNotNone(molecule.remainderWallet)
        self.assertEqual(molecule.remainderWallet.bundle, self.bundle)

        # Sign the molecule
        atom = Atom.create(
            isotope="C",
            wallet=source_wallet,
            value="0"
        )
        molecule.add_atom(atom)
        sig = molecule.sign()
        self.assertIsNotNone(sig)
        self.assertIsNotNone(molecule.molecularHash)

    def test_client_set_secret_auto_syncs_to_storage(self):
        client = KnishIOClient(url="https://api.test.knish.io")
        self.assertFalse(client.has_secret())
        self.assertIsNone(client.get_secret_storage())

        client.set_secret(self.secret)
        self.assertTrue(client.has_secret())
        self.assertEqual(client.get_bundle(), self.bundle)
        self.assertEqual(client.get_secret(), self.secret)

        storage = client.get_secret_storage()
        self.assertIsNotNone(storage)
        if storage:
            self.assertTrue(storage.has_secret(self.bundle))
            self.assertEqual(storage.retrieve_secret(self.bundle), self.secret)

    def test_client_reset_clears_storage(self):
        storage = MemorySecretStorageProvider()
        storage.store_secret(self.bundle, self.secret)

        client = KnishIOClient(url="https://api.test.knish.io", secret_storage=storage)
        client.set_secret_storage(storage, self.bundle)
        self.assertTrue(client.has_secret())

        client.reset()
        self.assertFalse(client.has_secret())
        self.assertIsNone(client.get_secret_storage())
        self.assertIsNone(client.get_bundle())


class SecretRecoveryWorkflowTest(unittest.TestCase):
    def test_aes_gcm_recovery_workflow(self):
        backend = MemoryStorageBackend()
        provider = AesGcmSecretStorageProvider(backend=backend, default_passphrase="primary-passphrase")

        bundle = "bundle-recovery-test-1"
        secret = "ultra-secure-master-secret-recovery"
        recovery_pass = "backup-recovery-pass-xyz"

        # 1. Store secret with recovery passphrase
        provider.store_secret(
            bundle,
            secret,
            options={"label": "RecoveryKey", "recovery_passphrase": recovery_pass}
        )

        # 2. Both primary and recovery envelopes exist in backend
        primary_raw = backend.get_item(f"{SECRET_KEY_PREFIX}{bundle}")
        self.assertIsNotNone(primary_raw)
        recovery_raw = backend.get_item(f"{RECOVERY_KEY_PREFIX}{bundle}")
        self.assertIsNotNone(recovery_raw)

        # 3. Inspect recovery payload contract
        recovery_payload = EncryptedSecretPayload.from_json(recovery_raw or "{}")
        self.assertEqual(recovery_payload.version, 1)
        self.assertEqual(recovery_payload.algorithm, "AES-GCM")
        self.assertEqual(recovery_payload.iterations, 100000)
        self.assertEqual(recovery_payload.metadata.bundleHash, bundle)
        self.assertEqual(recovery_payload.metadata.providerType, "aes-gcm")
        self.assertFalse(recovery_payload.metadata.hardwareBacked)
        self.assertEqual(recovery_payload.metadata.label, "RecoveryKey")

        # 4. list_secrets only returns primary secret, never recovery
        secrets_list = provider.list_secrets()
        self.assertEqual(len(secrets_list), 1)
        self.assertEqual(secrets_list[0].bundleHash, bundle)

        # 5. Simulate hardware failure or primary record destruction/corruption
        backend.set_item(f"{SECRET_KEY_PREFIX}{bundle}", "corrupted-ciphertext-or-lost-key")
        with self.assertRaises(SecretStorageException) as cm:
            provider.retrieve_secret(bundle)
        self.assertEqual(cm.exception.error_code, "DECRYPTION_FAILED")

        # 6. recover_secret restores the secret and re-enrolls it
        provider.recover_secret(bundle, recovery_pass)

        # 7. Direct retrieve succeeds with primary passphrase
        retrieved = provider.retrieve_secret(bundle)
        self.assertEqual(retrieved, secret)

        # 8. Re-enrolled secret retains a recovery envelope
        re_enrolled_recovery_raw = backend.get_item(f"{RECOVERY_KEY_PREFIX}{bundle}")
        self.assertIsNotNone(re_enrolled_recovery_raw)

        # 9. delete_secret deletes both primary and recovery records
        self.assertTrue(provider.delete_secret(bundle))
        self.assertIsNone(backend.get_item(f"{SECRET_KEY_PREFIX}{bundle}"))
        self.assertIsNone(backend.get_item(f"{RECOVERY_KEY_PREFIX}{bundle}"))

    def test_aes_gcm_recovery_with_options_object(self):
        backend = MemoryStorageBackend()
        provider = AesGcmSecretStorageProvider(backend=backend)

        bundle = "bundle-recovery-test-opts"
        secret = "secret-value-opts"

        # Store with StorageOptions object using camelCase options
        opts = StorageOptions(
            passphrase="first-pass",
            recoveryPassphrase="rec-pass-opts",
            label="OptionLabel"
        )
        provider.store_secret(bundle, secret, options=opts)

        # Corrupt primary
        backend.remove_item(f"{SECRET_KEY_PREFIX}{bundle}")
        self.assertIsNone(provider.retrieve_secret(bundle, options={"passphrase": "first-pass"}))

        # Recover with new primary passphrase
        recover_opts = StorageOptions(passphrase="second-pass")
        provider.recover_secret(bundle, "rec-pass-opts", options=recover_opts)

        # Retrieve with second-pass succeeds
        self.assertEqual(provider.retrieve_secret(bundle, options={"passphrase": "second-pass"}), secret)

    def test_memory_provider_recovery_workflow(self):
        provider = MemorySecretStorageProvider()
        bundle = "mem-rec-bundle"
        secret = "mem-secret-value-123"

        provider.store_secret(bundle, secret, options={"recovery_passphrase": "mem-recovery-pass"})
        self.assertTrue(provider.has_secret(bundle))

        # Primary and recovery exist
        self.assertIsNotNone(provider.backend.get_item(f"{RECOVERY_KEY_PREFIX}{bundle}"))

        # list_secrets returns 1
        self.assertEqual(len(provider.list_secrets()), 1)

        # Corrupt primary secret in memory
        provider._secrets[bundle]["secret"] = "corrupted-memory-data"
        self.assertEqual(provider.retrieve_secret(bundle), "corrupted-memory-data")

        # Recover restores original
        provider.recover_secret(bundle, "mem-recovery-pass")
        self.assertEqual(provider.retrieve_secret(bundle), secret)

        # Delete removes both
        self.assertTrue(provider.delete_secret(bundle))
        self.assertFalse(provider.has_secret(bundle))
        self.assertIsNone(provider.backend.get_item(f"{RECOVERY_KEY_PREFIX}{bundle}"))

    def test_recovery_error_conditions(self):
        backend = MemoryStorageBackend()
        provider = AesGcmSecretStorageProvider(backend=backend, default_passphrase="pass")

        bundle = "bundle-error-test"
        secret = "secret-error-test"

        provider.store_secret(bundle, secret, options={"recovery_passphrase": "good-recovery-pass"})

        # Empty bundle hash
        with self.assertRaises(SecretStorageException):
            provider.recover_secret("", "good-recovery-pass")

        # Empty recovery passphrase
        with self.assertRaises(SecretStorageException):
            provider.recover_secret(bundle, "")

        # Missing recovery record (wrong bundle)
        with self.assertRaises(SecretStorageException) as cm:
            provider.recover_secret("nonexistent-bundle", "good-recovery-pass")
        self.assertEqual(cm.exception.error_code, "SECRET_NOT_FOUND")

        # Wrong recovery passphrase
        with self.assertRaises(SecretStorageException) as cm:
            provider.recover_secret(bundle, "wrong-recovery-pass")
        self.assertEqual(cm.exception.error_code, "DECRYPTION_FAILED")

        # Corrupted recovery payload in storage
        backend.set_item(f"{RECOVERY_KEY_PREFIX}{bundle}", "not-valid-json-payload")
        with self.assertRaises(SecretStorageException) as cm:
            provider.recover_secret(bundle, "good-recovery-pass")
        self.assertEqual(cm.exception.error_code, "DECRYPTION_FAILED")
