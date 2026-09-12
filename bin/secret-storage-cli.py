#!/usr/bin/env python3
import sys
import json
import os

# Add package root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from knishioclient.storage.AesGcmSecretStorageProvider import seal_envelope, open_envelope
from knishioclient.storage.models import SecretStorageMetadata, EncryptedSecretPayload


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: secret-storage-cli.py <seal|open> [args...]\n")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd in ("seal", "seal-recovery"):
        if len(sys.argv) < 5:
            sys.stderr.write("Usage: secret-storage-cli.py seal <passphrase> <secret> <bundleHash> [label]\n")
            sys.exit(1)
        passphrase = sys.argv[2]
        secret = sys.argv[3]
        bundle_hash = sys.argv[4]
        label = sys.argv[5] if len(sys.argv) >= 6 and sys.argv[5] else None

        metadata = SecretStorageMetadata(
            bundle_hash=bundle_hash,
            created_at=1700000000000,
            hardware_backed=False,
            provider_type="aes-gcm",
            label=label,
        )
        payload = seal_envelope(secret, passphrase, metadata)
        print(json.dumps(payload.to_dict(), separators=(",", ":")))
        sys.exit(0)

    elif cmd == "open":
        if len(sys.argv) < 4:
            sys.stderr.write("Usage: secret-storage-cli.py open <passphrase> <payloadJson>\n")
            sys.exit(1)
        passphrase = sys.argv[2]
        payload_json = sys.argv[3]
        payload_dict = json.loads(payload_json)
        payload = EncryptedSecretPayload.from_dict(payload_dict)
        plain = open_envelope(payload, passphrase)
        print(plain)
        sys.exit(0)

    else:
        sys.stderr.write(f"Unknown command: {cmd}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
