# -*- coding: utf-8 -*-

import string
import base64
import numpy as np
from hashlib import shake_256 as shake
from json import dumps, loads
from typing import List, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..libraries import strings, crypto
from ..exception import WalletCredentialException
from .TokenUnit import TokenUnit


class Wallet(object):
    """class Wallet"""

    def __init__(self,
                 secret: str = None,
                 bundle: str | bytes = None,
                 token: str = 'USER',
                 address: str | bytes = None,
                 position: str = None,
                 batch_id: str = None,
                 characters: str = None) -> None:

        self.token: str = token
        self.balance: int | float = 0
        self.molecules: List = []

        # Empty values
        self.key: str | bytes | None = None
        self.privkey: List[int] | None = None
        self.pubkey: str | bytes | None = None
        self.tokenUnits: List["TokenUnit"] = []
        self.tradeRates: Dict = {}

        self.address: str | None = address
        self.position: str | None = position
        self.bundle: str | None = bundle
        self.batchId: str | None = batch_id
        self.characters: str | None = characters or 'BASE64'

        if secret is not None:
            self.bundle = self.bundle or crypto.generate_bundle_hash(secret)
            self.position = self.position or Wallet.generate_position()
            self.key = Wallet.generate_key(secret, self.token, self.position)
            self.address = self.address or Wallet.generate_address(self.key)
            self.initialize_mlkem()

    def initialize_mlkem(self):
        """Initialize ML-KEM768 keys for quantum resistance (matches JavaScript patterns)"""
        public_key, secret_key = crypto.keypair_from_seed(self.key)
        self.pubkey = Wallet.serialize_key(public_key)
        self.privkey = list(secret_key)

    @classmethod
    def serialize_key(cls, key: bytes) -> str:
        return base64.b64encode(key).decode('utf-8')

    @classmethod
    def deserialize_key(cls, serialized_key: str) -> bytes:
        return base64.b64decode(serialized_key)

    def is_shadow(self) -> bool:
        """
        :return: bool
        """
        return self.position is None and self.address is None

    def get_token_units_data(self):
        return [tokenUnit.to_data() for tokenUnit in self.tokenUnits]

    def split_units(self, units: List, remainder_wallet: "Wallet" = None, recipient_wallet: "Wallet" = None):
        if not units:
            return
        recipient_token_units = [tokenUnit for tokenUnit in self.tokenUnits if tokenUnit.id in units]
        self.tokenUnits = recipient_token_units
        if recipient_wallet:
            recipient_wallet.tokenUnits = recipient_token_units
        remainder_wallet.tokenUnits = [tokenUnit for tokenUnit in self.tokenUnits if tokenUnit.id not in units]

    @classmethod
    def get_token_units(cls, units_datas: List):
        return [TokenUnit.create_from_db(unit_data) for unit_data in units_datas]

    @classmethod
    def create(cls, secret: str = None, bundle: str = None, token: str = 'USER', batch_id: str = None,
               characters: str = None):
        if not secret and not bundle:
            raise WalletCredentialException()

        position: str | None = None

        if secret and not bundle:
            position = cls.generate_position()
            bundle = crypto.generate_bundle_hash(secret)

        return Wallet(
            secret=secret,
            bundle=bundle,
            token=token,
            position=position,
            batch_id=batch_id,
            characters=characters
        )

    def create_remainder(self, secret: str):
        remainder_wallet = Wallet.create(secret, token=self.token, characters=self.characters)
        remainder_wallet.init_batch_id(self, is_remainder=True)
        return remainder_wallet

    @classmethod
    def generate_position(cls, salt_length: int = 64):
        """
        :param salt_length: int
        :return: str
        """
        return strings.random_string(salt_length)

    @classmethod
    def is_bundle_hash(cls, code: str) -> bool:
        """
        :param code: str
        :return: bool
        """
        return len(code) == 64 and all(c in string.hexdigits for c in code)

    @classmethod
    def generate_address(cls, key: str) -> str:
        """
        :param key: str
        :return: str
        """
        digest_sponge = shake()

        for fragment in strings.chunk_substr(key, 128):
            working_fragment = fragment

            for _ in range(16):
                working_sponge = shake()
                working_sponge.update(strings.encode(working_fragment))
                working_fragment = working_sponge.hexdigest(64)

            digest_sponge.update(strings.encode(working_fragment))

        sponge = shake()
        sponge.update(strings.encode(digest_sponge.hexdigest(1024)))

        return sponge.hexdigest(32)

    @classmethod
    def generate_key(cls, secret: str, token: str, position: str) -> str:
        """
        :param secret: str
        :param token: str
        :param position: str
        :return: str
        """
        # Converting secret to bigInt
        # Adding new position to the user secret to produce the indexed key
        indexed_key = '%x' % np.add(np.array([int(secret, 16)], dtype='object'),
                                    np.array([int(position, 16)], dtype='object'))[0]
        # Hashing the indexed key to produce the intermediate key
        intermediate_key_sponge = shake()
        intermediate_key_sponge.update(indexed_key.encode('utf-8'))

        if token not in ['']:
            intermediate_key_sponge.update(token.encode('utf-8'))

        # Hashing the intermediate key to produce the private key
        sponge = shake()
        sponge.update(strings.encode(intermediate_key_sponge.hexdigest(1024)))

        return sponge.hexdigest(1024)

    def init_batch_id(self, source_wallet: "Wallet", is_remainder: bool = False) -> None:
        """
        :param source_wallet:
        :param is_remainder: bool
        :return:
        """
        if source_wallet.batchId is not None:
            self.batchId = source_wallet.batchId if is_remainder else crypto.generate_batch_id()

    @classmethod
    def encrypt_with_shared_secret(cls, message: bytes, shared_secret: bytes) -> bytes:
        iv = np.random.bytes(12)
        aesgcm = AESGCM(shared_secret)
        encrypted_content = aesgcm.encrypt(iv, message, None)
        return iv + encrypted_content

    def encrypt_message(self, message: Any, recipient_pubkey: str) -> Dict[str, str]:
        message_string = dumps(message)
        message_bytes = message_string.encode('utf-8')
        deserialized_pubkey = Wallet.deserialize_key(recipient_pubkey)

        # Use @noble/post-quantum via Node.js bridge for 100% cross-SDK compatibility
        # Returns (ciphertext, shared_secret) matching JavaScript SDK
        ciphertext, shared_secret = crypto.noble_bridge_encaps(deserialized_pubkey)

        encrypted_message = Wallet.encrypt_with_shared_secret(message_bytes, shared_secret)
        return {
            "cipherText": Wallet.serialize_key(ciphertext),
            "encryptedMessage": Wallet.serialize_key(encrypted_message)
        }

    @classmethod
    def decrypt_with_shared_secret(cls, encrypted_message: bytes, shared_secret: bytes) -> bytes:
        iv = encrypted_message[:12]
        ciphertext = encrypted_message[12:]
        aesgcm = AESGCM(shared_secret)
        return aesgcm.decrypt(iv, ciphertext, None)

    def decrypt_message(self, encrypted_data: Dict[str, str]) -> Any:
        cipher_text, encrypted_message = (
            Wallet.deserialize_key(encrypted_data["cipherText"]),
            Wallet.deserialize_key(encrypted_data["encryptedMessage"])
        )

        # Use @noble/post-quantum via Node.js bridge for 100% cross-SDK compatibility
        shared_secret = crypto.noble_bridge_decaps(cipher_text, bytes(self.privkey))

        decrypted = Wallet.decrypt_with_shared_secret(encrypted_message, shared_secret)
        return loads(decrypted.decode('utf-8'))