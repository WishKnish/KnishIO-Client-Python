# -*- coding: utf-8 -*-

from .Wallet import Wallet


class WalletShadow(Wallet):
    """class WalletShadow"""

    def __init__(self, bundle_hash: str, token: str = 'USER', batch_id: str = None, characters: str = None):
        """
        :param bundle_hash: str
        :param token: str
        :param batch_id: str
        :param characters: str
        """
        super().__init__(None, token)

        self.bundle = bundle_hash
        self.batchId = batch_id
        self.characters = characters

        self.position = None
        self.key = None
        self.address = None
        self.pubkey = None