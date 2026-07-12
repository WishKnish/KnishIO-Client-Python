# -*- coding: utf-8 -*-
import re
import json
import aiohttp
import asyncio
from ..models import Coder
from ..libraries.array import array_get

# PQ-transport Phase E: the canonical ML-KEM CipherHash transport query (matches the Rust
# validator's CipherHash handler + the other SDKs).
CIPHER_HASH_QUERY = 'query ( $Hash: String! ) { CipherHash ( Hash: $Hash ) { hash } }'


def _parse_operation(query):
    """Light parse of a GraphQL query string → (operation_type, root_field_name), for the
    CipherHash bypass decision (no full GraphQL parse needed). Mirrors the JS/Kotlin parseOperation."""
    if not query:
        return 'query', ''
    m = re.search(r'\b(query|mutation|subscription)\b', query, re.IGNORECASE)
    op_type = m.group(1).lower() if m else 'query'
    brace = query.find('{')
    name = ''
    if brace >= 0:
        nm = re.search(r'[A-Za-z_][A-Za-z0-9_]*', query[brace + 1:])
        name = nm.group(0) if nm else ''
    return op_type, name


class HttpClient(object):
    def __init__(self, url: str):
        self.__xAuthToken = None
        self.__url = url
        # PQ-transport Phase E: encrypted-transport state (wallet = the AUTH source wallet that
        # decrypts CipherHash responses; pubkey = the validator's advertised ML-KEM pubkey).
        self.__encrypt = False
        self.__wallet = None
        self.__pubkey = None

    def get_url(self):
        return self.__url

    def set_url(self, url: str):
        self.__url = url

    def set_auth_token(self, auth_token: str):
        self.__xAuthToken = auth_token

    def get_auth_token(self):
        return self.__xAuthToken

    def set_auth_data(self, auth_token, pubkey=None, wallet=None):
        """PQ-transport Phase E: plumb the auth token + the validator's ML-KEM pubkey + the AUTH
        source wallet (the one that decrypts CipherHash responses) into the transport."""
        self.__xAuthToken = auth_token
        self.__pubkey = pubkey
        self.__wallet = wallet

    def set_encryption(self, encrypt: bool):
        self.__encrypt = bool(encrypt)

    def has_encryption(self) -> bool:
        return self.__encrypt

    def __should_encrypt(self, request) -> bool:
        """Whether an outgoing GraphQL request should be wrapped in CipherHash. Bypass (plaintext):
        introspection __schema, ContinuId, the AccessToken mutation, and the U-isotope ProposeMolecule
        (auth bootstrap — the key exchange itself can't be encrypted). Mirrors the validator/other-SDK
        bypass set."""
        if not isinstance(request, dict):
            return False
        op_type, name = _parse_operation(request.get('query'))
        if op_type == 'query' and name in ('__schema', 'ContinuId'):
            return False
        if op_type == 'mutation' and name == 'AccessToken':
            return False
        if op_type == 'mutation' and name == 'ProposeMolecule':
            atoms = (((request.get('variables') or {}).get('molecule') or {}).get('atoms')) or []
            if atoms and isinstance(atoms[0], dict) and atoms[0].get('isotope') == 'U':
                return False
        return True

    def send(self, request: str, options: dict = None):
        # Sync-over-async bridge. Three environments to handle:
        #  1. No event loop in this thread (plain sync caller) → create one.
        #  2. A non-running loop exists → reuse it (legacy behavior).
        #  3. A loop is ALREADY RUNNING in this thread (caller is inside asyncio,
        #     e.g. the enhanced async client API) → run_until_complete would raise
        #     "This event loop is already running"; execute on a private loop in a
        #     worker thread instead.
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        if loop.is_running():
            import concurrent.futures

            def _run_in_fresh_loop():
                inner_loop = asyncio.new_event_loop()
                try:
                    return inner_loop.run_until_complete(self.__send(request, options))
                finally:
                    inner_loop.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(_run_in_fresh_loop).result()

        response = loop.run_until_complete(asyncio.gather(self.__send(request, options)))
        return array_get(response, '0')

    async def __send(self, request: str, options: dict = None):
        if options is None:
            options = {}
        options.update({
            'User-Agent': 'KnishIO/0.1',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        })
        if self.get_auth_token() is not None:
            options.update({'X-Auth-Token': self.get_auth_token()})

        # PQ-transport Phase E: wrap the request in the ML-KEM CipherHash envelope (encrypt to the
        # validator's pubkey); the response is decrypted back to the inner GraphQL response.
        encrypted = (
            self.__encrypt and self.__wallet is not None and self.__pubkey is not None
            and self.__should_encrypt(request)
        )
        payload = request
        if encrypted:
            payload = {
                'query': CIPHER_HASH_QUERY,
                'variables': {'Hash': self.__wallet.encrypt_string_ml768(request, self.__pubkey)},
            }

        async with aiohttp.ClientSession(headers=options, json_serialize=Coder().encode) as session:
            async with session.post(self.get_url(), json=payload, ssl=False) as response:
                result = await response.json()

        if not encrypted:
            return result

        # Decrypt the CipherHash response back to the inner GraphQL response dict. (array_get is not
        # used for the hash because it refuses to return a string leaf.)
        data = result.get('data') if isinstance(result, dict) else None
        cipher = data.get('CipherHash') if isinstance(data, dict) else None
        hash_value = cipher.get('hash') if isinstance(cipher, dict) else None
        if not isinstance(hash_value, str):
            # Plaintext (e.g. a validator-side error response) — return unchanged.
            return result
        decrypted = self.__wallet.decrypt_my_message_ml768(json.loads(hash_value))
        return decrypted if decrypted is not None else result
