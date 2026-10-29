# -*- coding: utf-8 -*-
import re
import os
import json
import aiohttp
import asyncio
import threading
import weakref
from ..models import Coder
from ..exception import CodeException

# PQ-transport Phase E: the canonical ML-KEM CipherHash transport query (matches the Rust
# validator's CipherHash handler + the other SDKs).
CIPHER_HASH_QUERY = 'query ( $Hash: String! ) { CipherHash ( Hash: $Hash ) { hash } }'

# A forked child's copies of its parent's loops and sessions. They are never collected: their
# sockets belong to the parent, and closing them would go through a selector the fork did not
# carry over.
_INHERITED_FROM_PARENT = []


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


class _Transport(object):
    """The client's own event loop, kept running by a background thread, and its one aiohttp session.

    Every request runs here, so the session's keep-alive connections are reused across requests.
    Opening a session per request (before 1.7.1) cost a TCP connection per request, and a client
    submitting at a sustained rate left so many sockets in TIME_WAIT that it ran out of local ports
    ("Cannot assign requested address"). The loop keeps running between requests so that a
    connection the server closes while idle is noticed (its FIN processed) and dropped from the pool
    before it could be reused; a loop that only runs during a request would hand out the dead
    connection and the request would fail with a reset.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._pid = None
        self._loop = None
        self._thread = None
        self._session = None

    def run(self, coro):
        """Run a coroutine on the client's loop and block until it finishes."""
        return asyncio.run_coroutine_threadsafe(coro, self._running_loop()).result()

    def session(self):
        """The client's session; call from a coroutine running on the client's loop."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(json_serialize=Coder().encode)
        return self._session

    def _running_loop(self):
        with self._lock:
            # A forked child inherits the loop object but not the thread running it.
            if self._loop is None or self._pid != os.getpid():
                if self._loop is not None:
                    _INHERITED_FROM_PARENT.append((self._loop, self._session))
                loop = asyncio.new_event_loop()
                thread = threading.Thread(target=loop.run_forever, name='knishio-http', daemon=True)
                thread.start()
                self._pid, self._loop, self._thread, self._session = os.getpid(), loop, thread, None
            return self._loop

    def close(self):
        with self._lock:
            loop, thread, session = self._loop, self._thread, self._session
            self._loop = self._thread = self._session = None
            owned = self._pid == os.getpid()
        if loop is None or thread is None or not owned:
            return
        if session is not None and not session.closed:
            asyncio.run_coroutine_threadsafe(session.close(), loop).result(5)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
        loop.close()


class HttpClient(object):
    def __init__(self, url: str):
        self.__xAuthToken = None
        self.__url = url
        # PQ-transport Phase E: encrypted-transport state (wallet = the AUTH source wallet that
        # decrypts CipherHash responses; pubkey = the validator's advertised ML-KEM pubkey).
        self.__encrypt = False
        self.__wallet = None
        self.__pubkey = None
        self.__transport = _Transport()
        # Closes the session and stops the loop's thread when the client is collected or the
        # interpreter exits.
        self.__close = weakref.finalize(self, self.__transport.close)

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
            # The request carries the Molecule model (Coder serializes its `atoms`, in order, on
            # the wire), or a dict for a pre-serialized request. Inspect whichever is sent.
            molecule = (request.get('variables') or {}).get('molecule')
            atoms = (molecule.get('atoms') if isinstance(molecule, dict) else getattr(molecule, 'atoms', None)) or []
            first = atoms[0] if atoms else None
            isotope = first.get('isotope') if isinstance(first, dict) else getattr(first, 'isotope', None)
            if isotope == 'U':
                return False
        return True

    def send(self, request: dict, options: dict = None):
        # Callers may be plain synchronous code or already inside asyncio (e.g. the enhanced async
        # client API); either way the request runs on the client's own loop and the caller blocks
        # on the result.
        return self.__transport.run(self.__send(request, options))

    async def __send(self, request: dict, options: dict = None):
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
        # Decide the bypass FIRST, then demand the keys: a bypassed operation (`__schema`,
        # `ContinuId`, `AccessToken`, U-isotope `ProposeMolecule`) must still go out in plaintext or
        # the auth bootstrap would deadlock encrypting to a server pubkey it has not learned yet.
        # Anything else on an encryption-enabled client fails closed rather than silently
        # downgrading to plaintext (matches PHP Cipher.php / Kotlin HttpClient).
        encrypted = self.__encrypt and self.__should_encrypt(request)
        payload = request
        if encrypted:
            if self.__wallet is None:
                raise CodeException('Authorized wallet missing.')
            if not self.__pubkey:
                raise CodeException('Server public key missing.')
            payload = {
                'query': CIPHER_HASH_QUERY,
                # Serialize through Coder first, as the plaintext wire does, so a Molecule model in
                # the variables encrypts as the same JSON it would be sent as.
                'variables': {'Hash': self.__wallet.encrypt_string_ml(json.loads(Coder().encode(request)), self.__pubkey)},
            }

        async with self.__transport.session().post(self.get_url(), json=payload, headers=options, ssl=False) as response:
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
        decrypted = self.__wallet.decrypt_my_message_ml(json.loads(hash_value))
        return decrypted if decrypted is not None else result
