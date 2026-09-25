# Changelog

All notable changes to the KnishIO Client Python SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
expressed in [PEP 440](https://peps.python.org/pep-0440/) form — hence
`0.9.2.post1` rather than a `0.9.3` patch, since that release changed packaging
only and not the library.
Releases are published to PyPI (`knishioclient`) from a git tag.
Conventions for tags, commits, and these entries: `docs/SDK-RELEASE-CONVENTIONS.md`
in the KnishIOClientSDK monorepo.

This file was backfilled on 2026-07-27 from the repository's own tag and commit
history. Entries at and below `0.8.1` are reconstructed from commit messages
rather than written at release time; where the history does not substantiate a
detail, the entry says so instead of guessing.

## [1.2.1] — 2026-09-25

### Fixed

- `Molecule.check()` now runs the ContinuID check (`knishioclient/libraries/check.py`), as the JS
  reference's `CheckMolecule.verify` does: a molecule whose first atom spends the `USER` token must
  carry a ContinuID `I` atom, or `check()` raises `AtomsMissingException`. `continu_id` was defined
  but commented out of `verify()`, so such a molecule verified. Its token test is exact now
  (`== 'USER'`); the substring test `in 'USER'` also matched tokens such as `'U'`, `'US'` and `''`.
  Pinned by `tests/test_check_continuid.py`.
- `Molecule.init_meta_append()` adds the ContinuID I-atom, as JS `initAppendRequest` and PHP
  `initMetaAppend` do. Without it, the ContinuID check above rejected its molecules
  (`AtomsMissingException`). Pinned by `tests/test_check_continuid.py`.
- After a profile authorization (`request_profile_auth_token`, which `request_auth_token` calls
  when it has a secret), the next molecule is signed from the ContinuID position the validator
  reports (`query_continu_id`) instead of from the auth molecule's cached USER remainder wallet.
  From validator 0.5.0 an unproven re-authorization (every login of an identity after its first)
  no longer creates a wallet at its I-atom position or moves the ContinuID pointer there, so the
  first molecule after such a login was rejected with `Wallet not found: bundle=…, position=…`.
  Querying the pointer is correct against earlier validators too. Pinned by
  `tests/test_auth_continuid_source_wallet.py`.
- `ResponseContinuId.payload()` (`knishioclient/response/ResponseContinuId.py`) called
  `Wallet.json_to_object`, which does not exist, so asking the validator for the ContinuID wallet
  raised `AttributeError: type object 'Wallet' has no attribute 'json_to_object'` whenever the
  bundle had a pointer. That broke `get_source_wallet()` and every method that calls it, including
  `create_meta` on any authenticated identity. It now builds the wallet with the same
  `_wallet_from_data` helper `ResponseWalletList` uses. The fix above depends on it; the same test
  parses a real `ContinuId` response.
- The wheel now ships the ML-KEM bridge. `NobleMLKEMBridge` runs `noble-mlkem-bridge.js` with Node
  and loads `@noble/post-quantum` from the `node_modules` beside it, but both lived in the
  repository's `bin/`, outside the package, so no wheel carried them: every pip install, 1.2.0
  included, raised `RuntimeError: Noble ML-KEM bridge script not found` in `request_auth_token`,
  because a wallet derives its ML-KEM keypair when it is constructed. `setup.py` now copies the
  script, its `package.json` and lockfile, and the pinned `@noble` modules into
  `knishioclient/bin/`, and refuses to build without them. Node.js 20.19 or later must be on the
  `PATH`. The publish workflow's wheel check now runs outside the checkout, where it imports the
  installed wheel rather than the source tree, and it constructs a wallet.
- `KnishIOClient.create_rule()` works, and builds the same R atom as the JS reference's
  `createRule`. `Molecule.init_rule_creation` raised `TypeError` on `AtomMeta(data=...)`, and past
  that called the nonexistent `add_continuid_atom()`. It now normalises each rule through the new
  `Rule`/`Condition`/`Callback` models (`knishioclient/models/Rule.py`, ported from JS), serialises
  it as JS `JSON.stringify` does (`strings.js_json_stringify`), always adds the policy, and appends
  the ContinuID atom. Malformed rules raise `MetaMissingException`/`RuleArgumentException` before
  signing. The unused, misspelled `Molecule.crate_rule` is removed.
- `create_meta(..., policy=...)` works. `AtomMeta.add_policy` merged raw `read`/`write` keys whose
  values were dicts, so the validator refused the whole mutation: `Invalid value for argument
  "molecule.atoms.1.meta.1.value", expected type "String"`. It now stores the policy as one JSON
  `policy` meta, filled from the meta entries' indices, as JS `AtomMeta.addPolicy` does. Pinned by
  `tests/test_rule_creation.py` against the JS SDK's digests for the same inputs.

### Notes

- Needed against validator 0.5.0 and later, which testnet.knish.io has run since 2026-09-24:
  earlier releases are rejected with `Wallet not found` on the first molecule after the second
  and later logins of an identity.

## [1.2.0] — 2026-09-20

### Added

- The requested transport mode now travels as a **signed `encrypt` meta** on the authorization
  U-atom (`Molecule.init_authorization(encrypt)` → `MutationRequestAuthorization.fill_molecule(encrypt)`
  → `request_profile_auth_token`), emitted first to match the C and C++ key order. Python never
  sent it before, so every Python profile session was persisted as a plaintext session and the
  validator's encrypted-transport enforcement could not apply to a Python client.

### Changed

- `HttpClient` **fails closed**: `CodeException('Authorized wallet missing.')` /
  `CodeException('Server public key missing.')` instead of a silent plaintext request when
  encryption is requested but the transport keys are missing; an empty advertised validator key
  counts as missing.

### Notes

- Both live CipherHash cases (`tests/test_cipherhash_live.py`) passed against `testnet.knish.io`
  on 2026-09-20 at ML-KEM-1024 and ML-KEM-768, including the validator refusing a plaintext query
  from an `encrypt: true` session.

## [1.1.1] — 2026-09-13

### Changed

- **BREAKING:** `AesGcmSecretStorageProvider(...)` no longer accepts arbitrary keyword arguments; passing the removed `hardwareBacked=` (or any unknown kwarg) now raises `TypeError` instead of being silently ignored. `hardwareBacked` has been provider-derived and always `False` for this software provider since 1.1.0; the wire format is unchanged.

## [1.1.0] — 2026-09-12

### Added

- Hardware-compatible envelope encryption secret storage layer (`knishioclient.storage`):
  - `SecretStorageException` with `not_found`, `decryption_failed`, and `unavailable` error factories.
  - Pluggable storage backend interface `StorageBackend` with thread-safe `MemoryStorageBackend` and atomic `FileStorageBackend` (mode 0o600 with atomic tempfile replacement).
  - Cross-SDK envelope models `SecretStorageMetadata` and `EncryptedSecretPayload` (AES-256-GCM, PBKDF2-HMAC-SHA256 @ 100,000 iterations, 16-byte salt, 12-byte IV, camelCase metadata keys).
  - Secret storage providers: `SecretStorageProvider` ABC, `MemorySecretStorageProvider`, and `AesGcmSecretStorageProvider` interoperable with TypeScript, JavaScript, Kotlin, and Rust SDKs.
  - Memory hygiene helpers in `knishioclient.libraries.crypto`: `zeroize`, `constant_time_compare`, and `with_secure_bytes`.
  - `KnishIOClient` integration with `secret_storage` constructor argument, `set_secret_storage()`, `get_secret_storage()`, `retrieve_secret()`, automatic storage synchronization in `set_secret()`, and just-in-time unwrapping in `create_molecule()`.
  - Secret recovery support (`recover_secret` & `recovery_passphrase`): cross-SDK secret recovery envelope support. When `options.recovery_passphrase` is provided to `store_secret`, a secondary software envelope is sealed and stored under `knishio:recovery:<bundleHash>`. `recover_secret` opens the recovery record and re-enrolls the master secret under the provider's active key without leaking plaintext.
  - `RECOVERY_KEY_PREFIX = "knishio:recovery:"` constant and `StorageOptions` extensions for `recovery_passphrase` and `allow_unrecoverable` (with camelCase property aliases).
  - Dual deletion in `delete_secret` (removes both primary and recovery keys) and recovery key filtering in `list_secrets`.
  - Test coverage: unit tests in `tests/test_secret_storage.py` covering envelope encryption, re-enrollment, dual deletion, key filtering, error conditions, and canonical vector decrypt in `tests/test_cross_platform_vectors.py`.

## [1.0.0] — 2026-09-10

### Added

- A wallet now decrypts records addressed to **its own ML-KEM-768 identity even when configured at
  ML-KEM-1024**, by deriving that identity on demand from the same 64-byte wallet seed. The seed is
  parameter-set-independent, so both identities belong to one wallet; only the final keygen call
  differs. Reading pre-bump 768 records therefore needs no configuration change and no second
  wallet. The derived private key lives only for the duration of the `decrypt_message()` call and
  is never cached on the wallet.
- `Wallet.decrypt_my_message_ml()` tries both identities' `CipherHash` map keys, so an envelope a
  pre-bump peer addressed to `hash_share(our_768_pubkey)` is found rather than missed.
- `Wallet.mlkem_param_set_from_pubkey()` recovers a parameter set from a serialized public key's
  length (FIPS 203's 1568/1184 lengths are disjoint).

  Encapsulation and the advertised public key are unchanged and remain single-set: inbound is
  permissive, outbound is strict. Reading a 768 record you own downgrades nothing — its
  confidentiality was fixed at 768 by the sender — whereas permissive outbound would be a real
  downgrade vector.

### Changed

- **ML-KEM-1024 is the default parameter set** for the post-quantum transport, replacing
  ML-KEM-768. `Wallet`, `Molecule` and `KnishIOClient` accept an `mlkem_param_set` option (`1024`
  default, `768` step-back); `KnishIOClient.set_mlkem_parameter_set()` validates it.
- Encapsulation is strict and **raises** `ValueError` on a wrong-length recipient key rather than
  silently downgrading to whatever the peer advertised.

### Removed

- `Wallet.encrypt_string_ml768()` and `Wallet.decrypt_my_message_ml768()`. Use
  `encrypt_string_ml()` and `decrypt_my_message_ml()`. No aliases are retained.

### Fixed

- The auth-token session snapshot now records the wallet's ML-KEM parameter set
  (`wallet.mlKemParameterSet`), and `AuthToken.restore()` honours it. A session persisted by an
  0.9.x build restores as ML-KEM-768 instead of silently becoming ML-KEM-1024 with a public key
  the validator never recorded for that token. Resolution is three-tiered: an explicit snapshot
  field, then the stored validator key's length, then ML-KEM-768 — never the constructor default,
  which is what produced the defect.
- Both `KnishIOClient` entry points now route `mlkem_param_set` through the validating setter.
  `__init__` and `initialize()` previously assigned it raw, so `mlkem_param_set=512` was silently
  accepted and only failed later, inside the ML-KEM bridge, while
  `set_mlkem_parameter_set(512)` had always rejected it.
- The distribution no longer ships a top-level `tests` package. `setup.py` used a bare
  `find_packages()`, and `tests/` has an `__init__.py`, so `top_level.txt` listed both
  `knishioclient` and `tests` — installing the package put a generic `tests` module on the
  consumer's import path, where it could shadow their own. Now excluded explicitly.
- Distribution metadata corrected for a stable release: the `License` field read the literal
  string `LICENSE` rather than `GPL-3.0-or-later` (disagreeing with the GPLv3 classifier it
  already carried), and the maturity classifier still said `Development Status :: 2 - Pre-Alpha`.

### Notes

- `0.9.5`–`0.9.9` were never published. The ML-KEM-1024 cutover is a breaking API change, so it
  takes the 1.0.0 line.
- A frozen pre-bump ML-KEM-768 auth molecule (`vectors.legacyMlkem768AuthMolecule` in
  `cross-platform-test-vectors.json`) is validated by this SDK from a 1024-default build —
  molecular hash and WOTS+ signature via `Molecule.from_json()` + `check()` — so the
  compatibility claim rests on a signed artifact rather than on parameter-set-independent hashing.

## [0.9.4] — 2026-08-05

### Security

- Dependency floors raised to the advisory fix versions: `aiohttp>=3.14.3` (was `>=3.14.1`,
  PYSEC-2026-3545 / -3546 / -3547) and `cryptography>=50.0.0` (was `>=46.0.6`,
  PYSEC-2026-3552). `requirements.lock` regenerated with the `uv pip compile` invocation
  recorded in its own header; only those two pins moved.

  `setup.py` derives `install_requires` from `requirements.txt`, so these floors are the
  shipped dependency contract. They previously sat *below* the fix versions, which meant a
  constrained resolver could still land a consumer on the vulnerable `aiohttp 3.14.1` even
  though a default `pip install` would not. Fixed at the declaration rather than by
  suppressing the audit.

  No published artifact was vulnerable: `requirements.txt` carries floors, not pins, and the
  advisories were against the CI lock. 0.9.3 on PyPI is unaffected and remains available.

## [0.9.3] — 2026-08-05

### Added

- Classical NaCl cross-platform parity vectors asserted in the test suite.

### Changed — cross-SDK gauntlet reporting integrity

- The self-test now publishes cross-validation **coverage**, not just a verdict:
  `crossValidation.{ran,targetsExpected,targetsValidated}` and `runId` sit alongside
  `crossSdkCompatible` in the results file. The boolean alone could not distinguish
  "validated every peer, all passed" from "validated nothing and so found no failures".
- `crossSdkCompatible` now defaults to **false** and must be earned. It was `True`, so every early return out of cross-validation published a pass.
- Cross-validation **fails** instead of reporting "compatible" when the shared results
  directory is missing or holds no peer results. Absence of evidence is not evidence of
  compatibility.
- Round 1 no longer asserts a cross-SDK verdict it cannot have; it records that no
  cross-validation ran.
- A coverage floor is required before a pass: every expected peer must have been validated,
  in addition to no individual check having failed.
- Each peer is now checked for all 7 required molecule types. The validation loop iterates
  the molecule keys that are **present**, so an omitted molecule was indistinguishable from
  a validated one.
- Peer results are matched with `*-results.json`. `glob('*.json')` also matched the
  canonical vector **masters** living in that directory and fed them into the peer loop
  as though they were SDK results.
- The Round-1 exit code no longer requires `crossSdkCompatible`, a check Round 1 skips by
  design.

Contract for these fields: `sdks/canonical-test-keys.json` in the KnishIOClientSDK
monorepo. Audit: `docs/audits/REPORTING-INTEGRITY-2026-08-05.md`.

## [0.9.2.post1] — 2026-07-12

Packaging-only release. No library changes.

### Fixed

- The `0.9.2` wheel shipped without the `knishioclient.config` subpackage, which
  made `import knishioclient` fail outright. Root cause: `config/` had no
  `__init__.py`, so `find_packages()` dropped the implicit namespace package.
  **Anyone on `0.9.2` must upgrade** — that release is unusable.

## [0.9.2] — 2026-07-12

**Broken on PyPI — use `0.9.2.post1`.** See above.

Coordinated dependency-security release across all 8 SDKs. Release record:
`docs/sdk-release-0.9.2-execution-2026-07-12.md` (monorepo).

### Changed

- Hardened dependency floors (including `aiohttp` and `cryptography`) and added a
  reproducible `requirements.lock` for CI.

### Added

- `pip-audit` gate in CI, run against both `requirements.txt` (the declared
  floors) and `requirements.lock` (the reproducible resolution).
- Tag-driven publish workflow using PyPI Trusted Publishing (OIDC);
  `PYPI_API_TOKEN` dropped. The publish job runs in the `release` GitHub
  environment.

### Fixed

- An async transport bug in the client.

### Notes

- `0.9.1` was staged in `knishioclient/__init__.py` on 2026-06-30 (a clear error
  when a node advertises a non-ML-KEM recipient key) but was never tagged and
  never published to PyPI. That fix ships in `0.9.2`.

## [0.9.0] — 2026-06-29

Coordinated `0.9.0` across all 8 SDKs, marking the post-quantum ML-KEM transport
milestone. Runbook: `docs/sdk-release-audit-2026-06-29.md` (monorepo).

### Added

- **ML-KEM768 CipherHash encrypted transport** (PQ Phase E).
- Multi-recipient stackable (NFT) transfer builder (`transfer_tokens`), and
  stackable readiness throughout: create-stackable, `tokenUnits` parsing,
  `tokenUnits` carried on stackable burn and transfer.
- Cross-platform vectors test (SHAKE256, bundle hash, wallet generation,
  `mlkem768`) and a "decrypt their message" ML-KEM768 cross-validation.
- A `ruff` lint gate (CI migrated from flake8 to ruff).

### Fixed

- Buffer withdraw debits the full source balance; corrected atom argument order.
- `generate_key` handles non-hex secrets the same way JS/TS/Rust do.
- The USER ContinuID I-atom is registered on auth.
- `claim_shadow_wallet` live path repaired (3 bugs on previously unexercised
  paths); `shadowWalletClaim` meta value is the string `"1"`, not the integer 1.
- Burn rebuilt as a canonical 3-atom zero-sum molecule; client `burn_tokens`
  repaired.
- The live HTTP request/response and transfer paths repaired.
- `Wallet.split_units` no longer loses the kept units.
- `init_wallet_creation` and `init_shadow_wallet_claim` reconciled to the JS
  reference; `ResponseWalletList` parsing fixed.

### Changed

- The classical NaCl path is documented as non-PQ (`Soda` + crypto wrappers).

### Removed

- Dead `QueryUserActivity` query.
- The vestigial `token_slug` parameter on `init_shadow_wallet_claim`.

### Notes

- Local version `0.8.4` was staged on 2026-06-15 and never published; that work
  reaches consumers here.

## [0.8.3] — 2026-06-15

### Fixed

- `init_token_creation` C-atom metadata reconciled to the JS reference (adds
  `set_meta_wallet`).

## [0.8.2] — 2026-06-14

### Fixed

- Molecule construction reconciled to the JS reference, restoring cross-SDK
  molecular-hash parity.

## [0.8.1] — 2026-06-09

First release of the 0.8 line to reach PyPI. Version `0.8.0` was staged in the
manifest on 2026-06-05 but was never tagged or published, so the two breaking
changes below reach consumers here.

### Changed

- **BREAKING (staged as 0.8.0):** atom `value` is serialized as an integer string
  (`"100"`), not a float string (`"100.0"`). The validator parses V/B/F values as
  integers and rejected the old form.

### Fixed

- `init_deposit_buffer` was non-functional; 5 distinct bugs repaired.
- Packaging: `requirements.txt`, `README`, and `LICENSE` are bundled in the sdist
  via `MANIFEST.in`, so `pip install` from source works.

### Added

- First CI workflow for this repo, demo examples, a `tests` package, and a
  lockfile for the Node ML-KEM bridge.
- `generate_secret` asserted against the canonical vector; WOTS+ two-pass
  OTS-address vector and fixture.

## Earlier releases

`0.6.0` and earlier predate this project's conventional-commit discipline; their
commit messages do not support accurate reconstruction. One fix is worth naming
because it is a correctness change: `0.6.0-2` (staged 2026-06-03, never
published) fixed policy ContinuID signing (F-3) by signing the R-atom from the
established source wallet. See the git tag history and the
[PyPI release list](https://pypi.org/project/knishioclient/#history).

[Unreleased]: https://github.com/WishKnish/KnishIO-Client-Python/compare/1.2.1...HEAD
[1.2.1]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/1.2.1
[1.2.0]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/1.2.0
[1.1.1]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/1.1.1
[1.1.0]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/1.1.0
[1.0.0]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/1.0.0
[0.9.2.post1]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.9.2.post1
[0.9.2]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.9.2
[0.9.0]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.9.0
[0.8.3]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.8.3
[0.8.2]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.8.2
[0.8.1]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.8.1
