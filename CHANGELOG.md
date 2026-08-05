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

[Unreleased]: https://github.com/WishKnish/KnishIO-Client-Python/compare/0.9.2.post1...HEAD
[0.9.2.post1]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.9.2.post1
[0.9.2]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.9.2
[0.9.0]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.9.0
[0.8.3]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.8.3
[0.8.2]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.8.2
[0.8.1]: https://github.com/WishKnish/KnishIO-Client-Python/releases/tag/0.8.1
