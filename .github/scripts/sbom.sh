#!/usr/bin/env bash
# This repo's CycloneDX SBOM — one definition shared by ci, audit, publish and local runs.
# Usage: bash .github/scripts/sbom.sh [OUT_DIR]   (default sbom-out)
# Needs cyclonedx-py (pip install cyclonedx-bom==7.5.0) and npm.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
OUT="${1:-sbom-out}"
case "$OUT" in ''|/) echo "SBOM FAIL refusing OUT_DIR '$OUT'" >&2; exit 1 ;; esac
VERSION="$(bash .github/scripts/check-version.sh | sed -n 's/^OK: version is \([^ ]*\).*/\1/p')"
[ -n "$VERSION" ] || { echo "SBOM FAIL could not read the version" >&2; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT/gen"
# Runtime graph = the committed hashed lock; the wheel also bundles the Node ML-KEM bridge.
cyclonedx-py requirements --of JSON --sv 1.5 --output-reproducible -o "$OUT/gen/pip.cdx.json" requirements.lock
(cd bin && npm sbom --sbom-format cyclonedx --sbom-type library --omit dev --package-lock-only) > "$OUT/gen/npm-bridge.cdx.json"
python3 .github/scripts/sbom.py --name knishio-client-python --version "$VERSION" --type library \
  --base "$OUT/gen/pip.cdx.json" --base "$OUT/gen/npm-bridge.cdx.json" \
  --components .github/sbom-components.json --out "$OUT"
