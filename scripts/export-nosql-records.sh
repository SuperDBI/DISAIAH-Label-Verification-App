#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <custodian-export-bundle-directory> <new-output-directory> <tenant-guid>" >&2
  exit 2
fi

BUNDLE_PATH="$1"
OUTPUT_PATH="$2"
TENANT_ID="$3"
if [[ ! -d "$BUNDLE_PATH" ]]; then
  echo "The Custodian export bundle directory does not exist." >&2
  exit 2
fi
if [[ -e "$OUTPUT_PATH" ]]; then
  echo "The output path must not already exist; overwrite is refused." >&2
  exit 2
fi

dotnet run --project "$ROOT_DIR/tools/SecRev.NoSqlExport/SecRev.NoSqlExport.csproj" -- "$BUNDLE_PATH" "$OUTPUT_PATH" "$TENANT_ID"
