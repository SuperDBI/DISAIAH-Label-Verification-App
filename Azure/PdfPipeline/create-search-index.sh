#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 https://<search-service>.search.windows.net" >&2
  exit 2
fi
endpoint=${1%/}
api_version=${AZURE_SEARCH_API_VERSION:-2024-07-01}
index_file=$(dirname "$0")/search-index.json

# Requires Azure CLI login and Search Service Contributor (or a narrower index-management role).
# Uses Microsoft Entra auth; no admin API key is placed in source or shell arguments.
az rest \
  --method put \
  --url "$endpoint/indexes/pdf-records?api-version=$api_version" \
  --headers 'Content-Type=application/json' \
  --body "@$index_file"
