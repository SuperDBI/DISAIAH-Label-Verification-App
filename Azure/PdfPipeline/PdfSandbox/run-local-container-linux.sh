#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.local.yml"
PROJECT_NAME="secrev-local-pdf"

usage() {
  echo "Usage: $0 [--services-only | --stop]" >&2
}

MODE="services"
case "${1:-}" in
  "") ;;
  --services-only) MODE="services" ;;
  --stop) MODE="stop" ;;
  *) usage; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then usage; exit 2; fi

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Docker Engine and the Docker Compose plugin are required for local PDF services on Linux." >&2
  echo "Install/start Docker, then retry. The parser and ClamAV run in restricted local containers." >&2
  exit 1
fi

# The app supplies an ephemeral per-session token. Generate one for manual use only.
if [[ -z "${PDF_SANDBOX_TOKEN:-}" ]]; then
  PDF_SANDBOX_TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
fi
if [[ ${#PDF_SANDBOX_TOKEN} -lt 32 ]]; then
  echo "PDF_SANDBOX_TOKEN must contain at least 32 characters." >&2
  exit 2
fi
export PDF_SANDBOX_TOKEN

compose() {
  docker compose --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE" "$@"
}

if [[ "$MODE" == "stop" ]]; then
  compose down --remove-orphans
  exit $?
fi

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  compose down --remove-orphans >/dev/null 2>&1 || true
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed but its Linux engine is not running or accessible." >&2
  exit 1
fi

echo "Building and starting the local PDF parser and ClamAV containers..."
compose up --build
