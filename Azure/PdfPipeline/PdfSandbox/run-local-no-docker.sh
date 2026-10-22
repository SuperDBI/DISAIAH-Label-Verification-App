#!/bin/bash
set -euo pipefail

UPDATE_SIGNATURES_ONLY=false
SERVICES_ONLY=false
for argument in "$@"; do
  case "$argument" in
    --update-signatures-only) UPDATE_SIGNATURES_ONLY=true ;;
    --services-only) SERVICES_ONLY=true ;;
    *) echo "Usage: $0 [--update-signatures-only] [--services-only]" >&2; exit 2 ;;
  esac
done
if [[ "$UPDATE_SIGNATURES_ONLY" == true && "$SERVICES_ONLY" == true ]]; then
  echo "--update-signatures-only cannot be combined with --services-only." >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
STATE_DIR="${SECREV_LOCAL_STATE_DIR:-$HOME/Library/Application Support/SecRev/local-services}"
CLAMD_BIN="${CLAMD_BIN:-$(command -v clamd || true)}"
FRESHCLAM_BIN="${FRESHCLAM_BIN:-$(command -v freshclam || true)}"
TESSERACT_BIN="${TESSERACT_PATH:-$(command -v tesseract || true)}"

if [[ -z "$CLAMD_BIN" || -z "$FRESHCLAM_BIN" ]]; then
  BREW_CLAMAV_PREFIX="$(brew --prefix clamav 2>/dev/null || true)"
  if [[ -z "$CLAMD_BIN" && -x "$BREW_CLAMAV_PREFIX/sbin/clamd" ]]; then
    CLAMD_BIN="$BREW_CLAMAV_PREFIX/sbin/clamd"
  fi
  if [[ -z "$FRESHCLAM_BIN" && -x "$BREW_CLAMAV_PREFIX/sbin/freshclam" ]]; then
    FRESHCLAM_BIN="$BREW_CLAMAV_PREFIX/sbin/freshclam"
  fi
fi

if [[ -z "$CLAMD_BIN" || -z "$FRESHCLAM_BIN" || -z "$TESSERACT_BIN" ]]; then
  cat >&2 <<'EOF'
Missing local PDF workflow dependencies. Install Homebrew ClamAV and Tesseract first:
  brew install clamav tesseract
Then start this script again. The Tesseract formula includes English language data.
EOF
  exit 1
fi

if ! "$TESSERACT_BIN" --list-langs 2>/dev/null | grep -qx 'eng'; then
  echo "Tesseract English language data ('eng') is required." >&2
  exit 1
fi

mkdir -p "$STATE_DIR/database" "$STATE_DIR/tmp"
chmod 700 "$STATE_DIR" "$STATE_DIR/database" "$STATE_DIR/tmp"
export TMPDIR="$STATE_DIR/tmp"
export TESSERACT_PATH="$TESSERACT_BIN"
if [[ -z "${PDF_SANDBOX_TOKEN:-}" ]]; then
  PDF_SANDBOX_TOKEN="$(openssl rand -hex 32)"
fi
if [[ ${#PDF_SANDBOX_TOKEN} -lt 32 ]]; then
  echo "PDF_SANDBOX_TOKEN must contain at least 32 characters." >&2
  exit 2
fi
export PDF_SANDBOX_TOKEN
export SECREV_PDF_PARSER_ENDPOINT="http://127.0.0.1:5080"
export SECREV_PDF_PARSER_TOKEN="$PDF_SANDBOX_TOKEN"
export ENABLE_LOCAL_CLAMAV=true
export CLAMAV_HOST=127.0.0.1
export CLAMAV_PORT=3310
export ASPNETCORE_URLS=http://127.0.0.1:5080

CLAMD_CONF="$STATE_DIR/clamd.conf"
FRESHCLAM_CONF="$STATE_DIR/freshclam.conf"
cat > "$CLAMD_CONF" <<EOF
DatabaseDirectory $STATE_DIR/database
LogFile $STATE_DIR/clamd.log
LogFileMaxSize 5M
LogTime yes
PidFile $STATE_DIR/clamd.pid
TemporaryDirectory $STATE_DIR/tmp
Foreground yes
TCPSocket 3310
TCPAddr 127.0.0.1
StreamMaxLength 30M
MaxFileSize 30M
MaxScanSize 100M
MaxThreads 4
MaxQueue 8
EOF
cat > "$FRESHCLAM_CONF" <<EOF
DatabaseDirectory $STATE_DIR/database
UpdateLogFile $STATE_DIR/freshclam.log
PidFile $STATE_DIR/freshclam.pid
DatabaseMirror database.clamav.net
Foreground yes
Checks 1
EOF
chmod 600 "$CLAMD_CONF" "$FRESHCLAM_CONF"

parser_pid=""
clamd_pid=""
cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if [[ -n "$parser_pid" ]] && kill -0 "$parser_pid" 2>/dev/null; then
    kill -TERM "$parser_pid" 2>/dev/null || true
    wait "$parser_pid" 2>/dev/null || true
  fi
  if [[ -n "$clamd_pid" ]] && kill -0 "$clamd_pid" 2>/dev/null; then
    kill -TERM "$clamd_pid" 2>/dev/null || true
    wait "$clamd_pid" 2>/dev/null || true
  fi
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

printf 'Updating local ClamAV signatures...\n'
if ! "$FRESHCLAM_BIN" --config-file="$FRESHCLAM_CONF"; then
  if [[ -s "$STATE_DIR/database/main.cvd" || -s "$STATE_DIR/database/main.cld" ]]; then
    printf 'Signature update failed; continuing with the previously downloaded local database.\n' >&2
  else
    echo "No existing ClamAV database is available; refusing to start without downloaded signatures." >&2
    exit 1
  fi
fi
if [[ "$UPDATE_SIGNATURES_ONLY" == true ]]; then
  printf 'ClamAV signatures are stored persistently at: %s/database\n' "$STATE_DIR"
  exit 0
fi
printf 'Starting local ClamAV daemon on 127.0.0.1:3310...\n'
"$CLAMD_BIN" --config-file="$CLAMD_CONF" &
clamd_pid=$!

python3 - <<'PY'
import socket, sys, time
for _ in range(60):
    try:
        with socket.create_connection(("127.0.0.1", 3310), timeout=1):
            sys.exit(0)
    except OSError:
        time.sleep(1)
print("ClamAV did not listen on 127.0.0.1:3310 within 60 seconds.", file=sys.stderr)
sys.exit(1)
PY

printf 'Building the local parser...\n'
dotnet build "$ROOT_DIR/Azure/PdfPipeline/PdfSandbox/PdfSandbox.csproj"
printf 'Starting local PDF parser at %s (no Docker).\n' "$SECREV_PDF_PARSER_ENDPOINT"
dotnet "$ROOT_DIR/Azure/PdfPipeline/PdfSandbox/bin/Debug/net10.0/PdfSandbox.dll" --urls "$ASPNETCORE_URLS" &
parser_pid=$!

python3 - <<'PY'
import sys, time, urllib.request
url = "http://127.0.0.1:5080/health/live"
for _ in range(60):
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            if response.status == 200:
                sys.exit(0)
    except Exception:
        time.sleep(1)
print("The local PDF parser did not become healthy within 60 seconds.", file=sys.stderr)
sys.exit(1)
PY

printf '\nLocal PDF services are ready. The parser, ClamAV and desktop app share this temporary token in memory.\nClose the desktop app or press Ctrl+C here to stop the services.\n\n'
if [[ "$SERVICES_ONLY" == true ]]; then
  wait "$parser_pid"
  exit $?
fi
dotnet run --project "$ROOT_DIR/SecRev.csproj"
