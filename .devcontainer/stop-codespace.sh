#!/usr/bin/env bash
set -euo pipefail

RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}"
REASON="${1:-manual}"
if [[ "$REASON" != "manual" && "$REASON" != "--browser-closed" ]]; then
  echo "Usage: $0 [--browser-closed]" >&2
  exit 2
fi

for service in app websockify x11vnc fluxbox xvfb; do
  pid_file="$RUNTIME_DIR/secrev-${service}.pid"
  if [[ ! -f "$pid_file" ]]; then
    continue
  fi

  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
  fi
  rm -f "$pid_file"
done
if [[ "$REASON" == "--browser-closed" ]]; then
  printf 'The noVNC browser disconnected; stopped SecRev and its virtual desktop session.\n'
else
  printf 'Stopped SecRev and its Codespaces virtual desktop processes.\n'
fi
