#!/usr/bin/env bash
set -euo pipefail

RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}"
REASON="${1:-manual}"
if [[ "$REASON" != "manual" && "$REASON" != "--browser-closed" ]]; then
  echo "Usage: $0 [--browser-closed]" >&2
  exit 2
fi

# A browser disconnect must keep x11vnc/noVNC alive so port 6080 can reconnect.
services=(app websockify x11vnc fluxbox xvfb)
if [[ "$REASON" == "--browser-closed" ]]; then
  services=(app)
fi

if [[ "$REASON" == "--browser-closed" ]]; then
  # Serialize with the relaunch hook, and skip if a newer client (e.g. a tab refresh)
  # connected before this disconnect callback ran.
  exec 9>"$RUNTIME_DIR/secrev-app.lock"
  flock 9
  if [[ -n "$(ss -H -tn state established '( sport = :5900 )' 2>/dev/null)" ]]; then
    exit 0
  fi
fi

for service in "${services[@]}"; do
  pid_file="$RUNTIME_DIR/secrev-${service}.pid"
  if [[ ! -f "$pid_file" ]]; then
    continue
  fi

  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in {1..50}; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
  fi
  rm -f "$pid_file"
done
if [[ "$REASON" == "--browser-closed" ]]; then
  printf 'The noVNC browser disconnected; stopped SecRev; it restarts when a browser reconnects.\n'
else
  printf 'Stopped SecRev and its Codespaces virtual desktop processes.\n'
fi
