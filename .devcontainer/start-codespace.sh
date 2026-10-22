#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DISPLAY="${DISPLAY:-:1}"
RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}"
WEB_ROOT="$RUNTIME_DIR/secrev-novnc"

start_background() {
  local pid_file="$1"
  local log_file="$2"
  shift 2

  if [[ -f "$pid_file" ]]; then
    local existing_pid
    existing_pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ "$existing_pid" =~ ^[0-9]+$ ]] && kill -0 "$existing_pid" 2>/dev/null; then
      return
    fi
    rm -f "$pid_file"
  fi

  # x11vnc installs its own SIGHUP handler (nohup is ignored), so detach into a new session.
  setsid nohup "$@" >>"$log_file" 2>&1 </dev/null 9>&- &
  echo "$!" > "$pid_file"
}

provision_demo_bootstrap_token() {
  # Demo-only: the token lives in the runtime dir (cleared on rebuild), so each rebuilt
  # Codespace gets a fresh one that the app prefills into the first-Custodian form.
  local token_file="$RUNTIME_DIR/secrev-bootstrap-token"
  if [[ -z "${SECREV_BOOTSTRAP_TOKEN:-}" ]]; then
    if [[ ! -s "$token_file" ]]; then
      (umask 077 && openssl rand -hex 32 > "$token_file")
    fi
    chmod 600 "$token_file"
    SECREV_BOOTSTRAP_TOKEN="$(cat "$token_file")"
  fi
  export SECREV_BOOTSTRAP_TOKEN
  export SECREV_PREFILL_BOOTSTRAP_TOKEN=1
}

start_app() {
  # Rebuild if the executable is absent, then launch the Avalonia desktop in the virtual display.
  if ! pgrep -f '[S]ecRev.dll|/SecRev$' >/dev/null 2>&1; then
    provision_demo_bootstrap_token
    if [[ ! -f "$ROOT_DIR/bin/Debug/net10.0/SecRev.dll" ]]; then
      dotnet build "$ROOT_DIR/SecRev.csproj"
    fi
    rm -f "$RUNTIME_DIR/secrev-app.pid"
    start_background "$RUNTIME_DIR/secrev-app.pid" "$RUNTIME_DIR/secrev-app.log" \
      env DISPLAY=:1 dotnet "$ROOT_DIR/bin/Debug/net10.0/SecRev.dll"
  fi
}

# Invoked by x11vnc -afteraccept when a browser connects: relaunch SecRev if it exited.
if [[ "${1:-}" == "--app-only" ]]; then
  exec 9>"$RUNTIME_DIR/secrev-app.lock"
  flock 9
  start_app
  exit 0
fi

if ! pgrep -f '[X]vfb :1' >/dev/null 2>&1; then
  rm -f /tmp/.X1-lock /tmp/.X11-unix/X1
  start_background "$RUNTIME_DIR/secrev-xvfb.pid" "$RUNTIME_DIR/secrev-xvfb.log" \
    Xvfb :1 -screen 0 1920x1080x24 -nolisten tcp -noreset
fi

# Wait briefly for Xvfb to accept local X clients, without exposing an X11 TCP listener.
for _ in {1..100}; do
  if DISPLAY=:1 xdpyinfo >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if ! DISPLAY=:1 xdpyinfo >/dev/null 2>&1; then
  echo "Xvfb did not start on display :1; inspect /tmp/secrev-xvfb.log." >&2
  exit 1
fi

# Fluxbox's packaged style requests a wallpaper, which makes fbsetbg open an
# error dialog when no wallpaper setter is installed in the Codespace.
mkdir -p "$HOME/.fluxbox"
if ! grep -Eq '^[[:space:]]*background:[[:space:]]*none([[:space:]]|$)' "$HOME/.fluxbox/overlay" 2>/dev/null; then
  printf '\nbackground: none\n' >> "$HOME/.fluxbox/overlay"
fi

if ! pgrep -f '[f]luxbox.*:1' >/dev/null 2>&1; then
  start_background "$RUNTIME_DIR/secrev-fluxbox.pid" "$RUNTIME_DIR/secrev-fluxbox.log" \
    env DISPLAY=:1 fluxbox
fi

if ! pgrep -f '[x]11vnc.*5900' >/dev/null 2>&1; then
  # VNC itself is loopback-only and has no password. Codespaces forwards only the
  # private noVNC HTTP port below; do not expose port 5900 or change the port to public.
  start_background "$RUNTIME_DIR/secrev-x11vnc.pid" "$RUNTIME_DIR/secrev-x11vnc.log" \
    x11vnc -display :1 -localhost -nopw -forever -shared -rfbport 5900 \
      -afteraccept "bash $ROOT_DIR/.devcontainer/start-codespace.sh --app-only" \
      -gone "bash $ROOT_DIR/.devcontainer/stop-codespace.sh --browser-closed"
fi

mkdir -p "$WEB_ROOT"
cp -a /usr/share/novnc/. "$WEB_ROOT/"
cat > "$WEB_ROOT/index.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SecRev Codespaces Desktop</title>
  <meta http-equiv="refresh" content="0; url=/vnc.html?autoconnect=true&amp;resize=scale&amp;path=websockify">
</head>
<body>
  <p>Opening the SecRev virtual desktop… If it does not open, <a href="/vnc.html?autoconnect=true&amp;resize=scale&amp;path=websockify">open noVNC</a>.</p>
</body>
</html>
HTML

if ! pgrep -f '[w]ebsockify.*6080' >/dev/null 2>&1; then
  start_background "$RUNTIME_DIR/secrev-websockify.pid" "$RUNTIME_DIR/secrev-websockify.log" \
    websockify --web="$WEB_ROOT" 6080 127.0.0.1:5900
fi

start_app

printf 'SecRev Codespaces desktop started. Open private forwarded port 6080 to view it.\n'
printf 'App log: %s/secrev-app.log\n' "$RUNTIME_DIR"
