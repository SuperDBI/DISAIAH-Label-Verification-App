#!/usr/bin/env bash
# Container entrypoint: runs the Avalonia desktop in a virtual display and serves it through noVNC on $PORT.
set -euo pipefail

export DISPLAY=:1
PORT="${PORT:-10000}"
WEB_ROOT=/tmp/novnc

Xvfb :1 -screen 0 1280x720x16 -nolisten tcp -noreset &
for _ in $(seq 1 100); do
  xdpyinfo >/dev/null 2>&1 && break
  sleep 0.1
done
fluxbox >/dev/null 2>&1 &

# VNC listens on loopback only; if VNC_PASSWORD is set, noVNC prompts for it.
VNC_AUTH=(-nopw)
if [[ -n "${VNC_PASSWORD:-}" ]]; then
  x11vnc -storepasswd "$VNC_PASSWORD" /tmp/vncpass >/dev/null 2>&1
  VNC_AUTH=(-rfbauth /tmp/vncpass)
fi
x11vnc -display :1 -localhost "${VNC_AUTH[@]}" -forever -shared -rfbport 5900 -quiet -noxdamage -wait 50 -defer 50 -nocursorshape -noxfixes >/dev/null 2>&1 &

mkdir -p "$WEB_ROOT"
cp -a /usr/share/novnc/. "$WEB_ROOT/"
cat > "$WEB_ROOT/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0; url=/vnc.html?autoconnect=true&resize=scale&path=websockify&quality=2&compression=9">
<title>SecRev Desktop</title>
<a href="/vnc.html?autoconnect=true&resize=scale&path=websockify&quality=2&compression=9">Open SecRev desktop</a>
HTML

# Demo only: each container start gets a fresh bootstrap token that the app prefills into the first-Custodian form.
# It is also printed to the service log. VNC_PASSWORD is optional; if unset, no viewer password is required.
export SECREV_PREFILL_BOOTSTRAP_TOKEN=1
if [[ -z "${SECREV_BOOTSTRAP_TOKEN:-}" ]]; then
  SECREV_BOOTSTRAP_TOKEN="$(openssl rand -hex 32)"
  export SECREV_BOOTSTRAP_TOKEN
  echo "SecRev bootstrap token (first Custodian): $SECREV_BOOTSTRAP_TOKEN"
fi

websockify --web="$WEB_ROOT" "$PORT" 127.0.0.1:5900 &

# Relaunch the app if it is closed so the browser never shows an empty desktop.
while true; do
  env SECREV_SOFTWARE_RENDER=1 DOTNET_TieredPGO=0 dotnet /app/SecRev.dll || true
  sleep 1
done
