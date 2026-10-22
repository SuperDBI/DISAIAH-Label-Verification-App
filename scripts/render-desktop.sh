#!/usr/bin/env bash
# Container entrypoint: runs the Avalonia desktop in a virtual display and serves it through noVNC on $PORT.
set -euo pipefail

export DISPLAY=:1
PORT="${PORT:-8080}"
WEB_ROOT=/tmp/novnc

Xvfb :1 -screen 0 1600x960x24 -nolisten tcp -noreset &
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
x11vnc -display :1 -localhost "${VNC_AUTH[@]}" -forever -shared -rfbport 5900 -quiet >/dev/null 2>&1 &

mkdir -p "$WEB_ROOT"
cp -a /usr/share/novnc/. "$WEB_ROOT/"
cat > "$WEB_ROOT/index.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecRev Demo</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1rem; color: #1b1b1b; line-height: 1.5; }
  .start { display: inline-block; margin: 1rem 0; padding: .75rem 1.5rem; background: #1f4e9c; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 600; }
  .note { color: #555; font-size: .9rem; }
</style>
</head>
<body>
<h1>SecRev Demo</h1>
<p>This starts the full SecRev desktop app, streamed to your browser. Nothing connects until you click the button.</p>
<a class="start" href="/vnc.html?autoconnect=true&amp;resize=scale&amp;path=websockify">Start the desktop</a>
<ul class="note">
  <li>The first load can take a minute if the service was asleep, and the stream may feel slow on a small instance.</li>
  <li>This is a disposable demo: the vault and the first-Custodian token reset on every restart or redeploy. Do not use real data.</li>
  <li>The stream needs WebSocket support from the host.</li>
</ul>
</body>
</html>
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
  dotnet /app/SecRev.dll || true
  sleep 1
done
