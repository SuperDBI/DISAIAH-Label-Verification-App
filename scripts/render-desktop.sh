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
<h2>Upload a document to import</h2>
<p>The desktop runs on the server and cannot see your computer. Upload a PDF or text file here, then use Import document in the desktop and pick it from the list.</p>
<form id="up">
  <input type="file" id="file" accept=".pdf,.txt,.md,.csv,.json" required>
  <input type="password" id="pw" placeholder="Viewer password (if one is set)">
  <button type="submit">Upload</button>
</form>
<p id="status" class="note" role="status"></p>
<script>
document.getElementById('up').addEventListener('submit', async e => {
  e.preventDefault();
  const f = document.getElementById('file').files[0];
  const st = document.getElementById('status');
  if (!f) return;
  st.textContent = 'Uploading...';
  try {
    const r = await fetch('/upload', { method: 'POST', body: f, headers: {
      'X-Upload-Name': f.name, 'X-Upload-Password': document.getElementById('pw').value } });
    st.textContent = await r.text();
  } catch (err) { st.textContent = 'Upload failed.'; }
});
</script>
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

# Wrapper adds POST /upload; the app lists these files when the desktop file picker is unavailable.
export SECREV_UPLOAD_DIR=/tmp/secrev-uploads
mkdir -p "$SECREV_UPLOAD_DIR"
chmod 700 "$SECREV_UPLOAD_DIR"
python3 /usr/local/bin/websockify-upload.py --web="$WEB_ROOT" "$PORT" 127.0.0.1:5900 &

# Local PDF services (ClamAV + parser) run in this container; Docker-in-Docker is unavailable on DigitalOcean App Platform.
# Everything binds to loopback and shares a per-start token with the app.
PDF_STATE=/tmp/secrev-pdf
mkdir -p "$PDF_STATE/database" "$PDF_STATE/tmp"
chmod 700 "$PDF_STATE" "$PDF_STATE/database" "$PDF_STATE/tmp"
PDF_SANDBOX_TOKEN="$(openssl rand -hex 32)"
export PDF_SANDBOX_TOKEN
export SECREV_PDF_PARSER_ENDPOINT="http://127.0.0.1:5080"
export SECREV_PDF_PARSER_TOKEN="$PDF_SANDBOX_TOKEN"
export SECREV_PDF_SERVICES_MANAGED=1

start_pdf_services() {
  cat > "$PDF_STATE/freshclam.conf" <<EOF
DatabaseDirectory $PDF_STATE/database
DatabaseMirror database.clamav.net
Foreground yes
Checks 1
# Skip freshclam's test-load of the whole database, which briefly needs as much RAM as clamd itself.
TestDatabases no
EOF
  cat > "$PDF_STATE/clamd.conf" <<EOF
DatabaseDirectory $PDF_STATE/database
TemporaryDirectory $PDF_STATE/tmp
Foreground yes
TCPSocket 3310
TCPAddr 127.0.0.1
StreamMaxLength 30M
MaxFileSize 30M
MaxScanSize 100M
MaxThreads 1
MaxQueue 2
ConcurrentDatabaseReload no
DetectPUA no
ScanArchive no
ScanMail no
ScanHTML no
ScanOLE2 no
ScanPE no
ScanELF no
EOF
  # Fail closed: without signatures the parser is never started, so no PDF is parsed.
  local attempt
  for attempt in 1 2 3; do
    freshclam --config-file="$PDF_STATE/freshclam.conf" >"$PDF_STATE/freshclam.log" 2>&1 && break
    [[ "$attempt" == 3 ]] && { echo "ClamAV signature download failed; PDF scanning stays unavailable."; return 0; }
    sleep 15
  done
  # clamd is started by the parser per scan and stopped when idle, so its ~1 GB is not held while idle.
  ENABLE_LOCAL_CLAMAV=true CLAMAV_ONDEMAND_CONF="$PDF_STATE/clamd.conf" CLAMAV_BINARY="$(command -v clamd)" CLAMAV_HOST=127.0.0.1 CLAMAV_PORT=3310 \
    TESSERACT_PATH=/usr/bin/tesseract TMPDIR="$PDF_STATE/tmp" \
    DOTNET_GCHeapHardLimit=0x10000000 DOTNET_GCConserveMemory=9 DOTNET_gcConcurrent=0 DOTNET_TieredPGO=0 MALLOC_ARENA_MAX=2 \
    dotnet /opt/pdf-sandbox/PdfSandbox.dll --urls "$SECREV_PDF_PARSER_ENDPOINT" >"$PDF_STATE/parser.log" 2>&1 &
}
start_pdf_services &

# Memory budget log (RSS per process) so the Runtime Logs show who uses the 2 GB.
( while true; do
    sleep 60
    echo "mem: $(ps -eo rss,comm --sort=-rss | awk 'NR>1 && NR<=7 {printf "%s=%dMB ", $2, $1/1024}')"
  done ) &

# Relaunch the app if it is closed so the browser never shows an empty desktop.
while true; do
  # Per-process GC caps: .NET otherwise sizes each process against the whole container limit.
  code=0
  DOTNET_GCHeapHardLimit=0x18000000 DOTNET_GCConserveMemory=9 DOTNET_gcConcurrent=0 DOTNET_TieredPGO=0 MALLOC_ARENA_MAX=2 dotnet /app/SecRev.dll || code=$?
  echo "SecRev exited with code $code (137 = killed, usually out of memory). Memory: $(free -m | awk 'NR==2{print $3"/"$2" MB used"}')"
  sleep 1
done
