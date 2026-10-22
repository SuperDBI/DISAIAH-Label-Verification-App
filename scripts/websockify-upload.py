#!/usr/bin/env python3
"""websockify with a POST /upload endpoint so the browser-streamed desktop can import local files.

The Avalonia file picker needs a desktop portal that the single demo container does not have, and the
container cannot see the visitor's disk. Uploaded files land in SECREV_UPLOAD_DIR, which the app lists.
Uploaded files are untrusted: they are only stored here, never parsed or executed by this script.
"""
import hmac
import os
import re
import secrets
import sys

from websockify import websocketproxy

UPLOAD_DIR = os.environ.get("SECREV_UPLOAD_DIR", "/tmp/secrev-uploads")
MAX_BYTES = 25 * 1024 * 1024
MAX_FILES = 20
PASSWORD = os.environ.get("VNC_PASSWORD", "")
ALLOWED = {".pdf", ".txt", ".md", ".csv", ".json"}


def _reply(handler, code, text):
    body = text.encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    handler.wfile.write(body)


def do_POST(self):
    if self.path.split("?")[0] != "/upload":
        return _reply(self, 404, "Not found")
    # The raw body is the file; name and password travel in headers so no multipart parsing is needed.
    if PASSWORD and not hmac.compare_digest(self.headers.get("X-Upload-Password", ""), PASSWORD):
        return _reply(self, 403, "Invalid password")
    try:
        length = int(self.headers.get("Content-Length", ""))
    except ValueError:
        return _reply(self, 411, "Content-Length required")
    if length <= 0 or length > MAX_BYTES:
        return _reply(self, 413, "File must be 1 byte to 25 MiB")
    name = os.path.basename(self.headers.get("X-Upload-Name", ""))
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)[:100]
    if os.path.splitext(name)[1].lower() not in ALLOWED:
        return _reply(self, 415, "Only .pdf, .txt, .md, .csv and .json files are accepted")
    os.makedirs(UPLOAD_DIR, mode=0o700, exist_ok=True)
    if len(os.listdir(UPLOAD_DIR)) >= MAX_FILES:
        return _reply(self, 429, "Too many pending uploads; import or wait for them to be removed")
    target = os.path.join(UPLOAD_DIR, f"{secrets.token_hex(4)}-{name}")
    remaining = length
    with open(target, "xb") as out:
        os.fchmod(out.fileno(), 0o600)
        while remaining:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            out.write(chunk)
            remaining -= len(chunk)
    if remaining:
        os.remove(target)
        return _reply(self, 400, "Upload was incomplete")
    _reply(self, 200, "Uploaded. In the desktop, choose Import document and select the file.")


websocketproxy.ProxyRequestHandler.do_POST = do_POST

if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, mode=0o700, exist_ok=True)
    websocketproxy.websockify_init()
    sys.exit(0)
