#!/usr/bin/env bash
# Creates one Droplet (single SecRev container) plus a 1 GiB block-storage volume that holds the encrypted vault.
# 1 GiB is DigitalOcean's minimum volume size. Requires an authenticated `doctl`.
#
#   [VNC_PASSWORD='long-random-value'] [DOMAIN=secrev.example.com] [ADMIN_CIDR=203.0.113.4/32] ./deploy.sh
# VNC_PASSWORD is optional; when unset, no viewer password is required.
set -euo pipefail

VNC_PASSWORD="${VNC_PASSWORD:-}"
if [[ -n "$VNC_PASSWORD" && ( ${#VNC_PASSWORD} -lt 12 || "$VNC_PASSWORD" =~ [^A-Za-z0-9._@%+=-] ) ]]; then
  echo "VNC_PASSWORD (optional) must be 12+ characters from A-Z a-z 0-9 . _ @ % + = -" >&2; exit 1
fi

NAME="${NAME:-secrev}"
REGION="${REGION:-nyc3}"
SIZE="${SIZE:-s-2vcpu-4gb}"
IMAGE="${IMAGE:-ubuntu-24-04-x64}"
REPO_URL="${REPO_URL:-https://github.com/SuperDBI/DISAIAH-Label-Verification-App.git}"
BRANCH="${BRANCH:-main}"
DOMAIN="${DOMAIN:-}"
ADMIN_CIDR="${ADMIN_CIDR:-}"
VOLUME_NAME="${NAME}-vault"
HERE="$(cd "$(dirname "$0")" && pwd)"

USERDATA="$(mktemp)"; trap 'rm -f "$USERDATA"' EXIT
chmod 600 "$USERDATA"
sed -e "s|__REPO_URL__|$REPO_URL|g" -e "s|__BRANCH__|$BRANCH|g" \
    -e "s|__VOLUME_NAME__|$VOLUME_NAME|g" -e "s|__VNC_PASSWORD__|$VNC_PASSWORD|g" \
    -e "s|__DOMAIN__|$DOMAIN|g" "$HERE/cloud-init.yaml.tpl" > "$USERDATA"

doctl compute volume create "$VOLUME_NAME" --region "$REGION" --size 1GiB \
  --fs-type ext4 --desc "SecRev encrypted vault" >/dev/null
VOLUME_ID="$(doctl compute volume list --format ID,Name --no-header | awk -v n="$VOLUME_NAME" '$2==n{print $1}')"

DROPLET_ID="$(doctl compute droplet create "$NAME" --region "$REGION" --size "$SIZE" --image "$IMAGE" \
  --volumes "$VOLUME_ID" --user-data-file "$USERDATA" --tag-name secrev --wait \
  --format ID --no-header)"

# Firewall: HTTP/HTTPS only when a domain is set; SSH only from ADMIN_CIDR when provided.
RULES=()
if [[ -n "$DOMAIN" ]]; then
  RULES+=(--inbound-rules "protocol:tcp,ports:80,address:0.0.0.0/0,address:::/0" \
          --inbound-rules "protocol:tcp,ports:443,address:0.0.0.0/0,address:::/0")
fi
if [[ -n "$ADMIN_CIDR" ]]; then
  RULES+=(--inbound-rules "protocol:tcp,ports:22,address:$ADMIN_CIDR")
fi
doctl compute firewall create --name "$NAME-fw" --droplet-ids "$DROPLET_ID" "${RULES[@]}" \
  --outbound-rules "protocol:tcp,ports:all,address:0.0.0.0/0,address:::/0" \
  --outbound-rules "protocol:udp,ports:53,address:0.0.0.0/0,address:::/0" >/dev/null

if [[ -z "$VNC_PASSWORD" && -n "$DOMAIN" ]]; then
  echo "WARNING: no VNC_PASSWORD set and DOMAIN is public: anyone with the URL can use the desktop." >&2
fi

IP="$(doctl compute droplet get "$DROPLET_ID" --format PublicIPv4 --no-header)"
echo "Droplet $DROPLET_ID at $IP. First boot builds the image (about 10 minutes)."
if [[ -n "$DOMAIN" ]]; then
  echo "Point a DNS A record for $DOMAIN to $IP, then open https://$DOMAIN"
else
  echo "No DOMAIN set: the stream is not exposed. Tunnel with: ssh -L 8080:127.0.0.1:8080 root@$IP  (needs ADMIN_CIDR for port 22), then open http://localhost:8080"
fi
