#cloud-config
# Rendered by deploy.sh. Placeholders: __REPO_URL__, __BRANCH__, __VOLUME_NAME__, __VNC_PASSWORD__, __DOMAIN__
package_update: true
packages:
  - docker.io
  - git
  - curl
write_files:
  - path: /etc/secrev/secrev.env
    permissions: "0600"
    content: |
      VNC_PASSWORD=__VNC_PASSWORD__
  - path: /usr/local/bin/secrev-setup.sh
    permissions: "0755"
    content: |
      #!/usr/bin/env bash
      set -euxo pipefail
      DEV=/dev/disk/by-id/scsi-0DO_Volume___VOLUME_NAME__
      MNT=/mnt/secrev_data
      for _ in $(seq 1 60); do [ -e "$DEV" ] && break; sleep 2; done
      # Format only a blank volume so a re-attached volume keeps its vault.
      blkid "$DEV" >/dev/null 2>&1 || mkfs.ext4 -q "$DEV"
      mkdir -p "$MNT"
      grep -q "$MNT" /etc/fstab || echo "$DEV $MNT ext4 defaults,nofail,discard,noatime 0 2" >> /etc/fstab
      mountpoint -q "$MNT" || mount "$MNT"
      # 1654 is the non-root "app" user in the .NET container image.
      mkdir -p "$MNT/vault"
      chown -R 1654:1654 "$MNT/vault"
      chmod 700 "$MNT/vault"
      systemctl enable --now docker
      rm -rf /opt/secrev
      git clone --depth 1 --branch "__BRANCH__" "__REPO_URL__" /opt/secrev
      docker build -f /opt/secrev/Dockerfile.desktop -t secrev-desktop /opt/secrev
      docker rm -f secrev 2>/dev/null || true
      # Published on loopback only; Caddy (HTTPS) or an SSH tunnel is the way in.
      docker run -d --name secrev --restart unless-stopped \
        --env-file /etc/secrev/secrev.env \
        --shm-size=512m \
        --cap-drop=ALL --security-opt=no-new-privileges \
        -p 127.0.0.1:8080:8080 \
        -v "$MNT/vault:/data/.config/SecRev" \
        secrev-desktop
      if [ -n "__DOMAIN__" ]; then
        apt-get install -y caddy
        printf '__DOMAIN__ {\n\treverse_proxy 127.0.0.1:8080\n}\n' > /etc/caddy/Caddyfile
        systemctl restart caddy
      fi
runcmd:
  - [ /usr/local/bin/secrev-setup.sh ]
