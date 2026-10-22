#!/usr/bin/env bash
set -euo pipefail

# The devcontainer image supplies the .NET 10 SDK. Install the Linux C++
# compiler and the X11/VNC dependencies needed by Avalonia's desktop backend.
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  build-essential \
  clang \
  cmake \
  pkg-config \
  xvfb \
  x11vnc \
  fluxbox \
  novnc \
  websockify \
  x11-utils \
  libfontconfig1 \
  libfreetype6 \
  libgl1 \
  libice6 \
  libsm6 \
  libx11-6 \
  libxcomposite1 \
  libxcursor1 \
  libxdamage1 \
  libxext6 \
  libxfixes3 \
  libxi6 \
  libxinerama1 \
  libxkbcommon0 \
  libxrandr2 \
  libxrender1 \
  libxtst6
