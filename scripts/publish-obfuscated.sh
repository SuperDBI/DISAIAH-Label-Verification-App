#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RID="${1:-}"
OUTPUT_DIR="${2:-}"
if [[ -z "$RID" || -z "$OUTPUT_DIR" ]]; then
  echo "Usage: $0 <runtime-id> <output-directory>" >&2
  echo "Example: $0 osx-arm64 ./artifacts/SecRev-osx-arm64" >&2
  exit 2
fi

case "$RID" in
  osx-arm64|osx-x64|linux-x64|linux-arm64)
    if [[ "$(uname -s)" != "Darwin" && "$(uname -s)" != "Linux" ]]; then
      echo "Build macOS/Linux RIDs on macOS or Linux with the matching native C++ toolchain." >&2
      exit 2
    fi
    ;;
  win-x64|win-arm64)
    echo "Build Windows RIDs with publish-obfuscated.ps1 on Windows/MSVC." >&2
    exit 2
    ;;
  *) echo "Unsupported runtime identifier: $RID" >&2; exit 2 ;;
esac

HOST_ARCH="$(uname -m)"
case "$RID:$HOST_ARCH" in
  osx-arm64:arm64|osx-x64:x86_64|linux-arm64:aarch64|linux-arm64:arm64|linux-x64:x86_64) ;;
  *) echo "RID $RID does not match this host architecture ($HOST_ARCH); native core cross-compilation is not configured." >&2; exit 2 ;;
esac

case "$RID" in
  osx-arm64|osx-x64) [[ "$(uname -s)" == "Darwin" ]] || { echo "macOS RIDs must be built on macOS." >&2; exit 2; } ;;
  linux-x64|linux-arm64) [[ "$(uname -s)" == "Linux" ]] || { echo "Linux RIDs must be built on Linux." >&2; exit 2; } ;;
esac

OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"
WORK_DIR="$ROOT_DIR/artifacts/obfuscation/$RID"
PUBLISH_DIR="$WORK_DIR/publish"
OBFUSCATED_DIR="$WORK_DIR/obfuscated"
CONFIG_FILE="$WORK_DIR/obfuscar.xml"
rm -rf "$WORK_DIR"
mkdir -p "$PUBLISH_DIR" "$OBFUSCATED_DIR"

cd "$ROOT_DIR"
dotnet tool restore
dotnet publish SecRev.csproj -c Release -r "$RID" --self-contained false -o "$PUBLISH_DIR" -p:DebugType=None -p:DebugSymbols=false

cat > "$CONFIG_FILE" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<Obfuscator>
  <Var name="InPath" value="$PUBLISH_DIR" />
  <Var name="OutPath" value="$OBFUSCATED_DIR" />
  <Var name="KeepPublicApi" value="true" />
  <Var name="HidePrivateApi" value="true" />
  <Var name="MarkedOnly" value="true" />
  <Var name="HideStrings" value="false" />
  <Var name="SkipGenerated" value="true" />
  <Var name="SkipSpecialName" value="true" />
  <Module file="$PUBLISH_DIR/SecRev.dll" />
</Obfuscator>
EOF

dotnet tool run obfuscar.console -- "$CONFIG_FILE"
cp -a "$PUBLISH_DIR/." "$OUTPUT_DIR/"
cp "$OBFUSCATED_DIR/SecRev.dll" "$OUTPUT_DIR/SecRev.dll"
find "$OUTPUT_DIR" -type f \( -name '*.pdb' -o -name 'Obfuscar*.xml' -o -name '*.map' \) -delete
printf 'Obfuscated release published to %s\n' "$OUTPUT_DIR"
printf 'Keep the private original symbols and obfuscation mapping from %s outside the distribution.\n' "$WORK_DIR"
