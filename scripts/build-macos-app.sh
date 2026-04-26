#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
BUILD_DIR="$ROOT_DIR/build/pyinstaller-macos"
SPEC_FILE="$ROOT_DIR/packaging/macos/Reverser.spec"
APP_BUNDLE="$DIST_DIR/Reverser.app"
ZIP_PATH="$DIST_DIR/Reverser-macos.zip"

cd "$ROOT_DIR"

python -m pip install -U pip
python -m pip install -e ".[gui,macos-app]"

rm -rf "$BUILD_DIR" "$APP_BUNDLE" "$ZIP_PATH"

pyinstaller \
  --noconfirm \
  --clean \
  --distpath "$DIST_DIR" \
  --workpath "$BUILD_DIR" \
  "$SPEC_FILE"

ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$ZIP_PATH"

echo "Built $APP_BUNDLE"
echo "Wrote $ZIP_PATH"
