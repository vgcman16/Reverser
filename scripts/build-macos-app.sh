#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This build script must be run on macOS because it creates a native .app bundle." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PYTHON_BIN="${PYTHON:-python3}"
VENV_DIR="${VENV_DIR:-.venv-macos-app}"

"${PYTHON_BIN}" -m venv "${VENV_DIR}"
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"

python -m pip install --upgrade pip wheel
python -m pip install -e ".[gui,macos-app]"

python -m PyInstaller --noconfirm --clean packaging/macos/Reverser.spec

APP_PATH="${ROOT_DIR}/dist/Reverser.app"
ZIP_PATH="${ROOT_DIR}/dist/Reverser-macos.zip"

if [[ ! -x "${APP_PATH}/Contents/MacOS/Reverser" ]]; then
  echo "Expected app executable was not created: ${APP_PATH}/Contents/MacOS/Reverser" >&2
  exit 1
fi

rm -f "${ZIP_PATH}"
ditto -c -k --keepParent "${APP_PATH}" "${ZIP_PATH}"

echo "Built ${APP_PATH}"
echo "Packaged ${ZIP_PATH}"
