#!/usr/bin/env bash
# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: CC0-1.0
#
# Build a single, self-contained check_routeros executable with all
# dependencies (Click, librouteros, nagiosplugin, ...) and the Python
# interpreter itself bundled inside, using PyInstaller. The result is a
# standalone binary that runs without a separate Python installation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

VENV_DIR="${SCRIPT_DIR}/.venv"
DIST_DIR="${SCRIPT_DIR}/dist"
BUILD_DIR="${SCRIPT_DIR}/build"
OUTPUT_FILE="${DIST_DIR}/check_routeros"

# 2. Create Virtual Environment
if [[ ! -d "${VENV_DIR}" ]]; then
    echo "Creating virtual environment in ${VENV_DIR} ..."
    python3 -m venv "${VENV_DIR}"
fi
source $VENV_DIR/bin/activate

# 3. Install Dependencies
pip install --upgrade pip
pip install pyinstaller
pip install -r "${SCRIPT_DIR}/requirements.txt"


rm -rf "${DIST_DIR}" "${BUILD_DIR}"

# routeros_check.check.* and nagiosplugin.platform.{posix,nt} are only ever
# loaded via importlib/__import__ at runtime, so PyInstaller can't discover
# them by static analysis. Pass them in explicitly as hidden imports instead.
HIDDEN_IMPORTS=()
for check_file in "${SCRIPT_DIR}"/routeros_check/check/*.py; do
    check_name="$(basename "${check_file}" .py)"
    [[ "${check_name}" == "__init__" ]] && continue
    HIDDEN_IMPORTS+=(--hidden-import "routeros_check.check.${check_name}")
done
HIDDEN_IMPORTS+=(--hidden-import "nagiosplugin.platform.posix")
HIDDEN_IMPORTS+=(--hidden-import "nagiosplugin.platform.nt")

echo "Building static ${OUTPUT_FILE} ..."
pyinstaller \
    --onefile \
    --name check_routeros \
    --distpath "${DIST_DIR}" \
    --workpath "${BUILD_DIR}" \
    --specpath "${BUILD_DIR}" \
    "${HIDDEN_IMPORTS[@]}" \
    "${SCRIPT_DIR}/check_routeros.py"

deactivate

echo "Done. Static build available at ${OUTPUT_FILE}"

