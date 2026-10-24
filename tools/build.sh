#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
PYTHON="$ROOT/.venv/bin/python"
export RTT_EXEC_PATH="${RTT_EXEC_PATH:-$ROOT/tools/gcc-arm-none-eabi-5_4-2016q3/bin}"
test -x "$RTT_EXEC_PATH/arm-none-eabi-gcc"
test -x "$PYTHON"
if [ ! -d build/sdk ]; then
    "$PYTHON" tools/prepare_build.py
fi
# Refresh application sources and Wi-Fi settings; SDK patches require a clean tree.
"$PYTHON" tools/prepare_build.py --sync
if ! "$ROOT/.venv/bin/scons" -C build/sdk --beken=bk7251 -j4 > build/compile.log 2>&1; then
    tail -60 build/compile.log
    exit 1
fi
tail -12 build/compile.log
"$PYTHON" tools/package_firmware.py
