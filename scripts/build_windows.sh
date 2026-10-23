#!/usr/bin/env bash
# Builds mikrotik-accounting-windows.zip: program + portable Python 3.12 (nuget) + all packages (win_amd64 wheels).
# Usage: scripts/build_windows.sh [output.zip]      (needs: python3 + pip, internet access to nuget.org and PyPI)
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$SRC/../mikrotik-accounting-windows.zip}"
PYVER=3.12.10
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PKG="$WORK/mikrotik-accounting"
mkdir -p "$PKG"

echo "== copying program"
tar -C "$SRC" --exclude=__pycache__ --exclude=./.venv --exclude=./data --exclude=./.env --exclude=./tests \
    --exclude=./.pytest_cache --exclude=./runtime -cf - . | tar -C "$PKG" -xf -

echo "== portable Python $PYVER (nuget.org)"
curl -fsSL -o "$WORK/python.nupkg" "https://api.nuget.org/v3-flatcontainer/python/$PYVER/python.$PYVER.nupkg"
python3 - "$WORK/python.nupkg" "$WORK/nupkg" <<'PY'
import sys, zipfile
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])
PY
mkdir -p "$PKG/runtime"
mv "$WORK/nupkg/tools" "$PKG/runtime/python"
rm -rf "$PKG/runtime/python/include" "$PKG/runtime/python/libs" "$PKG/runtime/python/Lib/test" \
       "$PKG/runtime/python/Lib/idlelib" "$PKG/runtime/python/Lib/turtledemo" "$PKG/runtime/python/Lib/tkinter" \
       "$PKG/runtime/python/tcl" "$PKG/runtime/python/DLLs/_tkinter.pyd" "$PKG/runtime/python/DLLs/tcl"*.dll \
       "$PKG/runtime/python/DLLs/tk"*.dll

echo "== packages (win_amd64, cp312)"
python3 -m pip install --quiet --no-compile --disable-pip-version-check \
    --target "$PKG/runtime/python/Lib/site-packages" --platform win_amd64 --python-version 3.12 \
    --implementation cp --abi cp312 --only-binary=:all: --upgrade -r "$SRC/windows/requirements-windows.txt"
rm -rf "$PKG/runtime/python/Lib/site-packages/bin"
find "$PKG" -name __pycache__ -type d -prune -exec rm -rf {} +

echo "== zip"
rm -f "$OUT"
(cd "$WORK" && python3 - "$OUT" <<'PY'
import os, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for base, dirs, files in os.walk("mikrotik-accounting"):
        dirs.sort()
        for f in sorted(files):
            zf.write(os.path.join(base, f))
PY
)
ls -lh "$OUT"
