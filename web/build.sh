#!/usr/bin/env bash
# Build the moonbin wasm playground and stage it next to web/index.html.
#
# The MoonBit wasm backend emits only the .wasm module (no .js glue); the
# host glue is inlined in web/index.html (<script id="moonbin-glue">), so the
# page stays a single self-contained file. If a future toolchain also emits
# a .js sidecar, it is copied along.
#
# Usage:   bash web/build.sh
# Serve:   cd web && python -m http.server 8080   ->  http://localhost:8080/
# Test:    node test/web_e2e.mjs
set -euo pipefail
cd "$(dirname "$0")/.."

moon build --target wasm --release src/web

wasm=_build/wasm/release/build/src/web/web.wasm
cp "$wasm" web/main.wasm
echo "staged web/main.wasm ($(wc -c < web/main.wasm) bytes)"

js=_build/wasm/release/build/src/web/web.js
if [ -f "$js" ]; then
  cp "$js" web/main.js
  echo "staged web/main.js"
fi

echo "serve with: (cd web && python -m http.server 8080)"