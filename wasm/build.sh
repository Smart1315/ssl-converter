#!/usr/bin/env bash
# 브라우저 전용(WebAssembly) 판을 dist/ 에 만든다. 화면은 Spring 판(src/main/resources/static)을 그대로 쓴다.
#   ./build.sh
#   python -m http.server -d dist 8000   →  http://localhost:8000
set -euo pipefail
cd "$(dirname "$0")"

static=../src/main/resources/static
rm -rf dist
mkdir -p dist

GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o dist/sslconverter.wasm ./cmd/wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" dist/
cp web/bridge.js web/worker.js "$static/app.js" "$static/style.css" dist/
# app.js 보다 먼저 bridge.js 를 불러와 서버 API 대신 WebAssembly 로 처리하게 한다
sed 's#<script src="app.js"></script>#<script src="bridge.js"></script>\n<script src="app.js"></script>#' \
	"$static/index.html" > dist/index.html

ls -l dist
