# 브라우저 전용(WebAssembly) 판을 dist\ 에 만든다. 화면은 Spring 판(src\main\resources\static)을 그대로 쓴다.
#   .\build.ps1
#   python -m http.server -d dist 8000   →  http://localhost:8000
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# PATH 에 go 가 없으면(IDE 실행 구성 등) GOROOT 나 IDE 가 내려받은 SDK(~\sdk\go*) 를 쓴다
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
	$goBin = @($env:GOROOT) + @(Get-ChildItem "$HOME\sdk\go*" -Directory -ErrorAction SilentlyContinue |
		Sort-Object { [version]($_.Name -replace '^go', '') } -Descending | ForEach-Object FullName) |
		Where-Object { $_ -and (Test-Path "$_\bin\go.exe") } | Select-Object -First 1
	if (-not $goBin) { throw 'go 를 찾을 수 없습니다. Go 를 설치하거나 PATH/GOROOT 를 설정하세요.' }
	$env:Path = "$goBin\bin;$env:Path"
}

$static = '..\src\main\resources\static'
if (Test-Path dist) { Remove-Item -Recurse -Force dist }
New-Item -ItemType Directory dist | Out-Null

$env:GOOS = 'js'; $env:GOARCH = 'wasm'
try {
	go build -trimpath -ldflags='-s -w' -o dist\sslconverter.wasm .\cmd\wasm
	if ($LASTEXITCODE -ne 0) { throw 'go build 실패' }
} finally {
	Remove-Item Env:GOOS, Env:GOARCH
}
Copy-Item (Join-Path (go env GOROOT) 'lib\wasm\wasm_exec.js') dist
Copy-Item web\bridge.js, web\worker.js, "$static\app.js", "$static\style.css" dist
# app.js 보다 먼저 bridge.js 를 불러와 서버 API 대신 WebAssembly 로 처리하게 한다
(Get-Content "$static\index.html" -Raw -Encoding utf8).Replace('<script src="app.js"></script>',
	"<script src=`"bridge.js`"></script>`n<script src=`"app.js`"></script>") |
	Set-Content dist\index.html -Encoding utf8 -NoNewline

Get-ChildItem dist
