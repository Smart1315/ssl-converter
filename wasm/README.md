# 브라우저 전용 판 (Go → WebAssembly)

Spring 판과 같은 기능을 Go 로 다시 구현해 WebAssembly 로 빌드한 판입니다. **서버 없이 브라우저 안에서만 변환**하므로
개인키와 비밀번호가 어디로도 전송되지 않습니다. 정적 파일만 있으면 되므로 GitHub Pages, 사내 웹서버, `file` 서버 등 어디든 올릴 수 있습니다.

화면은 Spring 판(`src/main/resources/static`)을 그대로 사용합니다. `bridge.js` 가 `app.js` 의 `/api/*` 호출을 가로채
Web Worker 안의 WebAssembly 엔진으로 보냅니다. Spring 판은 이 폴더와 상관없이 그대로 동작합니다.

## 빌드

Go 1.26 이상이 필요합니다.

```bash
./build.sh          # Windows PowerShell: .\build.ps1
```

`dist/` 에 결과가 만들어집니다. `.wasm` 은 `file://` 로 열 수 없으므로 웹서버로 띄웁니다.

```bash
python -m http.server -d dist 8000
```

| 파일 | 설명 |
|---|---|
| `sslconverter.wasm` | 변환 엔진 (약 10MB, gzip 시 약 2.8MB — 웹서버의 gzip/brotli 압축을 켜는 것을 권장) |
| `wasm_exec.js` | Go 런타임 (Go 설치본에서 복사) |
| `worker.js`, `bridge.js` | 엔진 실행 / 화면 연결 |
| `index.html`, `app.js`, `style.css` | Spring 판 화면 복사본 |

## 테스트

```bash
go test ./...
```

## 구조

| 경로 | 내용 (대응하는 Java 클래스) |
|---|---|
| `cert/parser.go` | 입력 형식 판별, PEM/DER 해석 (`InputParser`) |
| `cert/archive.go` | ZIP 입력 (`ArchiveExtractor`) |
| `cert/keystore.go` | PFX/JKS 읽기·쓰기 (`InputParser.loadKeyStore`, `Exporter.keyStore`) |
| `cert/pbe.go` | 암호화된 개인키, PFX 암호화 (BouncyCastle PBE) |
| `cert/chain.go` | 서버 인증서 찾기, 체인 정렬 (`ChainResolver`) |
| `cert/checks.go` | 점검 항목 (`CertificateChecks`) |
| `cert/exporter.go`, `cert/service.go` | 출력 파일 생성, 분석/변환 묶음 (`Exporter`, `ConverterService`) |
| `cmd/wasm/main.go` | 브라우저 진입점 (`ConverterController`) |

## Spring 판과 다른 점

- **공인 루트 신뢰**: JDK cacerts 대신 Mozilla(NSS) 루트 목록을 엔진에 내장합니다. `golang.org/x/crypto/x509roots/fallback` 을 올리고 다시 빌드하면 갱신됩니다.
- **폐기 여부 온라인 확인(OCSP/CRL)은 제외**했습니다. 대부분의 CA 서버가 CORS 를 허용하지 않고 주소도 `http://` 여서 브라우저가 접속을 막기 때문입니다. 화면의 해당 옵션은 숨기며, 필요하면 Spring 판을 사용하세요.
- **JCEKS 입력**은 지원하지 않습니다. `keytool -importkeystore` 로 PKCS12 로 바꿔서 올리세요.
- **DSA 개인키**와 RC2 로 암호화된 PKCS#8 개인키는 읽지 못합니다 (RC2 로 암호화된 구형 PFX 는 읽습니다).
- 별칭(friendlyName) 이 없는 PFX 는 별칭을 `1` 로 표시합니다.
- 공인 루트 검증 실패 사유는 Go 오류 메시지(영문)를 함께 보여줍니다.
