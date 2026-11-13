# 브라우저 전용 판 (Go → WebAssembly)

Spring 판과 같은 기능을 Go 로 다시 구현해 WebAssembly 로 빌드한 판입니다. **서버 없이 브라우저 안에서만 변환**하므로
개인키와 비밀번호가 어디로도 전송되지 않습니다. 정적 파일만 있으면 되므로 GitHub Pages, 사내 웹서버, `file` 서버 등 어디든 올릴 수 있습니다.

화면은 Spring 판(`src/main/resources/static`)을 그대로 사용합니다. `bridge.js` 가 `app.js`와 `tools.js`의 `/api/*` 호출을 가로채
Web Worker 안의 WebAssembly 엔진으로 보냅니다. Spring 판은 이 폴더와 상관없이 그대로 동작합니다.

| 화면 호출 | 엔진 함수 |
|---|---|
| `/api/analyze` | `sslConverter.analyze` |
| `/api/convert` | `sslConverter.convert` |
| `/api/tools/{tool}` | `sslConverter.tools` (`tool` 이름을 함께 전달) |

`bridge.js`는 `FormData`를 엔진 요청 객체로 바꿉니다. 파일 필드(`files`, `caFiles`, `issuerFiles`, `filesB`, `contentFiles` 등)는 이름별 파일 목록으로, 나머지는 문자열로 전달합니다.
응답은 Spring 판과 같은 `fetch` Response로 돌려주므로 화면 코드는 두 판에서 같습니다.

## PKI 도구

`tools.html`에서 Spring 판과 같은 도구를 브라우저 안에서 실행합니다. 기능과 입력 필드, 응답 JSON 형식은 [README.md의 PKI 도구](../README.md#pki-도구)와 같습니다.

- 자체 서명 인증서 / 사설 루트 CA (`self-signed`), CSR 및 키 생성 (`csr`), CSR 디코딩 (`csr-decode`)
- 사설 CA 발급 (`issue`): CA 권한과 `keyCertSign` 확인, CSR의 SAN만 반영, `serverAuth` EKU 부여
- 인증서·개인키·CSR 짝 확인 (`match`), 인증서 비교 (`compare`)
- CRL 보기 (`crl`), OCSP 응답 해석 (`ocsp`), ASN.1 구조 보기 (`asn1`), PKCS#7/CMS 서명 확인 (`cms`)

CA 개인키, 생성한 개인키, CMS 원본이 모두 브라우저 밖으로 나가지 않으므로, 사설 CA 발급처럼 비밀키를 다루는 작업은 이 판을 권장합니다.
난수는 Go 런타임이 브라우저의 `crypto.getRandomValues`로 만듭니다. RSA 4096 키 생성은 브라우저에 따라 수 초 이상 걸릴 수 있지만 Web Worker에서 실행되므로 화면은 멈추지 않습니다.

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
| `index.html`, `tools.html`, `app.js`, `tools.js`, `style.css` | Spring 판 화면 복사본 |

## 테스트

```bash
go test ./...
```

`cert/cert_test.go`는 변환·분석을, `tools/tools_test.go`는 CSR 생성·디코딩, 사설 CA 발급과 짝 확인, CRL·OCSP·ASN.1·인증서 비교, CMS 서명 검증을 확인합니다.
브라우저용 빌드가 되는지는 `GOOS=js GOARCH=wasm go build ./cmd/wasm`으로 확인합니다.

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
| `cmd/wasm/main.go` | 브라우저 진입점. `analyze`, `convert`, `tools` 함수 등록 (`ConverterController`, `ToolsController`) |
| `tools/tools.go` | 도구 실행(`Execute`), 자체 서명·CSR·발급·짝 확인·CRL·OCSP·비교·ASN.1 (`PkiToolsService`) |
| `tools/cms.go` | PKCS#7/CMS SignedData 해석과 서명 검증 (`encoding/asn1`로 직접 구현) |
| `tools/result.go` | 공통 응답 (`ToolResult`) |
| `web/bridge.js`, `web/worker.js` | `/api/*` 호출을 엔진 함수로 연결, Web Worker에서 엔진 실행 |

## Spring 판과 다른 점

### 변환·분석

- **공인 루트 신뢰**: JDK cacerts 대신 Mozilla(NSS) 루트 목록을 엔진에 내장합니다. `golang.org/x/crypto/x509roots/fallback` 을 올리고 다시 빌드하면 갱신됩니다.
- **폐기 여부 온라인 확인(OCSP/CRL)은 제외**했습니다. 대부분의 CA 서버가 CORS 를 허용하지 않고 주소도 `http://` 여서 브라우저가 접속을 막기 때문입니다. 화면의 해당 옵션은 숨기며, 필요하면 Spring 판을 사용하세요.
- **JCEKS 입력**은 지원하지 않습니다. `keytool -importkeystore` 로 PKCS12 로 바꿔서 올리세요.
- **DSA 개인키**와 RC2 로 암호화된 PKCS#8 개인키는 읽지 못합니다 (RC2 로 암호화된 구형 PFX 는 읽습니다).
- 별칭(friendlyName) 이 없는 PFX 는 별칭을 `1` 로 표시합니다.
- 공인 루트 검증 실패 사유는 Go 오류 메시지(영문)를 함께 보여줍니다.

### PKI 도구

- **원격 TLS 점검(`tls`)은 제공하지 않습니다.** 브라우저는 임의 호스트로 TLS 소켓을 열 수 없습니다. `bridge.js`가 `window.sslWasm = true`를 설정하면 `tools.js`가 이 탭을 숨기며, Spring 판에서만 쓸 수 있습니다.
- **OCSP**: `x/crypto/ocsp`가 돌려주는 첫 번째 응답 하나만 표시합니다 (Java 판은 전부 표시). 응답 서명은 발급자 인증서를 넣었을 때만 검증하고, 서명이 맞지 않으면 '무효'로 표시하는 대신 오류를 돌려줍니다. Java 판은 응답에 든 인증서로도 검증합니다.
- **CRL**: 발급자 인증서로 서명 검증에 실패하면 오류 대신 '서명 검증: 무효'와 Go 오류 메시지(영문)를 표시합니다.
- **인증서 비교**: 공개키는 알고리즘만 비교하고 키 지문은 비교하지 않습니다. SAN은 DNS 이름과 IP 주소만 비교합니다.
- **CMS**: RSA PKCS#1 v1.5, ECDSA, Ed25519 서명과 SHA-1/256/384/512 다이제스트를 검증합니다. RSA-PSS 등 그 밖의 알고리즘은 '무효'로 표시됩니다. 두 판 모두 서명 값만 확인하고 인증서 체인 신뢰는 확인하지 않습니다.
- 생성한 개인키는 Spring 판과 같이 암호화되지 않은 PKCS#8 PEM으로 내려받습니다. 안전하게 보관하세요.
