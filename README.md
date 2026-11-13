# SSL 인증서 변환기

Spring Boot 기반 웹 애플리케이션입니다. SSL 인증서를 PEM · CRT · KEY · PFX(P12) · JKS · P7B · DER 형식 사이에서 변환하고, CSR/인증서 발급, PKI 분석 도구를 제공합니다.
OpenSSL이나 keytool 없이 Java(BouncyCastle)만으로 동작하며, 업로드한 파일은 메모리에서만 처리하고 서버에 저장하지 않습니다.

테스트 주소: https://tool.yeongsby.com/ssl-converter

## 실행

```bash
./mvnw spring-boot:run
# 또는
./mvnw package
java -jar target/ssl-converter-0.0.1-SNAPSHOT.jar
```

브라우저에서 http://localhost:8080 에 접속합니다. 포트는 `--server.port=9090` 옵션으로 바꿀 수 있습니다.

> 개인키를 업로드하는 도구이므로 내부망이나 로컬에서만 실행하세요.
> 외부에 노출해야 한다면 HTTPS를 적용하고 접근을 제한하세요.
>
> 서버 없이 브라우저 안에서만 변환하는 WebAssembly 판도 있습니다. [wasm/README.md](wasm/README.md)를 참고하세요.

### Docker

```bash
docker compose up -d --build
```

http://localhost:8080 에 접속합니다. 개인키를 다루는 도구라서 compose 설정은 이 PC(`127.0.0.1`)에서만 접속할 수 있게 되어 있습니다.
내부망의 다른 PC에서도 쓰려면 [docker-compose.yml](docker-compose.yml)의 `ports`를 `"8080:8080"`으로 바꾸세요.

compose 없이 이미지만 빌드하고 실행할 수도 있습니다.

```bash
docker build -t ssl-converter .
docker run -d --name ssl-converter -p 127.0.0.1:8080:8080 --read-only --tmpfs /tmp ssl-converter
```

- 멀티 스테이지 빌드입니다. 빌드는 JDK 17, 실행은 JRE 17 이미지에서 하고, root가 아닌 `app` 사용자로 실행합니다
- `linux/amd64`와 `linux/arm64`(Apple Silicon, AWS Graviton, 라즈베리파이 64비트 등)를 지원합니다. 위 명령은 빌드하는 PC의 아키텍처로 만듭니다
- 컨테이너 파일시스템은 읽기 전용(`--read-only`)이어도 동작합니다. 업로드한 파일은 디스크에 쓰지 않고 메모리에서만 처리합니다
- 이미지 빌드 중에는 테스트를 실행하지 않습니다. 테스트는 `./mvnw test`로 따로 실행하세요

#### amd64 + arm64 통합 이미지

두 아키텍처를 이미지 하나(멀티 아키텍처 매니페스트)로 만들려면 `buildx`를 사용합니다.
같은 태그로 `docker pull`/`docker run`을 하면 각 서버가 자기 아키텍처에 맞는 이미지를 자동으로 받습니다.

```bash
# 레지스트리에 올리기
docker buildx build --platform linux/amd64,linux/arm64 -t registry.example.com/ssl-converter:latest --push .

# 로컬에만 저장 (Docker Desktop의 containerd 이미지 저장소가 켜져 있어야 합니다)
docker buildx build --platform linux/amd64,linux/arm64 -t ssl-converter:latest --load .

# 다른 아키텍처의 이미지로 실행해 보기
docker run --rm --platform linux/arm64 -p 127.0.0.1:8080:8080 ssl-converter:latest
```

- jar는 아키텍처와 관계없으므로 Maven 빌드 단계는 빌드하는 PC의 아키텍처에서 한 번만 실행합니다. 실행 이미지만 대상 아키텍처별로 만들어 에뮬레이션(QEMU) 때문에 느려지지 않습니다
- Docker Desktop에는 다른 아키텍처의 에뮬레이션이 기본으로 들어 있습니다. Linux 서버에서 빌드하려면 먼저 `docker run --privileged --rm tonistiigi/binfmt --install all`로 에뮬레이터를 설치하세요
- 로컬 저장소가 containerd를 쓰지 않으면 `--load`가 멀티 아키텍처 이미지를 저장하지 못합니다. 그때는 `--push`로 레지스트리에 올리거나 `--platform linux/arm64`처럼 하나만 지정하세요

## 기존 수작업과 비교

| 기존 방식 | 이 도구 |
|---|---|
| `cat ssl.crt chain_ssl.crt chain_all_ssl.crt > x.pem` | 파일을 순서 상관없이 모두 올리면 발급 관계(DN과 서명 검증)를 따라 서버 → 중간 → 루트 순서로 자동 정렬합니다 |
| `-----END CERTIFICATE----------BEGIN CERTIFICATE-----` 줄을 손으로 분리 | 자동으로 보정합니다. CRLF, BOM, 64자 줄바꿈이 깨진 경우, 앞뒤의 불필요한 텍스트도 함께 처리합니다 |
| `openssl pkcs12 -export -name ... -inkey ssl.key` | PFX 출력. 별칭은 CN에서 자동으로 채웁니다 (`example.com`) |
| `keytool -importkeystore ... -deststoretype jks` | JKS 출력 |
| `keytool -list -v` | 분석 화면에서 소유자, 발급자, SAN, 유효기간, 지문, 키 일치 여부를 바로 확인할 수 있습니다 |

## 지원 입력

- **PEM**: 인증서, 체인, PKCS#7, 개인키(PKCS#8 · RSA · EC), 암호화된 키(PKCS#8, OpenSSL 레거시 `Proc-Type: 4,ENCRYPTED`). 여러 블록이 한 파일에 섞여 있어도 됩니다
- **DER**: `.cer`/`.der` 인증서, `.p7b`, DER 개인키(PKCS#8/PKCS#1/SEC1)
- **헤더 없는 Base64**
- **키스토어**: PKCS#12(`.pfx`/`.p12`), JKS, JCEKS. 키 항목이 여러 개면 화면에서 별칭을 고를 수 있습니다
- **ZIP 압축파일**: CA에서 받은 ZIP을 그대로 올리면 됩니다
  - 폴더 구조와 ZIP 안의 ZIP(1단계)까지 읽습니다
  - 한국어 Windows에서 만든 ZIP의 파일명(CP949)도 제대로 읽습니다
  - 안내 문서, 이미지, `__MACOSX` 같은 파일은 건너뛰고, 건너뛴 파일 목록을 분석 화면에 보여줍니다
  - ZIP 안의 PFX/JKS를 비밀번호가 없거나 달라서 열지 못하면 오류가 아니라 경고로 처리합니다. 다른 파일만으로도 변환할 수 있습니다
  - 암호가 걸린 ZIP은 지원하지 않습니다. 압축을 푼 뒤 안의 파일을 올리세요
  - 압축 폭탄 방지 제한: 파일 500개, 파일당 5MB, 전체 50MB
- **PEM 텍스트 붙여넣기**: 인증서, 체인, 개인키 블록을 함께 붙여넣을 수 있고 파일 업로드와 같이 써도 됩니다
- 확장자를 보지 않고 파일 내용으로 형식을 판별합니다

## 출력 형식

| 형식 | 파일 | 용도 |
|---|---|---|
| 풀체인 PEM | `{이름}_fullchain.pem` | Nginx `ssl_certificate` |
| 개인키 PEM | `{이름}.key` | PKCS#8 또는 전통 형식(RSA/EC). **기본은 암호화하지 않으며**, '개인키 파일 암호화'를 켜면 출력 비밀번호로 암호화합니다 (PKCS#8 은 AES-256, 전통 형식은 `openssl rsa -aes256` 과 같은 DEK-Info) |
| 서버 인증서 PEM | `{이름}.crt` | Apache `SSLCertificateFile` |
| 체인 PEM | `{이름}_chain.crt` | Apache `SSLCertificateChainFile` |
| PFX | `{이름}.pfx` | IIS, Windows, Tomcat, Spring Boot. 기본은 AES-256이며, 구형 Windows/Java용 **레거시(3DES/SHA1)** 옵션이 있습니다. '비밀번호 없이 생성'을 켜면 빈 비밀번호로 만듭니다 (`openssl pkcs12 -passout pass:` 과 같음, 열 때 비밀번호 칸을 비워 둠) |
| JKS | `{이름}.jks` | Tomcat, WebLogic, JEUS. 비밀번호가 필요합니다 ('비밀번호 없이 생성' 불가) |
| 통합 PEM | `{이름}_combined.pem` | HAProxy (키와 풀체인을 한 파일에) |
| P7B | `{이름}.p7b` | Windows 인증서 가져오기 |
| DER | `{이름}.cer` | 바이너리 인증서 |
| 트러스트스토어 | `{이름}_truststore.jks` | 클라이언트 측 CA 신뢰 |

형식을 두 개 이상 고르면 ZIP 하나로 내려받습니다. ZIP 안의 `README.txt`에는 체인 정보와 확인 명령이 들어 있고, 비밀번호는 기록하지 않습니다.

## 자동 점검 항목

분석 화면 맨 위의 점검표에 항목별로 통과(✔), 확인 필요(!), 문제(✖), 미실행(–)을 표시합니다.

| 항목 | 점검 내용 | 문제(✖)로 판정하는 경우 |
|---|---|---|
| 개인키 일치 | 개인키와 서버 인증서가 쌍인지 확인 | 입력한 키가 인증서와 맞지 않음 (키가 아예 없으면 확인 필요) |
| 체인 구성 | 발급 관계를 따라 서버 → 중간 → 루트 정렬 | 중간 인증서 누락 (AIA의 다운로드 주소 안내) |
| 유효기간 | 서버, 중간, 루트 인증서 모두 확인 | 만료됨 또는 유효기간 시작 전 (30일 이내 만료는 확인 필요) |
| 도메인(SAN) | 주체 대체 이름 목록 | SAN 없음 (최신 브라우저는 CN만으로는 도메인을 인정하지 않음) |
| 서버 인증 용도 | EKU의 serverAuth, KeyUsage, CA 여부 | 클라이언트/코드서명용 인증서이거나 KeyUsage가 TLS에 맞지 않음 |
| 키 길이 | 서버와 중간 인증서의 공개키 | RSA 2048비트 미만, EC 256비트 미만 |
| 서명 알고리즘 | 서버와 중간 인증서의 서명 | SHA-1, MD5, MD2 (루트의 자체 서명은 제외) |
| 공인 루트 신뢰 | Java 기본 신뢰 저장소(cacerts)까지 경로 검증. 교차 서명 체인도 브라우저처럼 처리 | 판정하지 않음. 연결되지 않으면 확인 필요 (사내/사설 CA라면 정상) |
| 폐기 여부 | 선택 시 OCSP(우선) 또는 CRL로 조회하고 응답 서명도 검증 | 폐기됨 |

이 밖에 체인과 관계없는 인증서는 출력에서 빼고 따로 표시합니다.

**폐기 여부 온라인 확인**은 '폐기 여부 온라인 확인'을 체크했을 때만 실행합니다. API에서는 `checkRevocation=true`로 켭니다.
- 인증서에 적힌 CA 서버(OCSP/CRL)에 접속하므로 인터넷이 필요합니다. 막힌 환경에서는 '확인 실패'로 표시됩니다
- 조작된 인증서로 내부망을 조회하는 것(SSRF)을 막기 위해 http/https 주소만 허용합니다. 사설·루프백 주소에는 접속하지 않습니다
  - 사내 CA의 OCSP가 내부망에 있다면 `ssl-converter.revocation.allow-private-addresses=true`로 허용할 수 있습니다
  - Docker에서는 환경변수 `SSL_CONVERTER_REVOCATION_ALLOW_PRIVATE_ADDRESSES=true`로 지정합니다

## PKI 도구

변환 화면 상단의 **CSR · PKI 도구** 링크(`tools.html`)에서 쓸 수 있습니다. 탭마다 파일 업로드와 PEM 붙여넣기를 함께 지원하며, 결과 파일은 화면에서 바로 복사하거나 내려받습니다.

| 탭 (`tool`) | 기능 | 결과 |
|---|---|---|
| 자체 서명 인증서 / 사설 CA (`self-signed`) | RSA(2048/3072/4096) 또는 ECDSA P-256 키로 자체 서명 서버 인증서나 사설 루트 CA를 만듭니다. 유효기간 365일. 서버 인증서에는 SAN, `serverAuth` EKU를, CA에는 `keyCertSign`·`cRLSign`을 넣습니다 | `certificate.pem`, `private-key.pem` |
| CSR 및 키 생성 (`csr`) | CN, SAN(DNS/IP, 쉼표로 구분), 키 알고리즘을 정해 CSR과 개인키를 만듭니다 | `request.csr`, `private-key.pem` |
| CSR 디코딩 (`csr-decode`) | CSR의 주체, 공개키 알고리즘, SAN을 보여주고 요청 서명을 검증합니다 | 정보 표 |
| 사설 CA 발급 (`issue`) | CA 인증서와 CA 개인키로 CSR에 서명합니다. 유효기간 1~825일 | `issued-certificate.pem` |
| 짝 확인 (`match`) | 인증서 ↔ 개인키, 인증서 ↔ CSR의 공개키가 같은지 확인합니다 | 일치/불일치 |
| CRL 보기 (`crl`) | 발급자, 발급일, 다음 갱신, 폐기 일련번호(처음 100개)를 보여줍니다. 발급자 인증서를 넣으면 CRL 서명도 검증합니다 | 정보 표 |
| OCSP 응답 해석 (`ocsp`) | 응답 상태, 응답자, 인증서별 상태를 보여줍니다. 응답에 든 인증서나 입력한 발급자 인증서로 응답 서명을 검증합니다 | 정보 표 |
| ASN.1 / DER 구조 보기 (`asn1`) | PEM, Base64, DER 입력을 태그 트리로 표시합니다 (최대 500개 노드) | 트리 |
| 인증서 비교 (`compare`) | 두 인증서의 주체, 발급자, 유효기간, 공개키(지문), SAN을 비교합니다 | 같음/다름 표 |
| PKCS#7 / CMS 서명 확인 (`cms`) | 첨부 서명과 분리 서명(원본 파일 입력)의 서명자별 서명 값을 검증합니다 | 서명자별 유효/무효 |
| 원격 TLS 점검 (`tls`, **Spring 판만**) | 호스트에 TLS로 접속해 프로토콜, 암호군, 서버가 보낸 인증서 체인을 보여줍니다. JDK 기본 신뢰 저장소와 호스트 이름 검증을 그대로 적용합니다. 연결 제한 시간은 5초입니다 | 정보 표 |

발급과 검증 규칙:
- **사설 CA 발급**은 CA 인증서에 `CA:TRUE`와 `keyCertSign` 권한이 있는지, CA 개인키가 인증서와 맞는지 먼저 확인합니다
- 발급본에는 CSR의 확장 중 **SAN만** 옮깁니다. `CA:FALSE`, `digitalSignature`(RSA는 `keyEncipherment` 추가), `serverAuth` EKU는 직접 붙입니다. CSR에 CA 권한 같은 확장을 넣어도 반영되지 않습니다
- 일련번호는 159비트 난수이고, 시계 오차를 고려해 유효 시작을 5분 앞당깁니다
- **CMS 확인은 서명 값만 검증**합니다. 서명자 인증서가 믿을 만한 CA에서 발급됐는지는 따로 확인해야 합니다

보안 주의:
- 생성한 개인키는 **암호화되지 않은 PKCS#8 PEM**으로 내려받습니다. 서버에는 저장하지 않습니다
- Spring 판에서 사설 CA 발급을 쓰면 **CA 개인키를 서버로 보냅니다**. 비밀키를 서버에 보내지 않으려면 [WASM 판](wasm/README.md)을 사용하세요. WASM 판은 모든 도구를 브라우저 안에서 처리합니다
- 원격 TLS 점검은 서버가 외부 호스트로 접속하는 기능입니다. 내부망 조회(SSRF)를 막기 위해 DNS 결과가 모두 공인 주소일 때만 연결하고, 사설·루프백·링크 로컬 주소는 거부합니다. 포트는 1~65535만 받습니다

## API

웹 화면이 사용하는 API입니다. `curl`로 자동화할 때도 쓸 수 있습니다.

```bash
# 분석
curl -F files=@ssl.crt -F files=@chain.crt -F files=@ssl.key http://localhost:8080/api/analyze

# 변환 (형식을 여러 개 지정하면 zip)
curl -o out.zip -F files=@ssl.crt -F files=@chain.crt -F files=@ssl.key \
     -F formats=PFX -F formats=JKS -F outPassword=changeit http://localhost:8080/api/convert
```

| 파라미터 | 설명 |
|---|---|
| `files` (여러 개), `text` | 입력 파일, 붙여넣은 PEM 텍스트 |
| `password`, `alias` | 입력 키스토어/암호화 키 비밀번호, 사용할 키스토어 별칭 |
| `checkRevocation` (분석 전용, 기본 false) | OCSP/CRL 온라인 폐기 확인 |
| `formats` | `FULLCHAIN_PEM` `CERT_PEM` `CHAIN_PEM` `KEY_PEM` `COMBINED_PEM` `PFX` `JKS` `TRUSTSTORE_JKS` `P7B` `DER` |
| `baseName`, `outAlias`, `outPassword` | 출력 파일명, 별칭, 비밀번호 (영문·숫자·기호만 가능. 한글 등은 Java 에서 PFX 를 열 수 없어 거부합니다) |
| `includeRoot` (기본 true), `legacyPfx` (기본 false), `keyFormat` (`PKCS8` / `TRADITIONAL`), `encryptKey` (기본 false), `noPassword` (기본 false) | 출력 옵션. `noPassword=true` 이면 `outPassword` 를 무시하고 PFX 를 빈 비밀번호로 만듭니다 (JKS·트러스트스토어·`encryptKey` 와 함께 쓸 수 없음). 이전의 `keyFormat=PKCS8_ENCRYPTED` 는 `PKCS8` + `encryptKey=true` 와 같습니다 |

### PKI 도구 API

`POST /api/tools/{tool}` (multipart)로 호출합니다. `{tool}`은 위 표의 이름입니다. 오류는 다른 API와 같이 `{"message": "..."}`와 4xx 상태로 돌려줍니다.

```bash
# CSR 생성
curl -F commonName=example.com -F keyType=EC -F san=example.com,www.example.com http://localhost:8080/api/tools/csr

# 사설 CA로 발급
curl -F files=@request.csr -F caFiles=@ca.pem -F caFiles=@ca.key -F days=365 http://localhost:8080/api/tools/issue

# 분리 서명 CMS 확인
curl -F files=@data.p7s -F contentFiles=@data.bin http://localhost:8080/api/tools/cms
```

모든 도구는 같은 형식의 JSON을 돌려줍니다. WASM 판도 같은 형식입니다.

```json
{
  "messages": ["안내 문구"],
  "sections": [{"title": "제목", "level": "info", "rows": [{"label": "항목", "value": "값"}]}],
  "files": [{"name": "request.csr", "content": "-----BEGIN CERTIFICATE REQUEST-----..."}],
  "tree": {"name": "ASN.1", "value": "...", "children": []}
}
```

| 도구 | 파라미터 |
|---|---|
| `self-signed` | `commonName`(필수), `keyType` (`RSA`/`EC`, 기본 RSA), `keyBits` (2048~4096, 기본 2048), `san`, `isCa` (기본 false) |
| `csr` | `commonName`(필수), `keyType`, `keyBits`, `san` |
| `csr-decode`, `asn1` | `files` 또는 `text` |
| `issue` | CSR `files`/`text`, CA 인증서와 개인키 `caFiles`/`caText`, `caPassword`, `days` (1~825, 기본 365) |
| `match` | 인증서·개인키 `files`/`text`, `password`, 비교할 CSR `csrText`(선택) |
| `crl`, `ocsp` | `files`/`text`, 서명 검증용 발급자 인증서 `issuerFiles`/`issuerText`(선택) |
| `compare` | 첫 번째 인증서 `files`/`text`, 두 번째 인증서 `filesB`/`textB` |
| `cms` | CMS `files`/`text`, 분리 서명 원본 `contentFiles`/`contentText`(선택) |
| `tls` | `host`(필수), `port` (기본 443) |

`files`처럼 하나만 쓰는 입력에 파일을 여러 개 보내면 첫 번째 파일만 씁니다. 파일과 텍스트를 함께 보내면 파일을 먼저 씁니다 (`issue`의 CA, `match`의 입력은 파일과 텍스트를 합쳐서 읽습니다).

## 코드 구조

| 경로 | 내용 |
|---|---|
| `cert/` | 입력 해석, 체인 정렬, 점검, 출력 생성 (`InputParser`, `ChainResolver`, `CertificateChecks`, `Exporter`, `ConverterService`) |
| `tools/` | PKI 도구 (`PkiToolsService`, 공통 응답 `ToolResult`) |
| `web/` | `/api/analyze`·`/api/convert` (`ConverterController`), `/api/tools/{tool}` (`ToolsController`), 오류 응답 (`ApiExceptionHandler`) |
| `resources/static/` | 변환 화면 `index.html`·`app.js`, PKI 도구 화면 `tools.html`·`tools.js`, 공통 `style.css` |
| `wasm/` | 같은 기능의 Go 구현과 WebAssembly 빌드 ([wasm/README.md](wasm/README.md)) |

자바 경로는 `src/main/java/com/yeongsby/sslconverter` 기준입니다. 테스트는 `./mvnw test`로 실행합니다 (`PkiToolsServiceTests`는 CSR 생성·디코딩, 발급과 짝 확인, CA 아닌 인증서로 발급 거부, CRL·OCSP·ASN.1·비교, CMS 서명 검증을 다룹니다).
