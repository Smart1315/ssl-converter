# SSL 인증서 변환기

Spring Boot 기반 웹 애플리케이션입니다. SSL 인증서를 PEM · CRT · KEY · PFX(P12) · JKS · P7B · DER 형식 사이에서 변환합니다.
OpenSSL이나 keytool 없이 Java(BouncyCastle)만으로 동작하며, 업로드한 파일은 메모리에서만 처리하고 서버에 저장하지 않습니다.

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
- 컨테이너 파일시스템은 읽기 전용(`--read-only`)이어도 동작합니다. 업로드한 파일은 디스크에 쓰지 않고 메모리에서만 처리합니다
- 이미지 빌드 중에는 테스트를 실행하지 않습니다. 테스트는 `./mvnw test`로 따로 실행하세요

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
| 개인키 PEM | `{이름}.key` | PKCS#8, 전통 형식(RSA/EC), 암호화 PKCS#8 중 선택 |
| 서버 인증서 PEM | `{이름}.crt` | Apache `SSLCertificateFile` |
| 체인 PEM | `{이름}_chain.crt` | Apache `SSLCertificateChainFile` |
| PFX | `{이름}.pfx` | IIS, Windows, Tomcat, Spring Boot. 기본은 AES-256이며, 구형 Windows/Java용 **레거시(3DES/SHA1)** 옵션이 있습니다 |
| JKS | `{이름}.jks` | Tomcat, WebLogic, JEUS |
| 통합 PEM | `{이름}_combined.pem` | HAProxy (키와 풀체인을 한 파일에) |
| P7B | `{이름}.p7b` | Windows 인증서 가져오기 |
| DER | `{이름}.cer` | 바이너리 인증서 |
| 트러스트스토어 | `{이름}_truststore.jks` | 클라이언트 측 CA 신뢰 |

형식을 두 개 이상 고르면 ZIP 하나로 내려받습니다. ZIP 안의 `README.txt`에는 체인 정보와 확인 명령이 들어 있고, 비밀번호는 기록하지 않습니다.

## 자동 점검 항목

- 개인키와 인증서가 서로 맞는 쌍인지 확인합니다 (맞지 않으면 키가 필요한 출력은 만들지 않습니다)
- 개인키가 아예 없으면 경고합니다. 이때 만든 PFX/JKS에는 인증서만 들어 있어 서버에 설치할 수 없습니다
- 중간 인증서가 빠졌으면 경고하고, AIA에 있는 발급자 인증서 다운로드 주소를 함께 보여줍니다
- 만료되었거나 30일 안에 만료되는 인증서, 만료된 체인 인증서를 경고합니다
- 체인과 관계없는 인증서는 출력에서 빼고 따로 표시합니다

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
| `formats` | `FULLCHAIN_PEM` `CERT_PEM` `CHAIN_PEM` `KEY_PEM` `COMBINED_PEM` `PFX` `JKS` `TRUSTSTORE_JKS` `P7B` `DER` |
| `baseName`, `outAlias`, `outPassword` | 출력 파일명, 별칭, 비밀번호 |
| `includeRoot` (기본 true), `legacyPfx` (기본 false), `keyFormat` (`PKCS8` / `TRADITIONAL` / `PKCS8_ENCRYPTED`) | 출력 옵션 |
