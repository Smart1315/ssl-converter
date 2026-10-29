# syntax=docker/dockerfile:1

# 멀티 아키텍처 이미지 (linux/amd64, linux/arm64)
#   docker buildx build --platform linux/amd64,linux/arm64 -t ssl-converter .
# 빌드 결과(jar)는 아키텍처와 무관하므로 빌드 단계는 빌드하는 PC의 아키텍처에서 한 번만 실행하고,
# 실행 단계만 대상 아키텍처의 JRE 이미지를 사용한다. (QEMU 에뮬레이션으로 Maven 을 돌리지 않아 빠르다)

# ---- build ---------------------------------------------------------------
FROM --platform=$BUILDPLATFORM eclipse-temurin:17-jdk AS build
WORKDIR /workspace

# 의존성 레이어 캐시: pom.xml 이 바뀌지 않으면 다시 받지 않는다
COPY mvnw pom.xml ./
COPY .mvn .mvn
RUN chmod +x mvnw && ./mvnw -B -q dependency:go-offline

COPY src src
# 테스트는 CI/로컬에서 실행한다 (이미지 빌드 시간 단축)
RUN ./mvnw -B -q -DskipTests package \
 && cp target/ssl-converter-*.jar application.jar \
 && java -Djarmode=tools -jar application.jar extract --layers --destination extracted

# ---- runtime -------------------------------------------------------------
FROM eclipse-temurin:17-jre
WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --no-create-home app

# 변경 빈도가 낮은 레이어부터 복사
COPY --from=build /workspace/extracted/dependencies/ ./
COPY --from=build /workspace/extracted/spring-boot-loader/ ./
COPY --from=build /workspace/extracted/snapshot-dependencies/ ./
COPY --from=build /workspace/extracted/application/ ./

USER app
EXPOSE 8080
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75"
ENTRYPOINT ["java", "-jar", "application.jar"]
