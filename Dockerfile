# syntax=docker/dockerfile:1

# ---- build ---------------------------------------------------------------
FROM eclipse-temurin:17-jdk AS build
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
