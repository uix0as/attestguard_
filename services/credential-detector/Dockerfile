FROM eclipse-temurin:17-jdk-jammy AS build
WORKDIR /src
COPY src ./src
RUN mkdir -p target/classes \
    && javac -Xlint:all -Werror -d target/classes $(find src/main/java -name '*.java') \
    && jar --create --file target/credential-detector.jar \
    --main-class io.attestguard.detector.Main -C target/classes .

FROM eclipse-temurin:17-jre-jammy
RUN useradd --system --uid 10001 --no-create-home attestguard
WORKDIR /app
COPY --from=build /src/target/credential-detector.jar /app/service.jar
USER 10001:10001
EXPOSE 8090
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70", "-jar", "/app/service.jar"]
