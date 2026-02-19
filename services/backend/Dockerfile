FROM eclipse-temurin:25-jdk-alpine AS builder

WORKDIR /app

COPY gradlew .
COPY gradle gradle
COPY settings.gradle .
COPY services/backend/build.gradle services/backend/build.gradle

RUN ./gradlew :services:backend:dependencies --no-daemon

COPY services/backend/src services/backend/src

RUN ./gradlew :services:backend:bootJar --no-daemon -x test

FROM eclipse-temurin:25-jdk-alpine

WORKDIR /app

COPY --from=builder /app/services/backend/build/libs/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]