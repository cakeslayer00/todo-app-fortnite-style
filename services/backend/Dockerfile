# Stage 1: Build the JAR
FROM eclipse-temurin:25-jdk-alpine AS builder

WORKDIR /app

# Copy wrapper and configuration
COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .
COPY services/backend/build.gradle services/backend/build.gradle

# Download dependencies separately to leverage Docker layer caching
RUN --mount=type=cache,target=/root/.gradle ./gradlew :services:backend:dependencies --no-daemon

# Copy source code and build
COPY services/backend/src services/backend/src
RUN --mount=type=cache,target=/root/.gradle ./gradlew :services:backend:bootJar --no-daemon -x test

# Stage 2: Create a lightweight runtime image
FROM eclipse-temurin:25-jre-alpine

WORKDIR /app

# Create a non-root user for security
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

COPY --from=builder /app/services/backend/build/libs/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]