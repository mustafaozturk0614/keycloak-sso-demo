FROM eclipse-temurin:17-jre-alpine

RUN apk add --no-cache curl

RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

COPY target/*.jar app.jar

RUN mkdir -p /app/logs && \
    chown -R appuser:appgroup /app

USER appuser

ENV SPRING_PROFILES_ACTIVE=docker
ENV SERVER_PORT=8082
ENV JAVA_OPTS="-Xmx512m -Xms256m"

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8082/actuator/health || exit 1

EXPOSE 8082

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]

LABEL maintainer="HR Portal Team"
LABEL version="2.0.0"
LABEL description="HR Portal Backend"
LABEL port="8082"
LABEL authentication="Header-Based"
