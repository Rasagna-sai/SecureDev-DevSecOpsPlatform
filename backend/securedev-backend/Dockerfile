
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app

COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY src src

RUN chmod +x mvnw && ./mvnw clean package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app

ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.76.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*


# Install Gitleaks with checksum verification
RUN set -eux; \
    curl -fsSL -o "/tmp/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    curl -fsSL -o /tmp/gitleaks_checksums.txt \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"; \
    cd /tmp; \
    grep "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks_checksums.txt | sha256sum -c -; \
    tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -C /usr/local/bin gitleaks; \
    rm "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks_checksums.txt

# Install Trivy with checksum verification
RUN set -eux; \
    curl -fsSL -o "/tmp/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    curl -fsSL -o /tmp/trivy_checksums.txt \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    cd /tmp; \
    grep "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy_checksums.txt | sha256sum -c -; \
    tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -C /usr/local/bin trivy; \
    rm "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy_checksums.txt

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
