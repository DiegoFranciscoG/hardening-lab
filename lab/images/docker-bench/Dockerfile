# docker-bench-security construido desde un commit fijado: la imagen publicada en Docker Hub está desactualizada.
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

ARG DOCKER_BENCH_COMMIT=154869da6418089decf7e1ab0cfca0e1cdfc5c49
ARG DOCKER_BENCH_SHA256=31b29ac13d36a4cfc155bd5c434ca09dad54518da162f860fba1eda2b6aefcc2

SHELL ["/bin/ash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3018
RUN apk add --no-cache iproute2 docker-cli dumb-init jq curl \
 && curl -fsSLo /tmp/dbs.tar.gz "https://github.com/docker/docker-bench-security/archive/${DOCKER_BENCH_COMMIT}.tar.gz" \
 && echo "${DOCKER_BENCH_SHA256}  /tmp/dbs.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/docker-bench \
 && tar -xzf /tmp/dbs.tar.gz -C /opt/docker-bench --strip-components=1 \
 && rm /tmp/dbs.tar.gz \
 && apk del curl

LABEL org.opencontainers.image.title="hardening-lab docker-bench-security" \
      org.opencontainers.image.licenses="Apache-2.0"

HEALTHCHECK NONE
WORKDIR /opt/docker-bench
# Necesita root y docker.sock para inspeccionar el daemon: solo corre durante `make audit` (ver SECURITY.md).
ENTRYPOINT ["/usr/bin/dumb-init", "/bin/sh", "docker-bench-security.sh"]
