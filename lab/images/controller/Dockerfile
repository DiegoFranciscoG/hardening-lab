# Controlador del laboratorio: Ansible, Lynis, Trivy, contenido SCAP y el paquete hlab.
# Todo artefacto descargado se verifica con el hash publicado por su proyecto.

FROM python:3.15.0-slim-trixie@sha256:f5b92f2a669a4c347044f29367f31983280b648250ca94dea66f98c53bc87e58 AS downloads

ARG TRIVY_VERSION=0.75.0
# SHA-256 del tarball según trivy_0.75.0_checksums.txt, cuya firma Sigstore se valida con scripts/verify-tools.sh
ARG TRIVY_SHA256=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ARG LYNIS_VERSION=3.1.7
# SHA-256 publicado en https://cisofy.com/downloads/lynis/
ARG LYNIS_SHA256=b5314a07fd85fa3ffc7da57b508f0108ec3280d84e4af823f805d95cbbc2428c
ARG SSG_VERSION=0.1.82
# SHA-512 publicado junto al release de ComplianceAsCode
ARG SSG_SHA512=1caea418f0a5aaef7025e1655ca45a80942ea87ee832b943644ba6f9991b14a6ac5b35dddcd04b754e1fc8fbdee7b7f394507d24b123e821cca0354dc4e03cfd
# Ayudante de OpenSCAP 1.3.9 (LGPL-2.1) para ejecutar scripts SCE cuando /tmp es noexec; Ubuntu no lo empaqueta.
ARG OSCAP_SCE_HELPER_SHA256=73385d11262550a7b1c665991419b53cdb491208bc03b25e1b914f834c55a48c

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates unzip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /dl
RUN curl -fsSLo trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
 && echo "${TRIVY_SHA256}  trivy.tar.gz" | sha256sum -c - \
 && tar -xzf trivy.tar.gz trivy \
 && rm trivy.tar.gz
RUN curl -fsSLo lynis.tar.gz "https://downloads.cisofy.com/lynis/lynis-${LYNIS_VERSION}.tar.gz" \
 && echo "${LYNIS_SHA256}  lynis.tar.gz" | sha256sum -c -
RUN curl -fsSLo oscap-run-sce-script "https://raw.githubusercontent.com/OpenSCAP/openscap/1.3.9/utils/oscap-run-sce-script" \
 && echo "${OSCAP_SCE_HELPER_SHA256}  oscap-run-sce-script" | sha256sum -c -
RUN curl -fsSLo ssg.zip "https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip" \
 && echo "${SSG_SHA512}  ssg.zip" | sha512sum -c - \
 && unzip -q -j ssg.zip "*/ssg-ubuntu2404-ds.xml" -d ssg \
 && rm ssg.zip

FROM ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 AS uv

FROM python:3.15.0-slim-trixie@sha256:f5b92f2a669a4c347044f29367f31983280b648250ca94dea66f98c53bc87e58

ARG TRIVY_SHA256=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ARG LYNIS_VERSION=3.1.7
ARG LYNIS_SHA256=b5314a07fd85fa3ffc7da57b508f0108ec3280d84e4af823f805d95cbbc2428c
ARG SSG_VERSION=0.1.82

ENV HLAB_TRIVY_SHA256=${TRIVY_SHA256} \
    HLAB_LYNIS_VERSION=${LYNIS_VERSION} \
    HLAB_LYNIS_SHA256=${LYNIS_SHA256} \
    HLAB_SSG_VERSION=${SSG_VERSION} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/hlab/.venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH=/opt/hlab/.venv/bin:$PATH \
    ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections \
    HLAB_TOOLS_DIR=/opt/tools

# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client libnss-wrapper \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 auditor \
 && useradd --uid 10001 --gid 10001 --home-dir /tmp/home --no-create-home --shell /bin/bash auditor

COPY --from=uv /uv /usr/local/bin/uv

WORKDIR /opt/hlab
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --extra controller \
 && rm /usr/local/bin/uv

COPY ansible/requirements.yml /tmp/requirements.yml
RUN ansible-galaxy collection install -r /tmp/requirements.yml -p /usr/share/ansible/collections \
 && rm /tmp/requirements.yml

COPY --from=downloads /dl/trivy /usr/local/bin/trivy
COPY --from=downloads /dl/lynis.tar.gz /opt/tools/lynis.tar.gz
COPY --from=downloads /dl/ssg/ssg-ubuntu2404-ds.xml /opt/tools/ssg-ubuntu2404-ds.xml
COPY --from=downloads /dl/oscap-run-sce-script /opt/tools/oscap-run-sce-script
COPY lab/images/controller/entrypoint.sh /usr/local/bin/hlab-controller-entrypoint
RUN chmod 0755 /usr/local/bin/hlab-controller-entrypoint \
 && trivy --version

LABEL org.opencontainers.image.title="hardening-lab controller" \
      org.opencontainers.image.source="https://github.com/DiegoFranciscoG/hardening-lab" \
      org.opencontainers.image.licenses="MIT"

HEALTHCHECK NONE
WORKDIR /workspace
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/hlab-controller-entrypoint"]
CMD ["hlab", "--help"]
