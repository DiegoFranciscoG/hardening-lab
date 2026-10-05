# Nodo del laboratorio: emula un servidor Ubuntu 24.04 "recién instalado" (estado baseline).
# Un solo Dockerfile para los tres roles; LAB_ROLE decide el servicio (nginx, PostgreSQL o fail2ban).
FROM ubuntu:noble-20260917@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

ARG LAB_ROLE=bastion
# Snapshot del archivo de Ubuntu con la misma fecha que la imagen base: versiones de paquetes reproducibles.
ARG APT_SNAPSHOT=20260917T000000Z

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && apt-get update --snapshot "${APT_SNAPSHOT}" \
 && apt-get install -y --no-install-recommends \
      openssh-server sudo python3 supervisor rsyslog cron logrotate linux-base \
      nftables iproute2 procps netcat-openbsd \
      unattended-upgrades libpam-pwquality openscap-scanner \
      telnet ftp rsh-redone-client talk \
 && case "${LAB_ROLE}" in \
      web)     apt-get install -y --no-install-recommends nginx ;; \
      db)      apt-get install -y --no-install-recommends postgresql postgresql-client ;; \
      bastion) apt-get install -y --no-install-recommends fail2ban ;; \
      *)       echo "LAB_ROLE desconocido: ${LAB_ROLE}" >&2; exit 1 ;; \
    esac \
 && rm -f /etc/ssh/ssh_host_* \
 && rm -rf /var/lib/apt/lists/*

# Cuenta de automatización (Ansible): sin contraseña, solo clave pública inyectada al arrancar.
RUN useradd --create-home --shell /bin/bash --groups sudo ansible \
 && passwd --lock ansible \
 && printf 'ansible ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/10-ansible \
 && chmod 0440 /etc/sudoers.d/10-ansible

# Malas prácticas típicas de un servidor heredado (documentadas en docs/baseline.md).
COPY baseline/ /opt/hlab-baseline/
RUN bash /opt/hlab-baseline/apply.sh "${LAB_ROLE}" && rm -rf /opt/hlab-baseline

COPY supervisor/common.conf /etc/supervisor/conf.d/00-common.conf
COPY supervisor/${LAB_ROLE}.conf /etc/supervisor/conf.d/10-role.conf
COPY entrypoint.sh /usr/local/sbin/hlab-entrypoint
RUN chmod 0755 /usr/local/sbin/hlab-entrypoint

LABEL org.opencontainers.image.title="hardening-lab node (${LAB_ROLE})" \
      org.opencontainers.image.source="https://github.com/DiegoFranciscoG/hardening-lab" \
      org.opencontainers.image.licenses="MIT"

EXPOSE 22
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
  CMD ["/usr/bin/pgrep", "-x", "sshd"]

# El nodo emula una máquina completa: supervisord (PID 1) necesita root para lanzar sshd.
# Excepción documentada en controls/exceptions.yml (EXC-005).
ENTRYPOINT ["/usr/local/sbin/hlab-entrypoint"]
