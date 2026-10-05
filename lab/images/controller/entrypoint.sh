#!/bin/sh
# El controlador corre sin root. Si se lanza con un UID arbitrario (el del usuario en Linux/CI),
# nss_wrapper le da una entrada de passwd para que ssh y Ansible funcionen.
set -eu

export HOME=/tmp/home
mkdir -p "$HOME/.ssh" "$HOME/.ansible/tmp"
chmod 0700 "$HOME/.ssh"

if ! getent passwd "$(id -u)" >/dev/null 2>&1; then
  printf 'auditor:x:%s:%s:auditor:%s:/bin/sh\n' "$(id -u)" "$(id -g)" "$HOME" > /tmp/passwd
  printf 'auditor:x:%s:\n' "$(id -g)" > /tmp/group
  export LD_PRELOAD=libnss_wrapper.so NSS_WRAPPER_PASSWD=/tmp/passwd NSS_WRAPPER_GROUP=/tmp/group
fi

exec "$@"
