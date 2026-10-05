#!/bin/sh
# Prepara el nodo en cada arranque y entrega el control a supervisord.
set -eu

# El nodo emula un servidor completo: sin el marcador de Docker, OpenSCAP evalúa también las reglas de
# plataforma "machine". Los controles que dependen del kernel del anfitrión quedan como excepciones.
rm -f /.dockerenv

# Claves de host propias de cada contenedor: la imagen no trae ninguna.
ssh-keygen -A >/dev/null
install -d -m 0755 /run/sshd

# Clave pública de la cuenta de automatización, generada en `make lab-up`.
if [ -f /etc/lab-keys/authorized_keys ]; then
  install -d -m 0700 -o ansible -g ansible /home/ansible/.ssh
  install -m 0600 -o ansible -g ansible /etc/lab-keys/authorized_keys /home/ansible/.ssh/authorized_keys
fi

if [ -d /etc/postgresql ]; then
  install -d -m 2775 -o postgres -g postgres /run/postgresql
fi
if [ -d /etc/nginx ]; then
  install -d -m 0755 -o www-data -g www-data /run/nginx
fi
if [ -d /etc/fail2ban ]; then
  install -d -m 0755 /run/fail2ban
fi
touch /var/log/auth.log /var/log/syslog

exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
