#!/bin/bash
# Deja el nodo con malas prácticas frecuentes en servidores heredados.
# Ninguna incluye credenciales: las cuentas quedan bloqueadas y root no tiene clave autorizada.
set -euo pipefail
role="$1"

# Cuenta heredada con sudo sin contraseña (CIS 5.2.4).
useradd --create-home --shell /bin/bash deploy
passwd --lock deploy
printf 'deploy ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/90-deploy
chmod 0440 /etc/sudoers.d/90-deploy

# Carpeta compartida escribible por todos y sin sticky bit (CIS 7.1.11).
install -d -m 0777 /srv/exchange

# Ajustes SSH "temporales" que nadie revirtió (CIS 5.1.x).
install -m 0644 /opt/hlab-baseline/sshd-legacy.conf /etc/ssh/sshd_config.d/50-legacy.conf

case "$role" in
  db)
    # PostgreSQL escuchando en todas las interfaces y aceptando cualquier red.
    conf=/etc/postgresql/16/main
    sed -i "s/^#listen_addresses = 'localhost'/listen_addresses = '*'/" "$conf/postgresql.conf"
    printf 'host all all 0.0.0.0/0 scram-sha-256\n' >> "$conf/pg_hba.conf"
    ;;
  web)
    # Página de inicio propia del laboratorio; el resto queda con los valores por defecto del paquete.
    install -m 0644 /opt/hlab-baseline/index.html /var/www/html/index.html
    rm -f /var/www/html/index.nginx-debian.html
    ;;
esac
