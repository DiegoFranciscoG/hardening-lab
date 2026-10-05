# Estado baseline del laboratorio

El baseline representa un **servidor Ubuntu 24.04 recién instalado al que un administrador anterior le dejó ajustes
"temporales"**. Ningún ajuste incluye credenciales: las cuentas tienen la contraseña bloqueada, root no tiene clave
autorizada y la única forma de entrar es la clave efímera de la automatización.

| Ámbito | Qué trae el baseline | Dónde se define | Control que lo corrige |
|---|---|---|---|
| SSH | `PermitRootLogin yes`, `PasswordAuthentication yes`, `MaxAuthTries 10`, `X11Forwarding yes`, `LoginGraceTime 120` y los algoritmos por defecto de OpenSSH 9.6 | `lab/images/node/baseline/sshd-legacy.conf` | HL-SSH-001 a HL-SSH-010 |
| Cuentas | Cuenta heredada `deploy` con `sudo NOPASSWD: ALL`; `login.defs` sin caducidad (`PASS_MAX_DAYS 99999`) y umask 022 | `lab/images/node/baseline/apply.sh` | HL-ACC-001 a HL-ACC-006, HL-SUDO-* |
| PAM | Pila por defecto de Ubuntu: `nullok`, sin faillock ni historial de contraseñas | paquete `libpam-runtime` | HL-PAM-001 a HL-PAM-004 |
| Permisos | `/srv/exchange` en `0777` sin sticky bit; `crontab` y directorios de cron con permisos por defecto | `apply.sh` y paquetes | HL-PERM-001 a HL-PERM-005 |
| Paquetes | Clientes inseguros instalados: telnet, ftp, rsh, talk | `lab/images/node/Dockerfile` | HL-SVC-001 |
| Registros | rsyslog apagado: no hay `/var/log/auth.log` | `supervisor/common.conf` | HL-LOG-001, HL-LOG-002 |
| Firewall | nftables instalado pero sin reglas; red Docker plana con los tres nodos | `lab/compose.yaml` | HL-FW-001 a HL-FW-004 |
| Kernel y red | Parámetros por defecto del namespace (redirecciones ICMP aceptadas, `rp_filter` laxo, `log_martians` apagado) | `lab/compose.yaml` | HL-NET-001 a HL-NET-003 |
| Runtime de contenedores | Capacidades por defecto, sin límites de memoria/PIDs, `restart: always`, SSH de cada nodo y PostgreSQL publicados en el anfitrión (solo en 127.0.0.1) | `lab/compose.yaml` | HL-CTR-001 a HL-CTR-012 |
| nginx | Proceso maestro como root, `server_tokens` activo, sin cabeceras de seguridad ni TLS | paquete `nginx` | HL-WEB-001 a HL-WEB-004 |
| PostgreSQL | `listen_addresses = '*'` y `pg_hba` aceptando `0.0.0.0/0`; configuración legible por todos | `apply.sh` | HL-DB-001 a HL-DB-004 |
| fail2ban | Instalado pero apagado en el bastión | `supervisor/bastion.conf` | HL-SSH-011 |

Aun en el baseline todos los puertos se publican **solo en `127.0.0.1`**: el laboratorio nunca expone servicios a la red
del equipo anfitrión.
