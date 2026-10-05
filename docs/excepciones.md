# Excepciones justificadas

> Archivo generado con `hlab exceptions-doc` desde `controls/exceptions.yml`. No editar a mano.

Cada excepción es una desviación **identificada, documentada y aprobada** de la configuración segura
(NIST SP 800-53 Rev. 5, CM-6(c)), con los controles que mitigan su riesgo (NIST SP 800-128) y una fecha
de revisión de máximo 180 días. Una excepción vencida deja de cubrir el control y el informe lo marca como
falla. El aprobador es un rol ficticio del laboratorio.

| ID | Controles | Alcance | Categoría | Riesgo residual | Revisión |
|---|---|---|---|---|---|
| EXC-001 | HL-AUD-001 | bastion, web, db | Responsabilidad del anfitrión | medium | 2027-03-31 |
| EXC-002 | HL-KRN-004 | bastion, web, db | Responsabilidad del anfitrión | medium | 2027-03-31 |
| EXC-003 | HL-SVC-004 | bastion, web, db | Requisito operativo | low | 2027-03-31 |
| EXC-004 | HL-NET-004 | bastion, web, db | No aplicable en contenedor | low | 2027-03-31 |
| EXC-005 | HL-CTR-008 | bastion, web, db | No aplicable en contenedor | medium | 2027-03-31 |
| EXC-006 | HL-CTR-006 | bastion, web, db | Requisito operativo | medium | 2027-03-31 |
| EXC-007 | HL-SSH-005 | lab-bastion | Requisito operativo | low | 2027-03-31 |
| EXC-008 | HL-SUDO-004 | bastion, web, db | Requisito operativo | medium | 2027-03-31 |
| EXC-009 | HL-CTR-007 | bastion, web, db | Requisito operativo | low | 2027-03-31 |
| EXC-010 | HL-CTR-002 | bastion, web, db | Requisito operativo | low | 2027-03-31 |
| EXC-011 | HL-CTR-009 | bastion, web, db | Requisito operativo | low | 2027-03-31 |
| EXC-012 | HL-CTR-013 | bastion, web, db | Requisito operativo | low | 2027-03-31 |
| EXC-013 | HL-FW-002, HL-LOG-003 | bastion, web, db | No aplicable en contenedor | low | 2027-03-31 |
| EXC-014 | HL-SVC-005 | bastion, web, db | Responsabilidad del anfitrión | low | 2027-03-31 |
| EXC-015 | HL-SVC-002 | lab-web | Requisito operativo | low | 2027-03-31 |
| EXC-016 | HL-SSH-007 | bastion, web, db | Requisito operativo | info | 2027-03-31 |

## EXC-001 · HL-AUD-001

- **HL-AUD-001**: Auditoría del kernel (auditd) con reglas de eventos privilegiados (severidad medium)
- **Categoría**: Responsabilidad del anfitrión
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** El subsistema de auditoría del kernel no está aislado por namespaces: auditd solo puede ejecutarse en el namespace inicial, es decir, en el anfitrión. Dentro de un contenedor no hay forma de cargar reglas de audit.

**Controles compensatorios:**
- Registro de sudo en /var/log/sudo.log con use_pty (HL-SUDO-001)
- LogLevel VERBOSE de SSH enviado a rsyslog (HL-SSH-007, HL-LOG-001)
- Detección de deriva programada con re-auditoría y ansible --check

**Referencias:** Lista linux-audit (mantenedores del subsistema): auditd no es namespaced; CIS Ubuntu 24.04 v1.0.0 sección 6.2 (Level 2).

## EXC-002 · HL-KRN-004

- **HL-KRN-004**: AppArmor instalado y aplicado (severidad medium)
- **Categoría**: Responsabilidad del anfitrión
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** AppArmor lo aplica el anfitrión al crear el contenedor (perfil docker-default en Linux con AppArmor). Instalarlo o configurarlo dentro del nodo no tiene efecto; Docker Desktop no expone AppArmor en su VM.

**Controles compensatorios:**
- Perfil seccomp por defecto de Docker activo (docker-bench 5.22 en PASS)
- cap_drop ALL con capacidades mínimas y sin contenedores privilegiados (HL-CTR-002, HL-CTR-003)

**Referencias:** CIS Docker Benchmark 5.2; Docker Docs: Docker Engine security.

## EXC-003 · HL-SVC-004

- **HL-SVC-004**: Verificación periódica de integridad de archivos (AIDE) (severidad medium)
- **Categoría**: Requisito operativo
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** AIDE compara el sistema contra una base local; en contenedores la integridad se garantiza mejor por diseño: imagen fijada por digest, reconstrucción reproducible y re-auditoría que detecta cualquier cambio de configuración.

**Controles compensatorios:**
- Imágenes base fijadas por digest y paquetes desde snapshot de Ubuntu
- Detección de deriva (re-auditoría + ansible --check) contra la línea base aprobada
- Trivy sobre Dockerfiles, Compose y Ansible en cada auditoría

**Referencias:** CIS Ubuntu 24.04 v1.0.0 6.3.1 y 6.3.2; NIST SP 800-190 (contramedidas de imagen).

## EXC-004 · HL-NET-004

- **HL-NET-004**: Reenvío de paquetes IP deshabilitado en el kernel (severidad medium)
- **Categoría**: No aplicable en contenedor
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** Cambiar net.ipv4.ip_forward reinicia los demás parámetros de red al valor por defecto del kernel y Docker aplica los sysctl en orden aleatorio, por lo que fijarlo en el contenedor deja accept_redirects en 1 de forma no determinista. El namespace hereda ip_forward=1 del anfitrión de Docker.

**Controles compensatorios:**
- Cadena forward de nftables con policy drop en todos los nodos (HL-FW-001)
- Persistencia net.ipv4.ip_forward=0 en /etc/sysctl.d para cuando el rol se aplique a una VM

**Referencias:** docs.kernel.org networking/ip-sysctl: ip_forward reinicia la configuración al cambiar.

## EXC-005 · HL-CTR-008

- **HL-CTR-008**: Contenedor ejecutado con usuario no root y sin sshd (severidad medium)
- **Categoría**: No aplicable en contenedor
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** Los nodos emulan servidores completos administrados por SSH: el proceso 1 (supervisord) y sshd requieren root para separar privilegios y cambiar de usuario. Los servicios de negocio sí corren sin root.

**Controles compensatorios:**
- nginx (incluido el proceso maestro) como www-data y PostgreSQL como postgres (HL-WEB-002)
- cap_drop ALL con capacidades mínimas, sin privileged ni docker.sock (HL-CTR-002, HL-CTR-003)
- SSH solo por clave, grupo autorizado y acceso únicamente a través del bastión (HL-SSH-*, HL-FW-004)

**Referencias:** CIS Docker Benchmark 4.1 y 5.7; OWASP Docker Security Cheat Sheet, regla 2.

## EXC-006 · HL-CTR-006

- **HL-CTR-006**: Procesos sin posibilidad de ganar privilegios (no-new-privileges) (severidad medium)
- **Categoría**: Requisito operativo
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** no-new-privileges impide que sudo eleve privilegios, y la automatización necesita sudo para aplicar y verificar el endurecimiento. El controlador, que no administra hosts, sí usa no-new-privileges.

**Controles compensatorios:**
- Cuenta de automatización sin contraseña (bloqueada), solo con clave efímera y solo desde el bastión
- sudo con use_pty y registro propio (HL-SUDO-001)

**Referencias:** CIS Docker Benchmark 5.26; Docker Docs: --security-opt no-new-privileges.

## EXC-007 · HL-SSH-005

- **HL-SSH-005**: Reenvíos SSH (X11, TCP, agente y túneles) deshabilitados (severidad medium)
- **Categoría**: Requisito operativo
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** El bastión debe reenviar TCP (ssh -W) para que la automatización llegue a los nodos internos. El reenvío queda deshabilitado de forma global y solo se habilita para la cuenta ansible hacia el puerto 22 de los nodos. Ninguna herramienta lo marca (sshd -T muestra la configuración global), pero se documenta porque es una desviación real del control.

**Controles compensatorios:**
- Bloque Match User ansible con PermitOpen limitado a <ip-admin>:22 de cada nodo
- nftables del bastión solo permite salir por TCP/22 hacia la red de administración

**Referencias:** CIS Ubuntu 24.04 v1.0.0 5.1.8.

## EXC-008 · HL-SUDO-004

- **HL-SUDO-004**: Toda escalada de privilegios con sudo exige contraseña (severidad high)
- **Categoría**: Requisito operativo
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** La cuenta de automatización no tiene contraseña (está bloqueada) y entra solo con una clave efímera, por lo que NOPASSWD es la única forma de que Ansible eleve privilegios sin guardar secretos.

**Controles compensatorios:**
- Cuenta bloqueada para contraseña y con clave generada en cada laboratorio
- SSH a los nodos solo desde el bastión (HL-FW-004) y del bastión solo desde el controlador
- Cada sudo queda registrado en /var/log/sudo.log (HL-SUDO-001)

**Referencias:** CIS Ubuntu 24.04 v1.0.0 5.2.4 (Level 2).

## EXC-009 · HL-CTR-007

- **HL-CTR-007**: Sistema de archivos raíz del contenedor de solo lectura (severidad low)
- **Categoría**: Requisito operativo
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** El laboratorio demuestra endurecimiento en sitio con Ansible, que necesita escribir la configuración del sistema; una raíz de solo lectura lo impediría. En producción el patrón sería imagen dorada endurecida y read_only.

**Controles compensatorios:**
- /tmp y /dev/shm en tmpfs con noexec, nosuid y nodev
- Detección de deriva que reporta cualquier cambio respecto de la línea base

**Referencias:** CIS Docker Benchmark 5.13; NIST SP 800-190 (contenedores inmutables).

## EXC-010 · HL-CTR-002

- **HL-CTR-002**: Capacidades del kernel mínimas (cap_drop ALL) (severidad medium)
- **Categoría**: Requisito operativo
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** Cada nodo aplica su propio firewall nftables, que requiere CAP_NET_ADMIN. La capacidad es namespaced: solo afecta la pila de red del propio contenedor, no la del anfitrión.

**Controles compensatorios:**
- Se quitan todas las demás capacidades por defecto (MKNOD, NET_RAW, SETFCAP, SETPCAP, FSETID)
- Sin modo privilegiado ni namespaces del anfitrión compartidos (HL-CTR-003, HL-CTR-012)

**Referencias:** CIS Docker Benchmark 5.4.

## EXC-011 · HL-CTR-009

- **HL-CTR-009**: Solo se publican los puertos que el rol necesita (severidad medium)
- **Categoría**: Requisito operativo
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** El bastión publica SSH y la web publica HTTP/HTTPS para el anfitrión; además la imagen de nodo declara EXPOSE 22 porque todos los nodos se administran por SSH. La base de datos no publica ningún puerto.

**Controles compensatorios:**
- Todos los puertos se publican solo en 127.0.0.1 (HL-CTR-001)
- nftables restringe cada puerto a su origen esperado (HL-FW-001, HL-FW-004)

**Referencias:** CIS Docker Benchmark 5.9.

## EXC-012 · HL-CTR-013

- **HL-CTR-013**: Confianza de contenido de imágenes (Docker Content Trust) (severidad low)
- **Categoría**: Requisito operativo
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** Las imágenes del laboratorio se construyen en local y no se descargan de un registro, así que Docker Content Trust no aplica a ellas. La integridad de las bases se asegura fijándolas por digest.

**Controles compensatorios:**
- Imágenes base fijadas por digest SHA-256
- Herramientas descargadas verificadas por SHA-256/SHA-512 y Trivy por firma Sigstore

**Referencias:** CIS Docker Benchmark 4.5.

## EXC-013 · HL-FW-002, HL-LOG-003

- **HL-FW-002**: Una sola herramienta de firewall gestionada como servicio (severidad low)
- **HL-LOG-003**: journald y servicios de registro gestionados por systemd (severidad low)
- **Categoría**: No aplicable en contenedor
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** Los nodos no ejecutan systemd ni journald (el proceso 1 es supervisord), por lo que las reglas que verifican unidades de systemd no pueden evaluarse ni cumplirse.

**Controles compensatorios:**
- supervisord carga /etc/nftables.conf al arrancar y mantiene rsyslog activo
- Logs de los contenedores con rotación (json-file, max-size 10m)

**Referencias:** CIS Ubuntu 24.04 v1.0.0 4.1.1, 4.3.9 y 6.1.x.

## EXC-014 · HL-SVC-005

- **HL-SVC-005**: Sincronización de hora con una única fuente (severidad medium)
- **Categoría**: Responsabilidad del anfitrión
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** Los contenedores comparten el reloj del anfitrión y no tienen CAP_SYS_TIME: sincronizar la hora es responsabilidad del anfitrión de Docker.

**Controles compensatorios:**
- Marcas de tiempo de auditoría en UTC desde un único reloj (el del anfitrión)

**Referencias:** CIS Ubuntu 24.04 v1.0.0 2.3.1.1.

## EXC-015 · HL-SVC-002

- **HL-SVC-002**: Solo los servicios de red que exige el rol del host (severidad medium)
- **Categoría**: Requisito operativo
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** CIS 2.1.18 pide quitar el servidor web cuando no se usa; en lab-web servir HTTP/HTTPS es precisamente su función.

**Controles compensatorios:**
- nginx sin root, sin versión expuesta, con cabeceras de seguridad, TLS y métodos limitados (HL-WEB-*)

**Referencias:** CIS Ubuntu 24.04 v1.0.0 2.1.18.

## EXC-016 · HL-SSH-007

- **HL-SSH-007**: Registro detallado de eventos SSH (severidad low)
- **Categoría**: Requisito operativo
- **Aprobada por**: Responsable de seguridad del laboratorio (rol ficticio) el 2026-10-04; revisión antes del 2027-03-31

**Justificación.** CIS 5.1.14 admite LogLevel INFO o VERBOSE, pero la regla de SSG solo acepta INFO. Se elige VERBOSE porque además registra la huella de la clave usada en cada acceso, lo que mejora la trazabilidad (Lynis también lo recomienda).

**Controles compensatorios:**
- VERBOSE incluye todo lo que registra INFO

**Referencias:** CIS Ubuntu 24.04 v1.0.0 5.1.14; SSG regla sshd_set_loglevel_info (patrón ^INFO$).
