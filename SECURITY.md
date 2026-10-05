# Política de seguridad

## Alcance ético
Este laboratorio solo audita y endurece contenedores que él mismo crea y destruye (`make lab-up` / `make lab-down`).
No incluye exploits, malware ni credenciales reales, y no debe apuntarse a sistemas de terceros.

## Reportar una vulnerabilidad
No abras un issue público. Escríbeme por GitHub (perfil DiegoFranciscoG) o LinkedIn con los pasos para reproducir el
problema. Respondo en un máximo de 7 días.

## Prácticas aplicadas en este proyecto
- **Sin secretos**: no hay contraseñas en el repo ni en las imágenes. La clave SSH de la automatización se genera en cada
  `make lab-up` dentro de un volumen Docker y se destruye con `make lab-down`. Las claves de host SSH y el certificado TLS
  se generan dentro de cada nodo.
- **Cadena de suministro de las herramientas**: imágenes base fijadas por digest, paquetes de Ubuntu desde un snapshot con
  fecha, Lynis y el contenido SCAP verificados por SHA-256/SHA-512 y Trivy verificado por firma Sigstore y SHA-256
  (`scripts/verify-tools.sh`). Todas las acciones de GitHub fijadas por SHA de commit (lección del incidente de Trivy de
  marzo de 2026) y con `permissions` mínimos por job.
- **Mínimo privilegio**: el controlador corre sin root, sin capacidades, con raíz de solo lectura y `no-new-privileges`.
  docker-bench (que necesita `docker.sock`) solo corre durante la auditoría. Los nodos usan `cap_drop: [ALL]` con las
  capacidades mínimas; las desviaciones están en `docs/excepciones.md`.
- **Exposición**: todos los puertos se publican solo en `127.0.0.1`; las redes de administración y de datos son internas.
- **Parseo seguro**: el XML de OpenSCAP se lee con `defusedxml`; YAML siempre con `safe_load`.
- **CI**: gitleaks sobre todo el historial, ruff, mypy estricto, pytest con cobertura, yamllint, ansible-lint (perfil
  production) y hadolint en cada push y pull request. El informe publicado incluye una CSP con hash del único script.
- **Telemetría**: Trivy se ejecuta con `--disable-telemetry` y `--skip-version-check`.
