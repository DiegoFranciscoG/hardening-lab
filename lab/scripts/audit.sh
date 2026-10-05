#!/usr/bin/env bash
# Orquesta la auditoría dentro del controlador: Ansible (Lynis, OpenSCAP, sondas), Trivy, modo check e ingesta.
# docker-bench ya corrió desde el anfitrión (necesita docker.sock) y dejó su salida en raw/docker-bench.
set -euo pipefail
: "${HLAB_RUN_ID:?Falta HLAB_RUN_ID}" "${HLAB_PHASE:?Falta HLAB_PHASE}"

run_dir="/workspace/reports/runs/${HLAB_RUN_ID}"
mkdir -p "${run_dir}"/raw/{lynis,openscap,trivy,facts,ansible-check} "${run_dir}/evidence"

echo "==> Ansible: Lynis, OpenSCAP (CIS Level 1 Server), sondas de evidencia y pruebas de flujos"
(cd /workspace/ansible && ansible-playbook playbooks/audit.yml)

echo "==> Trivy: Dockerfiles y Ansible con checks integrados; Compose efectivo con checks propios (Rego)"
target=/tmp/trivy-target
rm -rf "${target}" && mkdir -p "${target}/compose"
for image_dir in /workspace/lab/images/*/; do
  name="$(basename "${image_dir}")"
  mkdir -p "${target}/images/${name}"
  cp "${image_dir}Dockerfile" "${target}/images/${name}/Dockerfile"
done
cp "${run_dir}/raw/compose/effective.yaml" "${target}/compose/compose.effective.yaml"
cp -r /workspace/ansible "${target}/ansible"
trivy config --quiet --skip-check-update --skip-version-check --disable-telemetry --include-non-failures \
  --misconfig-scanners dockerfile,yaml,ansible \
  --config-check /workspace/checks/compose --check-namespaces user \
  --format json --output "${run_dir}/raw/trivy/lab.json" "${target}"

echo "==> Versiones de las herramientas del controlador"
python3 /workspace/lab/scripts/tool_versions.py "${run_dir}/raw/tools.json"

if [ -f /workspace/ansible/playbooks/harden.yml ]; then
  echo "==> Ansible --check: tareas que cambiarían respecto del estado deseado"
  (cd /workspace/ansible && ANSIBLE_STDOUT_CALLBACK=ansible.posix.json \
    ansible-playbook playbooks/harden.yml --check --diff > "${run_dir}/raw/ansible-check/harden-check.json") || true
fi

echo "==> Normalización de resultados"
hlab ingest --run-dir "${run_dir}" --phase "${HLAB_PHASE}"
