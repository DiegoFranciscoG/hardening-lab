#!/usr/bin/env bash
# Espera a que los tres nodos respondan por SSH (a través del bastión) antes de seguir.
set -euo pipefail
cd /workspace/ansible
for attempt in $(seq 1 20); do
  if ansible all -m ansible.builtin.ping >/tmp/ping.log 2>&1; then
    cat /tmp/ping.log
    exit 0
  fi
  echo "Nodos aún no disponibles (intento ${attempt}/20)..."
  sleep 3
done
cat /tmp/ping.log
exit 1
