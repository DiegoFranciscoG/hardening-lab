#!/usr/bin/env bash
# Segunda pasada del endurecimiento: debe terminar sin cambios (changed=0) en todos los hosts.
set -euo pipefail
cd /workspace/ansible
ANSIBLE_STDOUT_CALLBACK=ansible.posix.json ansible-playbook playbooks/harden.yml > /tmp/idempotence.json
python3 - <<'PY'
import json, sys
stats = json.load(open("/tmp/idempotence.json"))["stats"]
changed = {host: s["changed"] for host, s in stats.items()}
failed = {host: s["failures"] + s["unreachable"] for host, s in stats.items()}
print("changed por host:", changed, "| fallos:", failed)
if any(changed.values()) or any(failed.values()):
    for play in json.load(open("/tmp/idempotence.json"))["plays"]:
        for task in play["tasks"]:
            for host, res in task["hosts"].items():
                if res.get("changed"):
                    print(f"  NO IDEMPOTENTE {host}: {task['task']['name']}")
    sys.exit(1)
print("Idempotente: segunda pasada sin cambios.")
PY
