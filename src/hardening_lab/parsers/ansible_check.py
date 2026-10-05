"""Parser de `ansible-playbook --check` con el callback ansible.posix.json.

Cada tarea de endurecimiento se llama `HL-XXX-NNN[, HL-...] | descripción` (el callback antepone `rol : `).
Una tarea que cambiaría algo en modo check indica que el host no está en el estado deseado (deriva).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from hardening_lab.domain import ParsedReport, RawFinding, Status, Tool
from hardening_lab.errors import ParseError
from hardening_lab.parsers import artifact

CONTROL_PREFIX = re.compile(r"^(?:[\w-]+ : )?(?P<ids>HL-[A-Z]+-\d{3}(?:\s*,\s*HL-[A-Z]+-\d{3})*)\s*\|\s*(?P<title>.+)$")


def _status(result: dict[str, Any]) -> Status:
    if result.get("unreachable") or result.get("failed"):
        return Status.ERROR
    if result.get("skipped"):
        # Un comando se salta en modo check aunque se habría ejecutado: eso también es una diferencia.
        if "check mode" in str(result.get("msg", "")).lower():
            return Status.FAIL
        return Status.NOTAPPLICABLE
    if result.get("changed"):
        return Status.FAIL
    return Status.PASS


def _load(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    start = text.find("{")
    if start < 0:
        raise ParseError(f"{path} no contiene JSON del callback de Ansible")
    try:
        loaded: dict[str, Any] = json.loads(text[start:])
    except json.JSONDecodeError as exc:
        raise ParseError(f"JSON del modo check inválido en {path}: {exc}") from exc
    return loaded


def parse(path: Path, run_dir: Path, version: str = "desconocida") -> ParsedReport:
    data = _load(path)
    findings: list[RawFinding] = []
    for play in data.get("plays", []):
        for task in play.get("tasks", []):
            name = str(task.get("task", {}).get("name", ""))
            match = CONTROL_PREFIX.match(name)
            if not match:
                continue
            control_ids = [cid.strip() for cid in match["ids"].split(",")]
            for host, result in (task.get("hosts") or {}).items():
                status = _status(result)
                for control_id in control_ids:
                    findings.append(
                        RawFinding(
                            tool=Tool.ANSIBLE_CHECK,
                            host=host,
                            check_id=name,
                            title=match["title"],
                            status=status,
                            details="cambiaría en modo check" if status is Status.FAIL else "",
                            item=control_id,
                            control_hint=control_id,
                        )
                    )
    return ParsedReport(
        tool=Tool.ANSIBLE_CHECK,
        tool_version=version,
        raw=[artifact(path, run_dir)],
        findings=findings,
    )
