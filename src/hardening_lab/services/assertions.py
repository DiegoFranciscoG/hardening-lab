"""Evaluación de las aserciones del catálogo sobre la evidencia guardada (método "examine")."""

from __future__ import annotations

import re
from pathlib import Path

from hardening_lab.config import Catalog, Inventory
from hardening_lab.domain import RawFinding, Severity, Status, Tool

HEADER_PREFIX = "# "


def evidence_body(path: Path) -> str:
    """Contenido de la sonda sin las líneas de encabezado que agrega el playbook."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    body = [line for index, line in enumerate(lines) if not (index < 4 and line.startswith(HEADER_PREFIX))]
    return "\n".join(body)


def evaluate(catalog: Catalog, inventory: Inventory, run_dir: Path) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for host_name, host in sorted(inventory.hosts.items()):
        for control in catalog:
            if host.role not in control.applies_to:
                continue
            for index, assertion in enumerate(control.assertions, start=1):
                path = run_dir / "evidence" / host_name / f"{assertion.probe}.txt"
                check_id = f"assert:{control.control_id}:{index}"
                expectation = "debe aparecer" if assertion.expect == "present" else "no debe aparecer"
                title = f"{assertion.probe}: /{assertion.pattern}/ {expectation}"
                if not path.exists():
                    findings.append(
                        RawFinding(
                            tool=Tool.LAB_PROBE,
                            host=host_name,
                            check_id=check_id,
                            title=title,
                            status=Status.NOTCHECKED,
                            details="sin evidencia de la sonda",
                            control_hint=control.control_id,
                        )
                    )
                    continue
                found = re.search(assertion.pattern, evidence_body(path), re.MULTILINE) is not None
                ok = found if assertion.expect == "present" else not found
                findings.append(
                    RawFinding(
                        tool=Tool.LAB_PROBE,
                        host=host_name,
                        check_id=check_id,
                        title=title,
                        status=Status.PASS if ok else Status.FAIL,
                        severity=Severity.MEDIUM,
                        details=f"evidencia: evidence/{host_name}/{assertion.probe}.txt",
                        control_hint=control.control_id,
                    )
                )
    return findings
