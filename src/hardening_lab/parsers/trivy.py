"""Parser de `trivy config --format json` (checks integrados para Dockerfile y propios en Rego para Compose)."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from hardening_lab.domain import ParsedReport, RawFinding, Severity, Status, Tool
from hardening_lab.errors import ParseError
from hardening_lab.parsers import artifact

_STATUS = {"PASS": Status.PASS, "FAIL": Status.FAIL, "EXCEPTION": Status.INFO}
_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}
_HOST_IN_MESSAGE = re.compile(r"^\[(?P<host>[\w.-]+)\]")

# Dockerfiles de herramientas: sus hallazgos se reportan aparte de los nodos del laboratorio.
TOOLING_TARGETS = {
    "images/controller/Dockerfile": "controller",
    "images/docker-bench/Dockerfile": "docker-bench",
}


def _scope(target: str, hosts: Sequence[str]) -> list[str]:
    if target in TOOLING_TARGETS:
        return [TOOLING_TARGETS[target]]
    if target.startswith("ansible/"):
        return ["ansible"]
    return list(hosts)


def _finding(host: str, item: dict[str, Any], status: Status, target: str) -> RawFinding:
    return RawFinding(
        tool=Tool.TRIVY,
        host=host,
        check_id=str(item.get("ID") or item.get("AVDID")),
        title=str(item.get("Title", "")),
        status=status,
        severity=_SEVERITY.get(str(item.get("Severity", "UNKNOWN")), Severity.INFO),
        details=str(item.get("Message", "")),
        item=target,
    )


def parse(path: Path, run_dir: Path, hosts: Sequence[str], version: str = "desconocida") -> ParsedReport:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ParseError(f"JSON de Trivy inválido en {path}: {exc}") from exc

    findings: list[RawFinding] = []
    for result in data.get("Results", []) or []:
        target = str(result.get("Target", ""))
        scope = _scope(target, hosts)
        failing_hosts: dict[str, set[str]] = defaultdict(set)
        by_check: dict[str, dict[str, Any]] = {}
        for item in result.get("Misconfigurations", []) or []:
            status = _STATUS.get(str(item.get("Status")), Status.ERROR)
            check_id = str(item.get("ID") or item.get("AVDID"))
            by_check.setdefault(check_id, item)
            match = _HOST_IN_MESSAGE.match(str(item.get("Message", "")))
            if status is Status.FAIL and match and match["host"] in scope:
                failing_hosts[check_id].add(match["host"])
                findings.append(_finding(match["host"], item, status, target))
            elif status is Status.FAIL:
                findings.extend(_finding(host, item, status, target) for host in scope)
                failing_hosts[check_id].update(scope)
            elif status is Status.PASS:
                findings.extend(_finding(host, item, status, target) for host in scope)
        # Un check que falla solo en algunos servicios pasa en el resto.
        for check_id, failing in failing_hosts.items():
            for host in scope:
                if host not in failing:
                    passed = {**by_check[check_id], "Message": "sin hallazgos para este servicio"}
                    findings.append(_finding(host, passed, Status.PASS, target))

    return ParsedReport(
        tool=Tool.TRIVY,
        tool_version=version,
        scores=[],
        raw=[artifact(path, run_dir)],
        findings=findings,
    )
