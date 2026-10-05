"""Parser de los hechos por host que deja el playbook de auditoría (versiones y pruebas de flujos de red)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from hardening_lab.domain import ParsedReport, RawArtifact, RawFinding, Severity, Status, Tool
from hardening_lab.errors import ParseError
from hardening_lab.parsers import artifact


@dataclass
class HostFacts:
    host: str
    role: str
    lab_state: str
    os: str
    versions: dict[str, str] = field(default_factory=dict)


def parse(paths: list[Path], run_dir: Path) -> tuple[ParsedReport, list[HostFacts]]:
    findings: list[RawFinding] = []
    raw: list[RawArtifact] = []
    facts: list[HostFacts] = []
    for path in sorted(paths):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            host = str(data["host"])
            tests = list(data.get("flow_tests", []))
            rcs = [int(rc) for rc in data.get("flow_rcs", [])]
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ParseError(f"Hechos de auditoría inválidos en {path}: {exc}") from exc
        if len(tests) != len(rcs):
            raise ParseError(f"{path}: flow_tests y flow_rcs no tienen el mismo largo")
        raw.append(artifact(path, run_dir))
        versions = dict(line.split("=", 1) for line in data.get("versions", []) if "=" in line)
        facts.append(
            HostFacts(
                host=host,
                role=str(data.get("role", "")),
                lab_state=str(data.get("lab_state", "baseline")),
                os=str(data.get("os", "")),
                versions=versions,
            )
        )
        for test, rc in zip(tests, rcs, strict=True):
            is_open = rc == 0
            expected_open = test["expect"] == "open"
            target = f"{test['target']}:{test['port']}"
            findings.append(
                RawFinding(
                    tool=Tool.LAB_PROBE,
                    host=host,
                    check_id=f"flow:{host}->{target}",
                    title=f"Flujo {host} → {target} debe estar {'abierto' if expected_open else 'bloqueado'}",
                    status=Status.PASS if is_open == expected_open else Status.FAIL,
                    severity=Severity.HIGH,
                    details=f"observado: {'abierto' if is_open else 'bloqueado'} (red {test.get('network', '?')})",
                    control_hint=str(test["control"]),
                )
            )
    report = ParsedReport(tool=Tool.LAB_PROBE, tool_version="nc (netcat-openbsd)", raw=raw, findings=findings)
    return report, facts
