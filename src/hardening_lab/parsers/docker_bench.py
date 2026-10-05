"""Parser del JSON de docker-bench-security (CIS Docker Benchmark 1.6.0).

docker-bench informa por chequeo, no por contenedor: los `items` dicen qué contenedores fallan. Se expande
a un hallazgo por host del laboratorio para poder comparar host a host.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from hardening_lab.domain import ParsedReport, RawFinding, Score, Status, Tool
from hardening_lab.errors import ParseError
from hardening_lab.parsers import artifact

_STATUS = {"PASS": Status.PASS, "WARN": Status.FAIL, "INFO": Status.INFO, "NOTE": Status.NOTCHECKED}
LAB_SCOPE = "lab"


def _affected(result: dict[str, Any], hosts: Sequence[str]) -> set[str]:
    names = {str(item).split(":", 1)[0] for item in result.get("items", []) or []}
    return names & set(hosts)


def parse(path: Path, run_dir: Path, hosts: Sequence[str]) -> ParsedReport:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        sections = data["tests"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ParseError(f"JSON de docker-bench inválido en {path}: {exc}") from exc

    findings: list[RawFinding] = []
    for section in sections:
        for result in section.get("results", []):
            check_id = str(result["id"])
            outcome = _STATUS.get(str(result.get("result")), Status.ERROR)
            affected = _affected(result, hosts)
            for host in hosts:
                if affected and host not in affected:
                    if outcome is not Status.FAIL:
                        continue
                    status = Status.PASS
                    details = "no aparece entre los contenedores señalados"
                else:
                    status = outcome
                    details = str(result.get("details", ""))
                findings.append(
                    RawFinding(
                        tool=Tool.DOCKER_BENCH,
                        host=host,
                        check_id=check_id,
                        title=str(result.get("desc", check_id)),
                        status=status,
                        details=details,
                    )
                )

    scores = []
    if isinstance(data.get("score"), int | float):
        scores.append(Score(host=LAB_SCOPE, value=float(data["score"]), maximum=None))
    return ParsedReport(
        tool=Tool.DOCKER_BENCH,
        tool_version=f"docker-bench-security (CIS Docker {data.get('dockerbenchsecurity', '?')})",
        scores=scores,
        raw=[artifact(path, run_dir)],
        findings=findings,
    )
