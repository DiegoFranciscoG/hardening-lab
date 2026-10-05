"""Parser de `lynis-report.dat` (formato clave=valor; arreglos con `clave[]=`)."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from hardening_lab.domain import ParsedReport, RawFinding, Score, Severity, Status, Tool
from hardening_lab.errors import ParseError
from hardening_lab.parsers import artifact


def _split_list(value: str) -> list[str]:
    seen: dict[str, None] = {}
    for item in value.split("|"):
        if item:
            seen.setdefault(item, None)
    return list(seen)


def _clean(value: str) -> str:
    return "" if value in {"", "-"} else value


def parse_report_text(text: str) -> tuple[dict[str, str], dict[str, list[str]]]:
    values: dict[str, str] = {}
    arrays: dict[str, list[str]] = defaultdict(list)
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if key.endswith("[]"):
            arrays[key[:-2]].append(value)
        else:
            values[key] = value
    return values, arrays


def parse(path: Path, run_dir: Path) -> ParsedReport:
    values, arrays = parse_report_text(path.read_text(encoding="utf-8", errors="replace"))
    if "lynis_version" not in values or "hostname" not in values:
        raise ParseError(f"{path} no parece un reporte de Lynis (faltan lynis_version/hostname)")
    host = values["hostname"]

    findings: list[RawFinding] = []
    with_issues: set[str] = set()
    for kind, severity in (("warning", Severity.MEDIUM), ("suggestion", Severity.LOW)):
        for entry in arrays.get(kind, []):
            test, message, details, solution = ([*entry.split("|"), "", "", "", ""])[:4]
            if not test:
                continue
            with_issues.add(test)
            findings.append(
                RawFinding(
                    tool=Tool.LYNIS,
                    host=host,
                    check_id=test,
                    title=message,
                    status=Status.FAIL,
                    severity=severity,
                    details=" · ".join(p for p in (_clean(details), _clean(solution)) if p),
                    item=f"{kind}:{message}|{_clean(details)}",
                )
            )

    for test in _split_list(values.get("tests_executed", "")):
        if test not in with_issues:
            findings.append(
                RawFinding(
                    tool=Tool.LYNIS,
                    host=host,
                    check_id=test,
                    title=f"Prueba {test} ejecutada sin hallazgos",
                    status=Status.PASS,
                )
            )
    for test in _split_list(values.get("tests_skipped", "")):
        if test not in with_issues:
            findings.append(
                RawFinding(
                    tool=Tool.LYNIS,
                    host=host,
                    check_id=test,
                    title=f"Prueba {test} omitida (no aplica al sistema)",
                    status=Status.NOTAPPLICABLE,
                )
            )

    scores = []
    if values.get("hardening_index", "").isdigit():
        scores.append(Score(host=host, value=float(values["hardening_index"]), maximum=100.0))
    return ParsedReport(
        tool=Tool.LYNIS,
        tool_version=values["lynis_version"],
        scores=scores,
        raw=[artifact(path, run_dir)],
        findings=findings,
    )
