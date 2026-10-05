"""Parser de resultados XCCDF 1.2 de `oscap xccdf eval --results` (opcionalmente comprimidos con gzip)."""

from __future__ import annotations

import gzip
from pathlib import Path
from xml.etree.ElementTree import Element  # solo para tipos; el parseo usa defusedxml

from defusedxml import ElementTree as SafeET

from hardening_lab.domain import ParsedReport, RawFinding, Score, Severity, Status, Tool
from hardening_lab.errors import ParseError
from hardening_lab.parsers import artifact

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"
_NS = {"x": XCCDF_NS}
RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
CIS_UBUNTU_HREF = "cisecurity.org/benchmark/ubuntu_linux"

_STATUS = {
    "pass": Status.PASS,
    "fixed": Status.PASS,
    "fail": Status.FAIL,
    "notapplicable": Status.NOTAPPLICABLE,
    "notchecked": Status.NOTCHECKED,
    "informational": Status.INFO,
    "error": Status.ERROR,
    "unknown": Status.ERROR,
}
_SEVERITY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "unknown": Severity.INFO,
    "info": Severity.INFO,
}


def _read(path: Path) -> bytes:
    data = path.read_bytes()
    return gzip.decompress(data) if path.suffix == ".gz" else data


def _rule_index(root: Element) -> dict[str, tuple[str, list[str]]]:
    index: dict[str, tuple[str, list[str]]] = {}
    for rule in root.iter(f"{{{XCCDF_NS}}}Rule"):
        rule_id = rule.get("id", "")
        title_el = rule.find("x:title", _NS)
        cis = [
            (ref.text or "").strip()
            for ref in rule.findall("x:reference", _NS)
            if CIS_UBUNTU_HREF in (ref.get("href") or "")
        ]
        index[rule_id] = ((title_el.text or "").strip() if title_el is not None else rule_id, cis)
    return index


def parse(path: Path, run_dir: Path) -> ParsedReport:
    try:
        root = SafeET.fromstring(_read(path))
    except (OSError, SafeET.ParseError) as exc:
        raise ParseError(f"No se pudo leer el XML de OpenSCAP {path}: {exc}") from exc
    result = root.find(".//x:TestResult", _NS)
    if result is None:
        raise ParseError(f"{path} no contiene TestResult de XCCDF")
    target = result.find("x:target", _NS)
    host = (target.text or "").strip() if target is not None else path.name.split(".")[0]
    scanner = (result.get("test-system") or "openscap").rsplit(":", 1)[-1]
    content_version = result.get("version", "desconocida")

    rules = _rule_index(root)
    findings: list[RawFinding] = []
    for rule_result in result.findall("x:rule-result", _NS):
        outcome_el = rule_result.find("x:result", _NS)
        outcome = (outcome_el.text or "").strip() if outcome_el is not None else "unknown"
        if outcome == "notselected":
            continue
        idref = rule_result.get("idref", "")
        title, cis_refs = rules.get(idref, (idref, []))
        findings.append(
            RawFinding(
                tool=Tool.OPENSCAP,
                host=host,
                check_id=idref.removeprefix(RULE_PREFIX),
                title=title,
                status=_STATUS.get(outcome, Status.ERROR),
                severity=_SEVERITY.get(rule_result.get("severity", "unknown"), Severity.INFO),
                details=f"resultado XCCDF: {outcome}",
                refs=cis_refs,
            )
        )

    scores = []
    score_el = result.find("x:score", _NS)
    if score_el is not None and score_el.text:
        maximum = score_el.get("maximum")
        scores.append(Score(host=host, value=float(score_el.text), maximum=float(maximum) if maximum else None))
    return ParsedReport(
        tool=Tool.OPENSCAP,
        tool_version=f"{scanner} (SSG {content_version})",
        scores=scores,
        raw=[artifact(path, run_dir)],
        findings=findings,
    )
