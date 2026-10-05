"""Mapeo de hallazgos crudos al catálogo de controles, aplicación de excepciones y evidencia (reglas R1–R3)."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime

from hardening_lab.config import Catalog, ExceptionRegistry, Inventory
from hardening_lab.domain import (
    Control,
    ControlRef,
    ControlResult,
    EvidenceRef,
    Finding,
    Framework,
    RawFinding,
    Severity,
    Status,
    Tool,
)

_DEFAULT_SEVERITY = {Status.FAIL: Severity.MEDIUM}
_COVERABLE = {Status.FAIL, Status.ERROR}
"""Estados que una excepción aprobada puede cubrir: fallos y reglas que no pueden evaluarse en el contenedor."""
"""Hallazgos sin severidad nativa ni control asociado (supuesto S3 de docs/investigacion.md)."""


@dataclass(frozen=True)
class MappingContext:
    run_id: str
    observed_at: datetime
    today: date
    inventory: Inventory
    catalog: Catalog
    exceptions: ExceptionRegistry
    evidence: dict[tuple[str, str], EvidenceRef]


def finding_id(run_id: str, raw: RawFinding) -> str:
    key = "|".join((run_id, raw.tool.value, raw.host, raw.check_id, raw.item))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _ref_matches(ref: ControlRef, raw: RawFinding) -> bool:
    if ref.framework is Framework.CIS_UBUNTU2404_V1:
        return raw.tool is Tool.OPENSCAP and ref.ref_id in raw.refs
    if ref.framework is Framework.SSG:
        return raw.tool is Tool.OPENSCAP and raw.check_id == ref.ref_id
    if ref.framework is Framework.LYNIS:
        if raw.tool is not Tool.LYNIS or raw.check_id != ref.ref_id:
            return False
        if ref.match is None or raw.status is not Status.FAIL:
            return True
        return re.search(ref.match, f"{raw.title} {raw.details}", re.IGNORECASE) is not None
    if ref.framework in (Framework.DOCKER_BENCH, Framework.CIS_DOCKER_V1_6):
        return raw.tool is Tool.DOCKER_BENCH and raw.check_id == ref.ref_id
    if ref.framework is Framework.TRIVY:
        return raw.tool is Tool.TRIVY and raw.check_id == ref.ref_id
    return False


def controls_for(raw: RawFinding, catalog: Catalog) -> list[str]:
    """Controles a los que aporta un hallazgo (orden estable)."""
    matched = {
        control.control_id
        for control in catalog
        if raw.control_hint == control.control_id or any(_ref_matches(ref, raw) for ref in control.refs)
    }
    return sorted(matched)


def _lynis_unmatched_pass(control: Control, host_findings: list[RawFinding]) -> list[str]:
    """Una prueba Lynis con hallazgos, pero ninguno del detalle que pide el control, cuenta como pass."""
    sources: list[str] = []
    for ref in control.refs:
        if ref.framework is not Framework.LYNIS or ref.match is None:
            continue
        executed = [f for f in host_findings if f.tool is Tool.LYNIS and f.check_id == ref.ref_id]
        if executed and not any(_ref_matches(ref, f) and f.status is Status.FAIL for f in executed):
            sources.append(f"lynis:{ref.ref_id}")
    return sources


def _aggregate(statuses: Iterable[Status]) -> Status:
    collected = list(statuses)
    if not collected:
        return Status.NOTCHECKED
    return max(collected, key=lambda status: status.weight)


def evaluate_controls(raw_findings: list[RawFinding], ctx: MappingContext) -> list[ControlResult]:
    # El estado de un control lo deciden los auditores (Lynis, OpenSCAP, docker-bench, Trivy y las sondas). El modo
    # check de Ansible es la propia herramienta de remediación: se reporta aparte como deriva respecto del código.
    by_host: dict[str, list[RawFinding]] = defaultdict(list)
    for raw in raw_findings:
        if raw.tool is not Tool.ANSIBLE_CHECK:
            by_host[raw.host].append(raw)

    results: list[ControlResult] = []
    for host_name, host in sorted(ctx.inventory.hosts.items()):
        host_findings = by_host.get(host_name, [])
        for control in ctx.catalog:
            if host.role not in control.applies_to:
                continue
            contributing = [
                raw
                for raw in host_findings
                if raw.control_hint == control.control_id or any(_ref_matches(r, raw) for r in control.refs)
            ]
            statuses = [raw.status for raw in contributing if not _is_lynis_noise(raw, control)]
            extra_pass = _lynis_unmatched_pass(control, host_findings)
            statuses += [Status.PASS] * len(extra_pass)
            status = _aggregate(statuses)
            exception_id = None
            if status in _COVERABLE:
                exception = ctx.exceptions.find(control.control_id, host_name, host.role.value, ctx.today)
                if exception is not None:
                    status, exception_id = Status.EXCEPTION, exception.exception_id
            # Fuentes que determinaron el estado final (para una excepción, las que fallaron o no se pudieron evaluar).
            decisive = _COVERABLE if status is Status.EXCEPTION else {status}
            sources = sorted(
                {f"{raw.tool.value}:{raw.check_id}" for raw in contributing if raw.status in decisive}
                | (set(extra_pass) if Status.PASS in decisive else set())
            )
            evidence = [
                ctx.evidence[(host_name, probe)] for probe in control.evidence if (host_name, probe) in ctx.evidence
            ]
            results.append(
                ControlResult(
                    host=host_name,
                    control_id=control.control_id,
                    status=status,
                    severity=control.severity,
                    exception_id=exception_id,
                    sources=sources[:25],
                    evidence=evidence,
                )
            )
    return results


def _is_lynis_noise(raw: RawFinding, control: Control) -> bool:
    """Un pass genérico de Lynis no cuenta si el control exige un detalle concreto de esa prueba."""
    if raw.tool is not Tool.LYNIS or raw.status is not Status.PASS:
        return False
    return any(r.framework is Framework.LYNIS and r.ref_id == raw.check_id and r.match for r in control.refs)


def build_findings(raw_findings: list[RawFinding], ctx: MappingContext) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for raw in raw_findings:
        fid = finding_id(ctx.run_id, raw)
        if fid in findings:
            continue
        control_ids = controls_for(raw, ctx.catalog)
        control = ctx.catalog.get(control_ids[0]) if control_ids else None
        severity = control.severity if control else (raw.severity or _DEFAULT_SEVERITY.get(raw.status, Severity.INFO))
        status, exception_id = raw.status, None
        if status in _COVERABLE and control is not None:
            role = ctx.inventory.role_of(raw.host)
            for control_id in control_ids:
                exception = ctx.exceptions.find(control_id, raw.host, role, ctx.today)
                if exception is not None:
                    status, exception_id = Status.EXCEPTION, exception.exception_id
                    break
        findings[fid] = Finding(
            finding_id=fid,
            run_id=ctx.run_id,
            host=raw.host,
            tool=raw.tool,
            check_id=raw.check_id,
            title=raw.title,
            control_id=control.control_id if control else None,
            status=status,
            severity=severity,
            exception_id=exception_id,
            details=raw.details,
            item=raw.item,
            observed_at=ctx.observed_at,
        )
    return list(findings.values())
