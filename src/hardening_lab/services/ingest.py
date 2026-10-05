"""Ingesta de un run: lee las salidas crudas, normaliza, mapea al catálogo y escribe los informes del run."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from hardening_lab.config import Catalog, ExceptionRegistry, Inventory
from hardening_lab.domain import (
    Benchmark,
    ControlResult,
    ControlsReport,
    EvidenceRef,
    Finding,
    HistoryRow,
    Method,
    ParsedReport,
    Phase,
    RawFinding,
    Run,
    RunStatus,
    Severity,
    Status,
    Tool,
    ToolInfo,
    ToolReport,
)
from hardening_lab.parsers import ansible_check, docker_bench, lynis, openscap, probes, sha256_file, trivy
from hardening_lab.services import assertions
from hardening_lab.services.mapping import MappingContext, build_findings, evaluate_controls
from hardening_lab.services.scoring import tally
from hardening_lab.services.storage import ReportStore

EXPECTED_TOOLS = (Tool.LYNIS, Tool.OPENSCAP, Tool.DOCKER_BENCH, Tool.TRIVY, Tool.LAB_PROBE)


@dataclass
class IngestResult:
    run: Run
    findings: list[Finding]
    controls: list[ControlResult]
    history_rows_added: int
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RunContext:
    run_id: str
    phase: Phase
    git_sha: str
    git_dirty: bool
    started_at: datetime


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def context_from_env(run_dir: Path, phase: Phase) -> RunContext:
    started = _parse_time(os.environ.get("HLAB_STARTED_AT")) or datetime.now(UTC).replace(microsecond=0)
    return RunContext(
        run_id=run_dir.name,
        phase=phase,
        git_sha=os.environ.get("HLAB_GIT_SHA") or "unknown",
        git_dirty=os.environ.get("HLAB_GIT_DIRTY", "false").lower() == "true",
        started_at=started,
    )


def _evidence_index(run_dir: Path) -> dict[tuple[str, str], EvidenceRef]:
    index: dict[tuple[str, str], EvidenceRef] = {}
    for path in sorted((run_dir / "evidence").glob("*/*.txt")):
        index[(path.parent.name, path.stem)] = EvidenceRef(
            path=path.relative_to(run_dir).as_posix(), sha256=sha256_file(path), method=Method.EXAMINE
        )
    return index


def _tool_versions(run_dir: Path) -> dict[str, str]:
    path = run_dir / "raw" / "tools.json"
    if not path.exists():
        return {}
    data: dict[str, str] = json.loads(path.read_text(encoding="utf-8"))
    return data


def parse_raw(run_dir: Path, hosts: list[str]) -> tuple[list[ParsedReport], list[str], str]:
    """Devuelve los informes parseados, advertencias y el estado del laboratorio observado."""
    raw = run_dir / "raw"
    versions = _tool_versions(run_dir)
    reports: list[ParsedReport] = []
    warnings: list[str] = []

    def merge(tool: Tool, parts: list[ParsedReport]) -> None:
        if not parts:
            warnings.append(f"sin salida de {tool.value}")
            return
        merged = ParsedReport(tool=tool, tool_version=parts[0].tool_version)
        for part in parts:
            merged.scores.extend(part.scores)
            merged.raw.extend(part.raw)
            merged.findings.extend(part.findings)
        reports.append(merged)

    merge(Tool.LYNIS, [lynis.parse(p, run_dir) for p in sorted((raw / "lynis").glob("*.dat"))])
    merge(
        Tool.OPENSCAP,
        [openscap.parse(p, run_dir) for p in sorted((raw / "openscap").glob("*.xml*"))],
    )
    bench = raw / "docker-bench" / "docker-bench.json"
    merge(Tool.DOCKER_BENCH, [docker_bench.parse(bench, run_dir, hosts)] if bench.exists() else [])
    trivy_path = raw / "trivy" / "lab.json"
    merge(
        Tool.TRIVY,
        [trivy.parse(trivy_path, run_dir, hosts, versions.get("trivy", "desconocida"))] if trivy_path.exists() else [],
    )
    fact_files = sorted((raw / "facts").glob("*.json"))
    lab_state = "baseline"
    if fact_files:
        probe_report, facts = probes.parse(fact_files, run_dir)
        reports.append(probe_report)
        lab_state = facts[0].lab_state
    else:
        warnings.append("sin hechos ni pruebas de flujos")
    check_path = raw / "ansible-check" / "harden-check.json"
    if check_path.exists() and check_path.stat().st_size > 0:
        reports.append(ansible_check.parse(check_path, run_dir, versions.get("ansible-core", "desconocida")))
    return reports, warnings, lab_state


def _history_rows(
    run: Run,
    findings: list[Finding],
    controls: list[ControlResult],
    reports: list[ParsedReport],
    inventory: Inventory,
) -> list[HistoryRow]:
    versions = {report.tool.value: report.tool_version for report in reports}
    scores = {(report.tool.value, score.host): score.value for report in reports for score in report.scores}
    grouped: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[(finding.host, finding.tool.value)].append(finding)

    rows: list[HistoryRow] = []

    def row(host: str, tool: str, items: list[tuple[Status, Severity]]) -> HistoryRow:
        t = tally(items)
        role = inventory.role_of(host) or "tooling"
        return HistoryRow.model_validate(
            {
                "run_id": run.run_id,
                "finished_at": run.finished_at,
                "phase": run.phase,
                "git_sha": run.git_sha,
                "host": host,
                "role": role,
                "tool": tool,
                "tool_version": versions.get(tool, "catálogo hardening-lab"),
                "native_score": scores.get((tool, host)),
                "pass": t.get(Status.PASS),
                "fail": t.get(Status.FAIL),
                "exception": t.get(Status.EXCEPTION),
                "notapplicable": t.get(Status.NOTAPPLICABLE),
                "notchecked": t.get(Status.NOTCHECKED),
                "info": t.get(Status.INFO),
                "error": t.get(Status.ERROR),
                "critical_fail": t.failing_by_severity[Severity.CRITICAL],
                "high_fail": t.failing_by_severity[Severity.HIGH],
                "medium_fail": t.failing_by_severity[Severity.MEDIUM],
                "low_fail": t.failing_by_severity[Severity.LOW],
                "strict_compliance": t.strict_compliance,
                "compliance_with_exceptions": t.compliance_with_exceptions,
            }
        )

    for (host, tool), items in sorted(grouped.items()):
        rows.append(row(host, tool, [(f.status, f.severity) for f in items]))
    by_host: dict[str, list[ControlResult]] = defaultdict(list)
    for result in controls:
        by_host[result.host].append(result)
    for host, results in sorted(by_host.items()):
        rows.append(row(host, "catalog", [(r.status, r.severity) for r in results]))
    return rows


def ingest(
    run_dir: Path,
    phase: Phase,
    *,
    store: ReportStore,
    inventory: Inventory,
    catalog: Catalog,
    exceptions: ExceptionRegistry,
    context: RunContext | None = None,
    force: bool = False,
) -> IngestResult:
    ctx = context or context_from_env(run_dir, phase)
    existing = run_dir / "run.json"
    previous = Run.model_validate_json(existing.read_text(encoding="utf-8")) if existing.exists() else None
    started_at = previous.started_at if previous and not force else ctx.started_at
    finished_at = previous.finished_at if previous and not force else datetime.now(UTC).replace(microsecond=0)
    hosts = sorted(inventory.hosts)

    reports, warnings, lab_state = parse_raw(run_dir, hosts)
    assertion_findings = assertions.evaluate(catalog, inventory, run_dir)
    if assertion_findings:
        probe_report = next((r for r in reports if r.tool is Tool.LAB_PROBE), None)
        if probe_report is None:
            probe_report = ParsedReport(tool=Tool.LAB_PROBE, tool_version="aserciones del catálogo")
            reports.append(probe_report)
        probe_report.findings.extend(assertion_findings)
    raw_findings: list[RawFinding] = [f for report in reports for f in report.findings]
    mapping_ctx = MappingContext(
        run_id=ctx.run_id,
        observed_at=started_at,
        today=finished_at.date(),
        inventory=inventory,
        catalog=catalog,
        exceptions=exceptions,
        evidence=_evidence_index(run_dir),
    )
    findings = build_findings(raw_findings, mapping_ctx)
    controls = evaluate_controls(raw_findings, mapping_ctx)

    versions = _tool_versions(run_dir)
    present = {report.tool for report in reports}
    missing = [tool.value for tool in EXPECTED_TOOLS if tool not in present]
    run = Run(
        run_id=ctx.run_id,
        phase=phase,
        lab_state="hardened" if lab_state == "hardened" else "baseline",
        started_at=started_at,
        finished_at=finished_at,
        git_sha=previous.git_sha if previous and not force else ctx.git_sha,
        git_dirty=previous.git_dirty if previous and not force else ctx.git_dirty,
        inventory_sha256=inventory.sha256,
        hosts=hosts,
        tools=[
            ToolInfo(name=report.tool.value, version=report.tool_version, artifact_sha256=None) for report in reports
        ]
        + [
            ToolInfo(name=name, version=version, artifact_sha256=versions.get(f"{name}_sha256"))
            for name, version in sorted(versions.items())
            if not name.endswith("_sha256")
        ],
        benchmarks=[
            Benchmark(
                name="CIS Ubuntu Linux 24.04 LTS",
                version="1.0.0",
                via="SCAP Security Guide (perfil cis_level1_server)",
            ),
            Benchmark(name="CIS Docker", version="1.6.0", via="docker-bench-security"),
        ],
        status=RunStatus.COMPLETED if not missing else RunStatus.PARTIAL,
        errors=warnings,
    )

    by_tool: dict[Tool, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_tool[finding.tool].append(finding)
    for report in reports:
        tool_report = ToolReport(
            run_id=run.run_id,
            tool=report.tool,
            tool_version=report.tool_version,
            generated_at=finished_at,
            raw=report.raw,
            scores=report.scores,
            findings=sorted(by_tool[report.tool], key=lambda f: (f.host, f.check_id, f.finding_id)),
        )
        store.write_model(run_dir / "findings" / f"{report.tool.value}.json", tool_report, force=force, compact=True)
    store.write_model(
        run_dir / "controls.json",
        ControlsReport(run_id=run.run_id, generated_at=finished_at, results=controls),
        force=force,
    )
    store.write_summary(run, findings, controls, force=force)
    store.write_model(existing, run, force=force)
    added = store.append_history(_history_rows(run, findings, controls, reports, inventory))
    return IngestResult(run=run, findings=findings, controls=controls, history_rows_added=added, warnings=warnings)
