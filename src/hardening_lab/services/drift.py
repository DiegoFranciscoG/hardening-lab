"""Detección de deriva de configuración (regla R6, NIST SP 800-128): compara contra la línea base aprobada."""

from __future__ import annotations

from datetime import UTC, datetime

from hardening_lab.domain import (
    Baseline,
    ControlResult,
    DriftChange,
    DriftReport,
    DriftTask,
    DriftVerdict,
    Finding,
    Phase,
    Run,
    Status,
    Tool,
)
from hardening_lab.errors import BaselineMissingError
from hardening_lab.services.storage import ReportStore

DRIFT_EXIT_CODE = 3
_GOOD = {Status.PASS, Status.EXCEPTION}


def compare(
    baseline_run_id: str,
    before: list[ControlResult],
    current_run_id: str,
    after: list[ControlResult],
    check_findings: list[Finding],
    now: datetime | None = None,
) -> DriftReport:
    previous = {(r.host, r.control_id): r.status for r in before}
    current = {(r.host, r.control_id): r.status for r in after}

    regressions: list[DriftChange] = []
    improvements: list[DriftChange] = []
    for key in sorted(previous.keys() & current.keys()):
        old, new = previous[key], current[key]
        change = DriftChange(host=key[0], control_id=key[1], before=old, after=new)
        if old in _GOOD and new is Status.FAIL:
            regressions.append(change)
        elif old is Status.FAIL and new in _GOOD:
            improvements.append(change)
    new_checks = [
        DriftChange(host=h, control_id=c, before=None, after=current[(h, c)])
        for h, c in sorted(current.keys() - previous.keys())
    ]
    missing_checks = [
        DriftChange(host=h, control_id=c, before=previous[(h, c)], after=None)
        for h, c in sorted(previous.keys() - current.keys())
    ]

    changed: dict[tuple[str, str], set[str]] = {}
    for finding in check_findings:
        if finding.tool is Tool.ANSIBLE_CHECK and finding.status is Status.FAIL:
            changed.setdefault((finding.host, finding.check_id), set()).add(finding.item)
    tasks = [DriftTask(host=host, task=task, control_ids=sorted(ids)) for (host, task), ids in sorted(changed.items())]
    verdict = DriftVerdict.DRIFT if regressions or tasks else DriftVerdict.NO_DRIFT
    return DriftReport(
        baseline_run_id=baseline_run_id,
        current_run_id=current_run_id,
        generated_at=now or datetime.now(UTC).replace(microsecond=0),
        regressions=regressions,
        improvements=improvements,
        new_checks=new_checks,
        missing_checks=missing_checks,
        ansible_changed_tasks=tasks,
        verdict=verdict,
    )


def latest_run(store: ReportStore, phases: set[Phase]) -> Run | None:
    candidates = [run for run in store.list_runs() if run.phase in phases]
    return candidates[-1] if candidates else None


def approve_baseline(store: ReportStore, run_id: str | None, approved_by: str) -> Baseline:
    run = store.read_run(run_id) if run_id else latest_run(store, {Phase.HARDENED})
    if run is None:
        raise BaselineMissingError("No hay una auditoría endurecida que aprobar como línea base")
    if run.phase is not Phase.HARDENED:
        raise BaselineMissingError(f"{run.run_id} no es una auditoría endurecida")
    baseline = Baseline(
        run_id=run.run_id, approved_at=datetime.now(UTC).replace(microsecond=0), approved_by=approved_by
    )
    store.write_baseline(baseline)
    return baseline


def detect(store: ReportStore, run_id: str | None = None) -> DriftReport:
    baseline = store.read_baseline()
    current = store.read_run(run_id) if run_id else latest_run(store, {Phase.DRIFT, Phase.SCHEDULED})
    if current is None:
        raise BaselineMissingError("No hay una re-auditoría (fase drift o scheduled) para comparar")
    check_findings: list[Finding] = []
    reports = store.read_tool_reports(current.run_id)
    if Tool.ANSIBLE_CHECK in reports:
        check_findings = reports[Tool.ANSIBLE_CHECK].findings
    report = compare(
        baseline.run_id,
        store.read_controls(baseline.run_id),
        current.run_id,
        store.read_controls(current.run_id),
        check_findings,
        now=current.finished_at,
    )
    store.write_model(store.run_dir(current.run_id) / "drift.json", report)
    return report
