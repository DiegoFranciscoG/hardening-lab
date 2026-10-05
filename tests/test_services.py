"""Puntajes (R7), almacenamiento (R4, R5), aserciones sobre evidencia y deriva (R6)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from hardening_lab.config import LabConfig
from hardening_lab.domain import (
    Baseline,
    ControlResult,
    DriftVerdict,
    Finding,
    HistoryRow,
    Phase,
    Severity,
    Status,
    Tool,
)
from hardening_lab.errors import BaselineMissingError, StorageError
from hardening_lab.services import assertions
from hardening_lab.services.drift import compare
from hardening_lab.services.scoring import delta, tally
from hardening_lab.services.storage import HISTORY_COLUMNS, ReportStore


def test_compliance_formulas() -> None:
    t = tally(
        [
            (Status.PASS, Severity.HIGH),
            (Status.PASS, Severity.LOW),
            (Status.FAIL, Severity.HIGH),
            (Status.EXCEPTION, Severity.MEDIUM),
            (Status.NOTAPPLICABLE, Severity.LOW),
            (Status.ERROR, Severity.LOW),
        ]
    )
    assert t.strict_compliance == 0.5
    assert t.compliance_with_exceptions == 0.75
    assert t.failing_by_severity[Severity.HIGH] == 1
    assert t.get(Status.ERROR) == 1


def test_compliance_is_none_without_evaluable_items() -> None:
    t = tally([(Status.NOTAPPLICABLE, Severity.LOW)])
    assert t.strict_compliance is None
    assert t.compliance_with_exceptions is None
    assert delta(None, 1.0) is None
    assert delta(0.25, 0.75) == 0.5


def test_write_once_accepts_identical_content_and_rejects_changes(tmp_path: Path) -> None:
    store = ReportStore(tmp_path)
    target = tmp_path / "runs" / "x" / "file.txt"
    store.write_once(target, "a")
    store.write_once(target, "a")
    with pytest.raises(StorageError, match="solo escritura"):
        store.write_once(target, "b")
    store.write_once(target, "b", force=True)
    assert target.read_text(encoding="utf-8") == "b"


def _history(run_id: str = "20261005T120000Z-hardened", passed: int = 3) -> HistoryRow:
    return HistoryRow.model_validate(
        {
            "run_id": run_id,
            "finished_at": datetime(2026, 10, 5, 12, tzinfo=UTC),
            "phase": "hardened",
            "git_sha": "abc",
            "host": "lab-web",
            "role": "web",
            "tool": "catalog",
            "tool_version": "1",
            "native_score": None,
            "pass": passed,
            "fail": 1,
            "exception": 0,
            "notapplicable": 0,
            "notchecked": 0,
            "info": 0,
            "error": 0,
            "critical_fail": 0,
            "high_fail": 1,
            "medium_fail": 0,
            "low_fail": 0,
            "strict_compliance": 0.75,
            "compliance_with_exceptions": 0.75,
        }
    )


def test_history_is_append_only_and_idempotent(tmp_path: Path) -> None:
    store = ReportStore(tmp_path)
    assert store.append_history([_history()]) == 1
    assert store.append_history([_history()]) == 0
    with pytest.raises(StorageError, match="no se reescribe"):
        store.append_history([_history(passed=4)])
    rows = store.read_history()
    assert len(rows) == 1
    assert rows[0].passed == 3
    header = store.history_path.read_text(encoding="utf-8").splitlines()[0]
    assert header.split(",") == HISTORY_COLUMNS


def test_missing_baseline_is_reported(tmp_path: Path) -> None:
    with pytest.raises(BaselineMissingError):
        ReportStore(tmp_path).read_baseline()
    store = ReportStore(tmp_path)
    store.write_baseline(
        Baseline(
            run_id="20261005T120000Z-hardened",
            approved_at=datetime(2026, 10, 5, tzinfo=UTC),
            approved_by="rol",
        )
    )
    assert store.read_baseline().run_id == "20261005T120000Z-hardened"


def test_assertions_on_evidence(tmp_path: Path, lab_config: LabConfig) -> None:
    run_dir = tmp_path / "run"
    evidence = run_dir / "evidence" / "lab-web"
    evidence.mkdir(parents=True)
    (evidence / "sshd_effective.txt").write_text(
        "# host: lab-web\n# probe: sshd_effective\n# command: sshd -T\n# exit_code: 0\n"
        "permitrootlogin no\npasswordauthentication yes\n",
        encoding="utf-8",
    )
    findings = {
        f.check_id: f
        for f in assertions.evaluate(lab_config.catalog, lab_config.inventory, run_dir)
        if f.host == "lab-web"
    }
    assert findings["assert:HL-SSH-001:1"].status is Status.PASS
    assert findings["assert:HL-SSH-002:1"].status is Status.FAIL
    assert findings["assert:HL-WEB-001:1"].status is Status.NOTCHECKED
    assert all(f.control_hint for f in findings.values())


def _control(host: str, control_id: str, status: Status) -> ControlResult:
    return ControlResult(host=host, control_id=control_id, status=status, severity=Severity.HIGH)


def test_drift_detects_regressions_and_changed_tasks() -> None:
    before = [
        _control("lab-web", "HL-SSH-001", Status.PASS),
        _control("lab-db", "HL-FW-001", Status.EXCEPTION),
    ]
    after = [_control("lab-web", "HL-SSH-001", Status.FAIL), _control("lab-db", "HL-FW-001", Status.PASS)]
    changed = Finding(
        finding_id="b" * 64,
        run_id="20261005T130000Z-drift",
        host="lab-web",
        tool=Tool.ANSIBLE_CHECK,
        check_id="ssh : HL-SSH-001 | Deploy",
        title="Deploy",
        control_id="HL-SSH-001",
        status=Status.FAIL,
        severity=Severity.HIGH,
        item="HL-SSH-001",
        observed_at=datetime(2026, 10, 5, 13, tzinfo=UTC),
    )
    report = compare("20261005T120000Z-hardened", before, "20261005T130000Z-drift", after, [changed])
    assert report.verdict is DriftVerdict.DRIFT
    assert [(r.host, r.control_id) for r in report.regressions] == [("lab-web", "HL-SSH-001")]
    assert report.improvements == []
    assert report.ansible_changed_tasks[0].control_ids == ["HL-SSH-001"]


def test_no_drift_when_nothing_regresses() -> None:
    before = [_control("lab-web", "HL-SSH-001", Status.FAIL)]
    after = [_control("lab-web", "HL-SSH-001", Status.PASS), _control("lab-web", "HL-SSH-002", Status.PASS)]
    report = compare("a", before, "b", after, [])
    assert report.verdict is DriftVerdict.NO_DRIFT
    assert len(report.improvements) == 1
    assert len(report.new_checks) == 1
    assert Phase.DRIFT.value == "drift"
