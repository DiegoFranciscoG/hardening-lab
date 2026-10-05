from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from hardening_lab.domain import ControlRef, ExceptionStatus, Framework, Run, Severity, Status
from tests.conftest import exception


def test_status_weight_makes_fail_the_worst() -> None:
    ordered = sorted(Status, key=lambda s: s.weight, reverse=True)
    assert ordered[0] is Status.FAIL
    assert ordered[-1] is Status.NOTAPPLICABLE


def test_severity_rank_order() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank


def test_exception_requires_review_after_approval() -> None:
    with pytest.raises(ValidationError, match="posterior"):
        exception(review_by=date(2026, 9, 1))


def test_exception_review_window_is_capped() -> None:
    with pytest.raises(ValidationError, match="180"):
        exception(review_by=date(2027, 6, 1))


def test_exception_needs_compensation_unless_not_applicable() -> None:
    with pytest.raises(ValidationError, match="compensatorio"):
        exception(compensating_controls=[])
    assert exception(category="not_applicable_container", compensating_controls=[]).compensating_controls == []


def test_exception_scope_cannot_be_empty() -> None:
    with pytest.raises(ValidationError, match="acotar"):
        exception(scope={})


def test_exception_expires_and_stops_covering() -> None:
    exc = exception()
    assert exc.effective_status(date(2026, 12, 31)) is ExceptionStatus.ACTIVE
    assert exc.effective_status(date(2027, 1, 1)) is ExceptionStatus.EXPIRED
    assert exc.covers("HL-SSH-001", "lab-web", "web", date(2026, 11, 1))
    assert not exc.covers("HL-SSH-001", "lab-web", "web", date(2027, 1, 2))


def test_exception_scope_by_host_or_role() -> None:
    by_host = exception(scope={"hosts": ["lab-db"]})
    today = date(2026, 10, 2)
    assert by_host.covers("HL-SSH-001", "lab-db", None, today)
    assert not by_host.covers("HL-SSH-001", "lab-web", "web", today)
    assert not by_host.covers("HL-SSH-002", "lab-db", "db", today)


def test_revoked_exception_never_covers() -> None:
    assert not exception(status="revoked").covers("HL-SSH-001", "lab-web", "web", date(2026, 10, 2))


def test_control_ref_rejects_invalid_regex() -> None:
    with pytest.raises(ValidationError):
        ControlRef(framework=Framework.LYNIS, ref_id="SSH-7408", match="(")


def _run(**overrides: Any) -> Run:
    data: dict[str, Any] = {
        "run_id": "20261005T120000Z-hardened",
        "phase": "hardened",
        "lab_state": "hardened",
        "started_at": datetime(2026, 10, 5, 12, 0, tzinfo=UTC),
        "finished_at": datetime(2026, 10, 5, 12, 5, tzinfo=UTC),
        "git_sha": "abc",
        "git_dirty": False,
        "inventory_sha256": "0" * 64,
        "hosts": ["lab-web"],
        "tools": [],
        "benchmarks": [],
        "status": "completed",
    }
    data.update(overrides)
    return Run.model_validate(data)


def test_run_rejects_inverted_chronology() -> None:
    with pytest.raises(ValidationError, match="finished_at"):
        _run(finished_at=datetime(2026, 10, 5, 11, 0, tzinfo=UTC))


def test_run_id_must_match_phase() -> None:
    with pytest.raises(ValidationError, match="fase"):
        _run(phase="baseline")


def test_run_id_pattern() -> None:
    with pytest.raises(ValidationError):
        _run(run_id="2026-10-05-hardened")
