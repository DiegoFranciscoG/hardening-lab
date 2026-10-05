from __future__ import annotations

from datetime import UTC, date, datetime

from hardening_lab.config import ExceptionRegistry, LabConfig
from hardening_lab.domain import EvidenceRef, Method, Severity, Status, Tool
from hardening_lab.services.mapping import (
    MappingContext,
    build_findings,
    controls_for,
    evaluate_controls,
    finding_id,
)
from tests.conftest import exception, raw

RUN_ID = "20261005T120000Z-hardened"


def _ctx(
    lab_config: LabConfig, exceptions: ExceptionRegistry | None = None, today: date | None = None
) -> MappingContext:
    evidence = {
        ("lab-web", "sshd_effective"): EvidenceRef(
            path="evidence/lab-web/sshd_effective.txt", sha256="a" * 64, method=Method.EXAMINE
        )
    }
    return MappingContext(
        run_id=RUN_ID,
        observed_at=datetime(2026, 10, 5, 12, tzinfo=UTC),
        today=today or date(2026, 10, 5),
        inventory=lab_config.inventory,
        catalog=lab_config.catalog,
        exceptions=exceptions if exceptions is not None else ExceptionRegistry(exceptions=[]),
        evidence=evidence,
    )


def _result(results: list, host: str, control_id: str):  # type: ignore[no-untyped-def]
    return next(r for r in results if r.host == host and r.control_id == control_id)


def test_cis_reference_pulls_every_ssg_rule_citing_it(lab_config: LabConfig) -> None:
    finding = raw(Tool.OPENSCAP, "lab-web", "sshd_disable_root_login", Status.FAIL, refs=["5.1.20"])
    assert controls_for(finding, lab_config.catalog) == ["HL-SSH-001"]


def test_worst_status_wins_and_evidence_is_attached(lab_config: LabConfig) -> None:
    findings = [
        raw(Tool.OPENSCAP, "lab-web", "sshd_disable_root_login", Status.PASS, refs=["5.1.20"]),
        raw(Tool.LAB_PROBE, "lab-web", "assert:HL-SSH-001:1", Status.FAIL, control_hint="HL-SSH-001"),
    ]
    result = _result(evaluate_controls(findings, _ctx(lab_config)), "lab-web", "HL-SSH-001")
    assert result.status is Status.FAIL
    assert result.sources == ["lab-probe:assert:HL-SSH-001:1"]
    assert result.evidence[0].path.endswith("sshd_effective.txt")
    assert result.severity is Severity.HIGH


def test_control_without_sources_is_not_checked(lab_config: LabConfig) -> None:
    result = _result(evaluate_controls([], _ctx(lab_config)), "lab-db", "HL-DB-001")
    assert result.status is Status.NOTCHECKED


def test_controls_only_apply_to_their_roles(lab_config: LabConfig) -> None:
    results = evaluate_controls([], _ctx(lab_config))
    assert not [r for r in results if r.control_id == "HL-WEB-001" and r.host != "lab-web"]


def test_lynis_detail_match_is_required(lab_config: LabConfig) -> None:
    other_detail = raw(
        Tool.LYNIS,
        "lab-web",
        "SSH-7408",
        Status.FAIL,
        title="Consider hardening SSH",
        details="Port (set 22 to )",
    )
    matching = raw(
        Tool.LYNIS,
        "lab-web",
        "SSH-7408",
        Status.FAIL,
        title="Consider hardening SSH",
        details="PermitRootLogin (set YES to NO)",
        item="x",
    )
    passed = _result(evaluate_controls([other_detail], _ctx(lab_config)), "lab-web", "HL-SSH-001")
    failed = _result(evaluate_controls([other_detail, matching], _ctx(lab_config)), "lab-web", "HL-SSH-001")
    assert passed.status is Status.PASS
    assert passed.sources == ["lynis:SSH-7408"]
    assert failed.status is Status.FAIL


def test_active_exception_turns_fail_into_exception(lab_config: LabConfig) -> None:
    registry = ExceptionRegistry(exceptions=[exception()])
    findings = [raw(Tool.LAB_PROBE, "lab-web", "assert:HL-SSH-001:1", Status.FAIL, control_hint="HL-SSH-001")]
    results = evaluate_controls(findings, _ctx(lab_config, registry))
    web = _result(results, "lab-web", "HL-SSH-001")
    assert web.status is Status.EXCEPTION
    assert web.exception_id == "EXC-900"
    assert web.sources == ["lab-probe:assert:HL-SSH-001:1"]
    mapped = build_findings(findings, _ctx(lab_config, registry))
    assert mapped[0].status is Status.EXCEPTION


def test_expired_exception_no_longer_covers(lab_config: LabConfig) -> None:
    registry = ExceptionRegistry(exceptions=[exception()])
    findings = [raw(Tool.LAB_PROBE, "lab-web", "assert:HL-SSH-001:1", Status.FAIL, control_hint="HL-SSH-001")]
    results = evaluate_controls(findings, _ctx(lab_config, registry, today=date(2027, 2, 1)))
    assert _result(results, "lab-web", "HL-SSH-001").status is Status.FAIL


def test_findings_take_control_severity_or_defaults(lab_config: LabConfig) -> None:
    mapped = build_findings(
        [
            raw(
                Tool.OPENSCAP,
                "lab-web",
                "sshd_disable_root_login",
                Status.FAIL,
                refs=["5.1.20"],
                severity=Severity.LOW,
            ),
            raw(Tool.DOCKER_BENCH, "lab-web", "9.9", Status.FAIL),
            raw(Tool.TRIVY, "lab-web", "DS-9999", Status.PASS, severity=Severity.LOW),
        ],
        _ctx(lab_config),
    )
    by_check = {f.check_id: f for f in mapped}
    assert by_check["sshd_disable_root_login"].severity is Severity.HIGH
    assert by_check["9.9"].severity is Severity.MEDIUM
    assert by_check["9.9"].control_id is None
    assert by_check["DS-9999"].severity is Severity.LOW


def test_finding_id_is_deterministic_and_deduplicated(lab_config: LabConfig) -> None:
    finding = raw(Tool.TRIVY, "lab-web", "HLC-002", Status.FAIL, item="compose")
    assert finding_id(RUN_ID, finding) == finding_id(RUN_ID, finding)
    assert len(build_findings([finding, finding], _ctx(lab_config))) == 1


def test_exception_also_covers_rules_that_cannot_be_evaluated(lab_config: LabConfig) -> None:
    registry = ExceptionRegistry(exceptions=[exception()])
    findings = [raw(Tool.OPENSCAP, "lab-web", "sshd_disable_root_login", Status.ERROR, refs=["5.1.20"])]
    web = _result(evaluate_controls(findings, _ctx(lab_config, registry)), "lab-web", "HL-SSH-001")
    assert web.status is Status.EXCEPTION
    assert web.sources == ["openscap:sshd_disable_root_login"]


def test_ansible_check_does_not_decide_control_status(lab_config: LabConfig) -> None:
    findings = [
        raw(Tool.OPENSCAP, "lab-web", "sshd_disable_root_login", Status.PASS, refs=["5.1.20"]),
        raw(Tool.ANSIBLE_CHECK, "lab-web", "ssh : HL-SSH-001 | Deploy", Status.FAIL, control_hint="HL-SSH-001"),
    ]
    assert _result(evaluate_controls(findings, _ctx(lab_config)), "lab-web", "HL-SSH-001").status is Status.PASS
    assert build_findings(findings, _ctx(lab_config))[1].control_id == "HL-SSH-001"
