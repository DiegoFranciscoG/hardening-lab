"""Parsers contra salidas reales recortadas del laboratorio (tests/fixtures/run)."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from hardening_lab.domain import Severity, Status, Tool
from hardening_lab.errors import ParseError
from hardening_lab.parsers import ansible_check, docker_bench, lynis, openscap, probes, trivy
from tests.conftest import FIXTURES

RUN = FIXTURES / "run"
HOSTS = ["lab-bastion", "lab-db", "lab-web"]


def test_lynis_report_findings_and_score() -> None:
    report = lynis.parse(RUN / "raw" / "lynis" / "lab-web.dat", RUN)
    assert report.tool is Tool.LYNIS
    assert report.tool_version == "3.1.7"
    assert report.scores[0].host == "lab-web"
    assert 0 < report.scores[0].value <= 100
    by_check: dict[str, list[Status]] = {}
    for finding in report.findings:
        by_check.setdefault(finding.check_id, []).append(finding.status)
    assert Status.FAIL in by_check["SSH-7408"]
    assert Status.PASS not in by_check["SSH-7408"], "una prueba con hallazgos no genera además un pass"
    assert by_check["KRNL-6000"] == [Status.PASS]
    warnings = [f for f in report.findings if f.severity is Severity.MEDIUM]
    assert all(f.item.startswith("warning:") for f in warnings)
    assert report.raw[0].path == "raw/lynis/lab-web.dat"


def test_lynis_rejects_foreign_files(tmp_path: Path) -> None:
    path = tmp_path / "x.dat"
    path.write_text("hola=mundo\n", encoding="utf-8")
    with pytest.raises(ParseError):
        lynis.parse(path, tmp_path)


def test_lynis_report_text_arrays() -> None:
    values, arrays = lynis.parse_report_text("# c\na=1\nb[]=x\nb[]=y\nnoequal\n")
    assert values == {"a": "1"}
    assert arrays["b"] == ["x", "y"]


def test_openscap_results_with_cis_references() -> None:
    report = openscap.parse(RUN / "raw" / "openscap" / "lab-web.xml.gz", RUN)
    by_rule = {f.check_id: f for f in report.findings}
    root_login = by_rule["sshd_disable_root_login"]
    assert root_login.status is Status.FAIL
    assert "5.1.20" in root_login.refs
    assert root_login.host == "lab-web"
    assert by_rule["package_telnet_removed"].status is Status.FAIL
    assert report.scores and report.scores[0].maximum == 100.0
    assert "SSG 0.1.82" in report.tool_version


def test_openscap_plain_xml_and_errors(tmp_path: Path) -> None:
    plain = tmp_path / "r.xml"
    plain.write_bytes(gzip.decompress((RUN / "raw" / "openscap" / "lab-web.xml.gz").read_bytes()))
    assert openscap.parse(plain, tmp_path).findings
    broken = tmp_path / "broken.xml"
    broken.write_text("<no", encoding="utf-8")
    with pytest.raises(ParseError):
        openscap.parse(broken, tmp_path)
    empty = tmp_path / "empty.xml"
    empty.write_text('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"/>', encoding="utf-8")
    with pytest.raises(ParseError, match="TestResult"):
        openscap.parse(empty, tmp_path)


def test_openscap_rejects_entity_expansion(tmp_path: Path) -> None:
    bomb = tmp_path / "bomb.xml"
    bomb.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>', encoding="utf-8")
    with pytest.raises(Exception, match=r"(?i)entit"):
        openscap.parse(bomb, tmp_path)


def test_docker_bench_expands_items_to_hosts() -> None:
    report = docker_bench.parse(RUN / "raw" / "docker-bench" / "docker-bench.json", RUN, HOSTS)
    user_check = [f for f in report.findings if f.check_id == "4.1"]
    assert {f.host for f in user_check} == set(HOSTS)
    assert all(f.status is Status.FAIL for f in user_check)
    ports = {f.host: f.status for f in report.findings if f.check_id == "5.9"}
    assert set(ports) == set(HOSTS)
    note = [f for f in report.findings if f.check_id == "4.2"]
    assert note and all(f.status is Status.NOTCHECKED for f in note)
    assert report.scores[0].host == "lab"


def test_docker_bench_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ParseError):
        docker_bench.parse(path, tmp_path, HOSTS)


def test_trivy_attributes_compose_findings_to_services() -> None:
    report = trivy.parse(RUN / "raw" / "trivy" / "lab.json", RUN, HOSTS, "0.75.0")
    compose = [f for f in report.findings if f.item == "compose/compose.effective.yaml"]
    db_port = [f for f in compose if f.check_id == "HLC-007"]
    assert {(f.host, f.status) for f in db_port} == {
        ("lab-db", Status.FAIL),
        ("lab-web", Status.PASS),
        ("lab-bastion", Status.PASS),
    }
    tooling = {f.host for f in report.findings if f.item == "images/controller/Dockerfile"}
    assert tooling == {"controller"}
    node_user = [f for f in report.findings if f.check_id == "DS-0002" and f.item == "images/node/Dockerfile"]
    assert {f.host for f in node_user} == set(HOSTS)
    assert report.tool_version == "0.75.0"


def test_trivy_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ParseError):
        trivy.parse(path, tmp_path, HOSTS)


def test_probes_flow_results_and_versions() -> None:
    report, facts = probes.parse(sorted((RUN / "raw" / "facts").glob("*.json")), RUN)
    flows = {f.check_id: f for f in report.findings}
    blocked_expected = flows["flow:lab-bastion->lab-db:5432"]
    assert blocked_expected.control_hint == "HL-FW-003"
    assert blocked_expected.status is Status.FAIL, "en el baseline la red es plana: el flujo está abierto"
    assert flows["flow:lab-web->lab-db:5432"].status is Status.PASS
    web = next(f for f in facts if f.host == "lab-web")
    assert web.versions["openssh-server"].startswith("1:9.6p1")
    assert web.lab_state == "baseline"


def test_probes_reject_mismatched_lists(tmp_path: Path) -> None:
    path = tmp_path / "lab-web.json"
    path.write_text(json.dumps({"host": "lab-web", "flow_tests": [{}], "flow_rcs": []}), encoding="utf-8")
    with pytest.raises(ParseError, match="largo"):
        probes.parse([path], tmp_path)


def test_ansible_check_maps_task_names_to_controls(tmp_path: Path) -> None:
    report = ansible_check.parse(RUN / "raw" / "ansible-check" / "harden-check.json", RUN, "2.21.4")
    assert report.findings
    assert all(f.control_hint and f.control_hint.startswith("HL-") for f in report.findings)
    login_defs = [f for f in report.findings if "login.defs" in f.check_id]
    assert {f.control_hint for f in login_defs} == {"HL-ACC-001", "HL-ACC-002", "HL-ACC-005"}
    assert any(f.status is Status.FAIL for f in report.findings), "el baseline difiere del estado deseado"


def test_ansible_check_statuses(tmp_path: Path) -> None:
    document = {
        "plays": [
            {
                "tasks": [
                    {"task": {"name": "ssh : HL-SSH-001 | A"}, "hosts": {"h": {"changed": False}}},
                    {"task": {"name": "HL-SSH-002 | B"}, "hosts": {"h": {"changed": True}}},
                    {"task": {"name": "HL-SSH-003 | C"}, "hosts": {"h": {"skipped": True, "skip_reason": "no"}}},
                    {
                        "task": {"name": "HL-SSH-004 | D"},
                        "hosts": {"h": {"skipped": True, "msg": "Command would have run if not in check mode"}},
                    },
                    {"task": {"name": "HL-SSH-005 | E"}, "hosts": {"h": {"failed": True}}},
                    {"task": {"name": "Gathering Facts"}, "hosts": {"h": {}}},
                ]
            }
        ]
    }
    path = tmp_path / "check.json"
    path.write_text("WARNING antes del JSON\n" + json.dumps(document), encoding="utf-8")
    statuses = {f.control_hint: f.status for f in ansible_check.parse(path, tmp_path).findings}
    assert statuses == {
        "HL-SSH-001": Status.PASS,
        "HL-SSH-002": Status.FAIL,
        "HL-SSH-003": Status.NOTAPPLICABLE,
        "HL-SSH-004": Status.FAIL,
        "HL-SSH-005": Status.ERROR,
    }


def test_ansible_check_without_json(tmp_path: Path) -> None:
    path = tmp_path / "x.json"
    path.write_text("sin json", encoding="utf-8")
    with pytest.raises(ParseError):
        ansible_check.parse(path, tmp_path)
