"""Integración: ingesta de un run real recortado, informe HTML y CLI de punta a punta (sin Docker)."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
from pathlib import Path

import pytest

from hardening_lab import cli
from hardening_lab.config import LabConfig
from hardening_lab.domain import Phase, RunStatus, Status
from hardening_lab.errors import StorageError
from hardening_lab.report.site import FILTER_SCRIPT, build_site
from hardening_lab.services.ingest import RunContext, ingest
from hardening_lab.services.storage import ReportStore
from tests.conftest import FIXTURES, REPO

BASELINE = "20261005T003027Z-baseline"
HARDENED = "20261005T013000Z-hardened"


def _context(run_id: str, phase: Phase) -> RunContext:
    from datetime import UTC, datetime

    return RunContext(
        run_id=run_id,
        phase=phase,
        git_sha="0" * 40,
        git_dirty=False,
        started_at=datetime(2026, 10, 5, 0, 30, tzinfo=UTC),
    )


def _copy_run(reports: Path, run_id: str) -> Path:
    target = reports / "runs" / run_id
    shutil.copytree(FIXTURES / "run", target)
    return target


@pytest.fixture
def ingested(tmp_path: Path, lab_config: LabConfig) -> ReportStore:
    store = ReportStore(tmp_path / "reports")
    for run_id, phase in ((BASELINE, Phase.BASELINE), (HARDENED, Phase.HARDENED)):
        run_dir = _copy_run(store.root, run_id)
        ingest(
            run_dir,
            phase,
            store=store,
            inventory=lab_config.inventory,
            catalog=lab_config.catalog,
            exceptions=lab_config.exceptions,
            context=_context(run_id, phase),
        )
    return store


def test_ingest_writes_every_artifact(ingested: ReportStore) -> None:
    run_dir = ingested.run_dir(BASELINE)
    run = ingested.read_run(BASELINE)
    assert run.status is RunStatus.COMPLETED
    assert run.lab_state == "baseline"
    assert {"lynis", "openscap", "docker-bench", "trivy", "lab-probe", "ansible-check"} <= {t.name for t in run.tools}
    assert any(b.version == "1.0.0" and "Ubuntu" in b.name for b in run.benchmarks)
    for name in ("lynis", "openscap", "docker-bench", "trivy", "lab-probe", "ansible-check"):
        assert (run_dir / "findings" / f"{name}.json").exists()
    header = (run_dir / "summary.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header.startswith("run_id,observed_at,phase,host,tool,check_id,control_id,status,severity")
    controls = ingested.read_controls(BASELINE)
    assert {c.host for c in controls} == {"lab-bastion", "lab-web", "lab-db"}
    assert any(c.status is Status.EXCEPTION for c in controls)
    root_login = next(c for c in controls if c.host == "lab-web" and c.control_id == "HL-SSH-001")
    assert root_login.status is Status.FAIL
    assert root_login.evidence and root_login.evidence[0].path == "evidence/lab-web/sshd_effective.txt"
    rows = [r for r in ingested.read_history() if r.run_id == BASELINE]
    assert {r.tool for r in rows} >= {"lynis", "openscap", "catalog"}


def test_reingest_is_reproducible(ingested: ReportStore, lab_config: LabConfig) -> None:
    run_dir = ingested.run_dir(BASELINE)
    before = (run_dir / "controls.json").read_text(encoding="utf-8")
    result = ingest(
        run_dir,
        Phase.BASELINE,
        store=ingested,
        inventory=lab_config.inventory,
        catalog=lab_config.catalog,
        exceptions=lab_config.exceptions,
        context=_context(BASELINE, Phase.BASELINE),
    )
    assert result.history_rows_added == 0
    assert (run_dir / "controls.json").read_text(encoding="utf-8") == before


def test_tampered_run_cannot_be_rewritten(ingested: ReportStore, lab_config: LabConfig) -> None:
    run_dir = ingested.run_dir(BASELINE)
    controls = run_dir / "controls.json"
    controls.write_text(controls.read_text(encoding="utf-8").replace('"fail"', '"pass"', 1), encoding="utf-8")
    with pytest.raises(StorageError):
        ingest(
            run_dir,
            Phase.BASELINE,
            store=ingested,
            inventory=lab_config.inventory,
            catalog=lab_config.catalog,
            exceptions=lab_config.exceptions,
            context=_context(BASELINE, Phase.BASELINE),
        )


def test_partial_run_is_flagged(tmp_path: Path, lab_config: LabConfig) -> None:
    store = ReportStore(tmp_path / "reports")
    run_dir = _copy_run(store.root, BASELINE)
    shutil.rmtree(run_dir / "raw" / "trivy")
    result = ingest(
        run_dir,
        Phase.BASELINE,
        store=store,
        inventory=lab_config.inventory,
        catalog=lab_config.catalog,
        exceptions=lab_config.exceptions,
        context=_context(BASELINE, Phase.BASELINE),
    )
    assert result.run.status is RunStatus.PARTIAL
    assert "sin salida de trivy" in result.warnings


def test_report_site(ingested: ReportStore, lab_config: LabConfig, tmp_path: Path) -> None:
    out = tmp_path / "site"
    images = tmp_path / "img"
    index = build_site(ingested, out, lab_config, images_dir=images)
    html = index.read_text(encoding="utf-8")
    for section in (
        "Antes y después",
        "Controles y evidencia por host",
        "Excepciones justificadas",
        "Deriva de configuración",
    ):
        assert section in html
    expected = "sha256-" + base64.b64encode(hashlib.sha256(FILTER_SCRIPT.encode()).digest()).decode()
    assert expected in html
    assert re.search(r"<title>[^<]*hardening-lab · .*?</title>", html, re.S), "los SVG traen tooltips"
    assert (out / "img" / "puntajes-antes-despues.png").exists()
    assert (images / "puntajes-antes-despues-dark.png").exists()
    assert (out / "evidence" / HARDENED / "lab-web" / "sshd_effective.txt").exists()
    assert (out / "data" / "history.csv").exists()


def test_cli_flow(ingested: ReportStore, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    reports = str(ingested.root)
    assert cli.main(["--repo", str(REPO), "validate"]) == 0
    assert cli.main(["drift", "--reports", reports]) == 2, "sin línea base aprobada"
    assert cli.main(["baseline", "approve", "--reports", reports]) == 0
    assert json.loads(ingested.baseline_path.read_text(encoding="utf-8"))["run_id"] == HARDENED
    drift_dir = _copy_run(ingested.root, "20261005T020000Z-drift")
    assert cli.main(["--repo", str(REPO), "ingest", "--run-dir", str(drift_dir), "--phase", "drift"]) == 0
    assert cli.main(["drift", "--reports", reports]) == 3, "el modo check del baseline muestra cambios pendientes"
    assert (drift_dir / "drift.json").exists()
    assert cli.main(["--repo", str(REPO), "report", "--reports", reports, "--out", str(tmp_path / "site")]) == 0
    assert cli.main(["schemas", "--out", str(tmp_path / "schemas")]) == 0
    assert cli.main(["--repo", str(REPO), "exceptions-doc", "--out", str(tmp_path / "exc.md")]) == 0
    output = capsys.readouterr().out
    assert "Línea base aprobada" in output
    assert "REGRESIÓN" in output or "CAMBIO" in output


def test_generated_files_are_up_to_date(tmp_path: Path) -> None:
    assert cli.main(["schemas", "--out", str(tmp_path / "schemas")]) == 0
    for generated in sorted((tmp_path / "schemas").glob("*.json")):
        assert generated.read_text(encoding="utf-8") == (REPO / "schemas" / "v1" / generated.name).read_text(
            encoding="utf-8"
        ), f"regenera schemas/v1 ({generated.name})"
    assert cli.main(["--repo", str(REPO), "exceptions-doc", "--out", str(tmp_path / "exc.md")]) == 0
    assert (tmp_path / "exc.md").read_text(encoding="utf-8") == (REPO / "docs" / "excepciones.md").read_text(
        encoding="utf-8"
    ), "regenera docs/excepciones.md"


def test_direct_labels_do_not_overlap() -> None:
    from hardening_lab.report.charts import _spread

    assert _spread([98.0, 97.0, 80.0, None], min_gap=7.0) == [98.0, 91.0, 80.0, None]
