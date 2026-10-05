"""Informe HTML estático (GitHub Pages): antes/después, evidencia por control, excepciones, deriva e historial."""

from __future__ import annotations

import base64
import hashlib
import shutil
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from hardening_lab.config import LabConfig
from hardening_lab.domain import (
    ControlResult,
    DriftReport,
    HistoryRow,
    Phase,
    Run,
    Severity,
    Status,
    Tool,
    ToolReport,
)
from hardening_lab.report import charts
from hardening_lab.services.drift import latest_run
from hardening_lab.services.scoring import Tally, tally
from hardening_lab.services.storage import ReportStore

REPO_URL = "https://github.com/DiegoFranciscoG/hardening-lab"
SEVERITY_LABELS = {
    Severity.CRITICAL: "Crítica",
    Severity.HIGH: "Alta",
    Severity.MEDIUM: "Media",
    Severity.LOW: "Baja",
}
STATUS_LABELS = {
    Status.PASS: "Cumple",
    Status.FAIL: "Falla",
    Status.EXCEPTION: "Excepción",
    Status.ERROR: "Error",
    Status.NOTCHECKED: "Sin evidencia",
    Status.NOTAPPLICABLE: "No aplica",
    Status.INFO: "Informativo",
}


@dataclass(frozen=True)
class MatrixCell:
    host: str
    after: ControlResult | None
    before: Status | None


@dataclass
class Snapshot:
    run: Run
    controls: list[ControlResult]
    tools: dict[Tool, ToolReport]
    tally: Tally


@dataclass
class ReportData:
    runs: list[Run]
    before: Snapshot | None
    after: Snapshot | None
    drift_run: Run | None
    drift: DriftReport | None
    history: list[HistoryRow]
    charts: list[charts.Chart] = field(default_factory=list)


def _snapshot(store: ReportStore, run: Run | None) -> Snapshot | None:
    if run is None:
        return None
    controls = store.read_controls(run.run_id)
    return Snapshot(
        run=run,
        controls=controls,
        tools=store.read_tool_reports(run.run_id),
        tally=tally((c.status, c.severity) for c in controls),
    )


def load(store: ReportStore) -> ReportData:
    runs = store.list_runs()
    drift_run = latest_run(store, {Phase.DRIFT, Phase.SCHEDULED})
    drift = None
    if drift_run is not None:
        path = store.run_dir(drift_run.run_id) / "drift.json"
        if path.exists():
            drift = DriftReport.model_validate_json(path.read_text(encoding="utf-8"))
    return ReportData(
        runs=runs,
        before=_snapshot(store, latest_run(store, {Phase.BASELINE})),
        after=_snapshot(store, latest_run(store, {Phase.HARDENED})),
        drift_run=drift_run,
        drift=drift,
        history=store.read_history(),
    )


def _row(history: list[HistoryRow], run: Run | None, host: str, tool: str) -> HistoryRow | None:
    if run is None:
        return None
    return next((r for r in history if r.run_id == run.run_id and r.host == host and r.tool == tool), None)


def _pct(value: float | None) -> float | None:
    return None if value is None else round(value * 100, 1)


def build_charts(data: ReportData, hosts: list[str]) -> list[charts.Chart]:
    before = data.before.run if data.before else None
    after = data.after.run if data.after else None

    def pairs(tool: str, attribute: str, scale: float = 1.0) -> list[charts.Pair]:
        result = []
        for host in hosts:
            values = []
            for run in (before, after):
                row = _row(data.history, run, host, tool)
                value = getattr(row, attribute) if row else None
                values.append(None if value is None else round(value * scale, 1))
            result.append(charts.Pair(label=host, before=values[0], after=values[1]))
        return result

    built = [
        charts.dumbbell(
            "puntajes-antes-despues",
            "Puntaje por herramienta y host, antes y después del endurecimiento (0-100)",
            [
                ("Lynis · índice", pairs("lynis", "native_score")),
                ("OpenSCAP · CIS L1", pairs("openscap", "native_score")),
                ("Catálogo · estricto", pairs("catalog", "strict_compliance", 100)),
                ("Catálogo · con excepciones", pairs("catalog", "compliance_with_exceptions", 100)),
            ],
        )
    ]
    if data.before and data.after:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        built.append(
            charts.grouped_bars(
                "fallos-por-severidad",
                "Controles en fallo por severidad (suma de los tres hosts)",
                [SEVERITY_LABELS[s] for s in order],
                [data.before.tally.failing_by_severity[s] for s in order],
                [data.after.tally.failing_by_severity[s] for s in order],
            )
        )
    catalog_runs = [
        run for run in data.runs if any(r.run_id == run.run_id and r.tool == "catalog" for r in data.history)
    ]
    if len(catalog_runs) >= 2:
        labels = [f"{_short_date(run)}\n{run.phase.value}" for run in catalog_runs]
        series = [
            charts.Series(
                label=host,
                values=[
                    _pct(row.compliance_with_exceptions) if (row := _row(data.history, run, host, "catalog")) else None
                    for run in catalog_runs
                ],
            )
            for host in hosts
        ]
        built.append(
            charts.lines(
                "evolucion-cumplimiento",
                "Evolución del cumplimiento del catálogo con excepciones aprobadas, por auditoría",
                labels,
                series,
            )
        )
    return built


MONTHS = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"]


def _short_date(run: Run) -> str:
    moment = run.finished_at
    return f"{moment.day} {MONTHS[moment.month - 1]} {moment:%H:%M}"


def _copy_evidence(store: ReportStore, run: Run | None, out: Path) -> None:
    if run is None:
        return
    source = store.run_dir(run.run_id) / "evidence"
    if source.exists():
        shutil.copytree(source, out / "evidence" / run.run_id, dirs_exist_ok=True)


def _script_hash(script: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")


FILTER_SCRIPT = """
const input = document.getElementById("control-filter");
const statusSelect = document.getElementById("status-filter");
const rows = Array.from(document.querySelectorAll("#control-matrix tbody tr"));
function applyFilter() {
  const text = input.value.trim().toLowerCase();
  const status = statusSelect.value;
  let visible = 0;
  for (const row of rows) {
    const matchesText = !text || row.dataset.search.includes(text);
    const matchesStatus = !status || row.dataset.statuses.split(" ").includes(status);
    row.hidden = !(matchesText && matchesStatus);
    if (!row.hidden) visible += 1;
  }
  document.getElementById("filter-count").textContent = visible + " de " + rows.length + " controles";
}
input.addEventListener("input", applyFilter);
statusSelect.addEventListener("change", applyFilter);
applyFilter();
""".strip()


def build_site(store: ReportStore, out: Path, config: LabConfig, images_dir: Path | None = None) -> Path:
    data = load(store)
    hosts = sorted(config.inventory.hosts)
    data.charts = build_charts(data, hosts)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    (out / "data").mkdir()
    if store.history_path.exists():
        shutil.copy2(store.history_path, out / "data" / "history.csv")
    for snapshot in (data.before, data.after):
        if snapshot:
            shutil.copy2(
                store.run_dir(snapshot.run.run_id) / "summary.csv",
                out / "data" / f"{snapshot.run.run_id}.csv",
            )
    _copy_evidence(store, data.after.run if data.after else None, out)
    _copy_evidence(store, data.drift_run, out)
    for chart in data.charts:
        charts.save_png(chart, out / "img")
        if images_dir is not None:
            charts.save_png(chart, images_dir)

    before_status = {(c.host, c.control_id): c.status for c in data.before.controls} if data.before else {}
    after_results = {(c.host, c.control_id): c for c in data.after.controls} if data.after else {}
    matrix: list[dict[str, object]] = []
    for control in config.catalog:
        cells: list[MatrixCell] = []
        for host in hosts:
            result = after_results.get((host, control.control_id))
            cells.append(MatrixCell(host=host, after=result, before=before_status.get((host, control.control_id))))
        statuses = sorted({c.after.status.value for c in cells if c.after})
        matrix.append({"control": control, "cells": cells, "statuses": " ".join(statuses)})

    tools_table = []
    for host in hosts:
        row: dict[str, object] = {"host": host}
        for tool, attribute in (
            ("lynis", "native_score"),
            ("openscap", "native_score"),
            ("catalog", "strict_compliance"),
            ("catalog_exc", "compliance_with_exceptions"),
        ):
            source_tool = "catalog" if tool.startswith("catalog") else tool
            for label, snapshot in (("before", data.before), ("after", data.after)):
                history_row = _row(data.history, snapshot.run if snapshot else None, host, source_tool)
                value = getattr(history_row, attribute) if history_row else None
                if value is not None and source_tool == "catalog":
                    value = round(value * 100, 1)
                row[f"{tool}_{label}"] = value
        for tool in ("trivy", "docker-bench"):
            for label, snapshot in (("before", data.before), ("after", data.after)):
                history_row = _row(data.history, snapshot.run if snapshot else None, host, tool)
                row[f"{tool}_{label}"] = history_row.fail if history_row else None
        tools_table.append(row)

    bench_scores = {}
    for label, snapshot in (("before", data.before), ("after", data.after)):
        report = snapshot.tools.get(Tool.DOCKER_BENCH) if snapshot else None
        bench_scores[label] = report.scores[0].value if report and report.scores else None

    today = data.after.run.finished_at.date() if data.after else datetime.now(UTC).date()
    env = Environment(loader=PackageLoader("hardening_lab.report", "templates"), autoescape=select_autoescape())
    env.filters["pct"] = lambda v: "—" if v is None else f"{v * 100:.0f} %"
    env.filters["num"] = lambda v: "—" if v is None else (f"{v:.0f}" if float(v).is_integer() else f"{v:.1f}")
    html = env.get_template("report.html.j2").render(
        data=data,
        hosts=hosts,
        matrix=matrix,
        tools_table=tools_table,
        bench_scores=bench_scores,
        exceptions=config.exceptions.exceptions,
        exception_status={e.exception_id: e.effective_status(today).value for e in config.exceptions.exceptions},
        catalog=config.catalog,
        severity_labels=SEVERITY_LABELS,
        status_labels=STATUS_LABELS,
        counts_after=Counter(c.status.value for c in data.after.controls) if data.after else Counter(),
        counts_before=Counter(c.status.value for c in data.before.controls) if data.before else Counter(),
        generated_at=datetime.now(UTC).replace(microsecond=0),
        repo_url=REPO_URL,
        filter_script=FILTER_SCRIPT,
        script_hash=_script_hash(FILTER_SCRIPT),
        by_domain=_by_domain(config, data),
    )
    index = out / "index.html"
    index.write_text(html, encoding="utf-8", newline="\n")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    return index


def _by_domain(config: LabConfig, data: ReportData) -> list[dict[str, object]]:
    domains: dict[str, list[ControlResult]] = defaultdict(list)
    domain_of = {c.control_id: c.domain.value for c in config.catalog}
    if data.after:
        for result in data.after.controls:
            domains[domain_of.get(result.control_id, "?")].append(result)
    rows = []
    for domain, results in sorted(domains.items()):
        t = tally((r.status, r.severity) for r in results)
        rows.append({"domain": domain, "tally": t, "total": len(results)})
    return rows
