"""Repositorio de informes en disco (reports/): runs de solo escritura (R4) e historial que solo crece (R5)."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel

from hardening_lab.domain import (
    Baseline,
    ControlResult,
    ControlsReport,
    Finding,
    HistoryRow,
    Run,
    Tool,
    ToolReport,
)
from hardening_lab.errors import BaselineMissingError, StorageError

HISTORY_COLUMNS = [
    "schema_version",
    "run_id",
    "finished_at",
    "phase",
    "git_sha",
    "host",
    "role",
    "tool",
    "tool_version",
    "native_score",
    "pass",
    "fail",
    "exception",
    "notapplicable",
    "notchecked",
    "info",
    "error",
    "critical_fail",
    "high_fail",
    "medium_fail",
    "low_fail",
    "strict_compliance",
    "compliance_with_exceptions",
]
SUMMARY_COLUMNS = [
    "run_id",
    "observed_at",
    "phase",
    "host",
    "tool",
    "check_id",
    "control_id",
    "status",
    "severity",
    "exception_id",
    "evidence_ref",
]


def _csv_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.4f}".rstrip("0").rstrip(".") if value % 1 else str(int(value))
    return str(value.value if hasattr(value, "value") else value)


class ReportStore:
    def __init__(self, reports_dir: Path) -> None:
        self.root = reports_dir
        self.runs_dir = reports_dir / "runs"
        self.history_path = reports_dir / "history.csv"
        self.baseline_path = reports_dir / "baseline.json"

    # ------------------------------------------------------------------ escritura de solo una vez
    def write_once(self, path: Path, content: str, *, force: bool = False) -> None:
        """Escribe un archivo del run; si ya existe con otro contenido falla (los runs no se reescriben)."""
        if path.exists() and not force:
            if path.read_text(encoding="utf-8") == content:
                return
            raise StorageError(f"{path} ya existe con otro contenido: los runs son de solo escritura")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")

    def write_model(self, path: Path, model: BaseModel, *, force: bool = False, compact: bool = False) -> None:
        """Serializa un modelo; `compact` omite la sangría en los informes grandes (findings por herramienta)."""
        text = model.model_dump_json(indent=None if compact else 2, by_alias=True)
        self.write_once(path, text + "\n", force=force)

    # ------------------------------------------------------------------ lectura
    def run_dir(self, run_id: str) -> Path:
        return self.runs_dir / run_id

    def read_run(self, run_id: str) -> Run:
        return Run.model_validate_json((self.run_dir(run_id) / "run.json").read_text(encoding="utf-8"))

    def list_runs(self) -> list[Run]:
        if not self.runs_dir.exists():
            return []
        runs = [
            Run.model_validate_json(path.read_text(encoding="utf-8"))
            for path in sorted(self.runs_dir.glob("*/run.json"))
        ]
        return sorted(runs, key=lambda run: run.run_id)

    def read_controls(self, run_id: str) -> list[ControlResult]:
        path = self.run_dir(run_id) / "controls.json"
        return ControlsReport.model_validate_json(path.read_text(encoding="utf-8")).results

    def read_tool_reports(self, run_id: str) -> dict[Tool, ToolReport]:
        reports: dict[Tool, ToolReport] = {}
        for path in sorted((self.run_dir(run_id) / "findings").glob("*.json")):
            report = ToolReport.model_validate_json(path.read_text(encoding="utf-8"))
            reports[report.tool] = report
        return reports

    # ------------------------------------------------------------------ summary.csv
    def write_summary(
        self,
        run: Run,
        findings: Iterable[Finding],
        controls: Iterable[ControlResult],
        *,
        force: bool = False,
    ) -> None:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(SUMMARY_COLUMNS)
        observed = run.started_at.isoformat().replace("+00:00", "Z")
        for f in sorted(findings, key=lambda f: (f.host, f.tool.value, f.check_id, f.finding_id)):
            writer.writerow(
                [
                    run.run_id,
                    observed,
                    run.phase.value,
                    f.host,
                    f.tool.value,
                    f.check_id,
                    f.control_id or "",
                    f.status.value,
                    f.severity.value,
                    f.exception_id or "",
                    "",
                ]
            )
        for c in sorted(controls, key=lambda c: (c.host, c.control_id)):
            writer.writerow(
                [
                    run.run_id,
                    observed,
                    run.phase.value,
                    c.host,
                    "catalog",
                    c.control_id,
                    c.control_id,
                    c.status.value,
                    c.severity.value,
                    c.exception_id or "",
                    ";".join(e.path for e in c.evidence),
                ]
            )
        self.write_once(self.run_dir(run.run_id) / "summary.csv", buffer.getvalue(), force=force)

    # ------------------------------------------------------------------ history.csv
    def read_history(self) -> list[HistoryRow]:
        if not self.history_path.exists():
            return []
        with self.history_path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        return [
            HistoryRow.model_validate({key: (value if value != "" else None) for key, value in row.items()})
            for row in rows
        ]

    def append_history(self, rows: Iterable[HistoryRow]) -> int:
        """Agrega filas nuevas; una clave repetida solo se tolera si la fila es idéntica (reingesta)."""
        existing: dict[tuple[str, str, str], list[str]] = {}
        if self.history_path.exists():
            with self.history_path.open(encoding="utf-8", newline="") as handle:
                for record in csv.DictReader(handle):
                    existing[(record["run_id"], record["host"], record["tool"])] = [record[c] for c in HISTORY_COLUMNS]
        new_lines: list[list[str]] = []
        for history_row in rows:
            data = history_row.model_dump(by_alias=True)
            line = [_csv_value(data[column]) for column in HISTORY_COLUMNS]
            line[2] = history_row.finished_at.isoformat().replace("+00:00", "Z")
            key = (history_row.run_id, history_row.host, history_row.tool)
            if key in existing:
                if existing[key] != line:
                    raise StorageError(f"history.csv ya tiene {key} con otros valores: el historial no se reescribe")
                continue
            existing[key] = line
            new_lines.append(line)
        if new_lines:
            write_header = not self.history_path.exists()
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            with self.history_path.open("a", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle, lineterminator="\n")
                if write_header:
                    writer.writerow(HISTORY_COLUMNS)
                writer.writerows(new_lines)
        return len(new_lines)

    # ------------------------------------------------------------------ línea base
    def read_baseline(self) -> Baseline:
        if not self.baseline_path.exists():
            raise BaselineMissingError("No hay línea base aprobada: ejecuta `make approve-baseline`")
        return Baseline.model_validate_json(self.baseline_path.read_text(encoding="utf-8"))

    def write_baseline(self, baseline: Baseline) -> None:
        self.baseline_path.write_text(baseline.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n")
