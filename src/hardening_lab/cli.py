"""Punto de entrada de línea de comandos `hlab` (capa de presentación: sin lógica de negocio)."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from hardening_lab.config import load_lab_config, validate_consistency
from hardening_lab.domain import Phase
from hardening_lab.errors import HardeningLabError
from hardening_lab.services.storage import ReportStore

DEFAULT_APPROVER = "Responsable de seguridad del laboratorio (rol ficticio)"


def _cmd_validate(args: argparse.Namespace) -> int:
    cfg = load_lab_config(args.repo)
    problems = validate_consistency(cfg.inventory, cfg.catalog, cfg.exceptions)
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if not problems:
        print(
            f"OK: {len(cfg.inventory.hosts)} hosts, {len(cfg.catalog.controls)} controles, "
            f"{len(cfg.exceptions.exceptions)} excepciones"
        )
    return 1 if problems else 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    from hardening_lab.services.ingest import ingest

    cfg = load_lab_config(args.repo)
    result = ingest(
        args.run_dir,
        Phase(args.phase),
        store=ReportStore(args.run_dir.parent.parent),
        inventory=cfg.inventory,
        catalog=cfg.catalog,
        exceptions=cfg.exceptions,
        force=args.force,
    )
    statuses: dict[str, int] = {}
    for control in result.controls:
        statuses[control.status.value] = statuses.get(control.status.value, 0) + 1
    print(
        f"Run {result.run.run_id} ({result.run.status.value}): {len(result.findings)} hallazgos, "
        f"controles {json.dumps(statuses, sort_keys=True)}, {result.history_rows_added} filas nuevas en history.csv"
    )
    for warning in result.warnings:
        print(f"AVISO: {warning}", file=sys.stderr)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from hardening_lab.report.site import build_site

    index = build_site(ReportStore(args.reports), args.out, load_lab_config(args.repo), images_dir=args.images)
    print(f"Informe generado en {index}")
    return 0


def _cmd_drift(args: argparse.Namespace) -> int:
    from hardening_lab.services.drift import DRIFT_EXIT_CODE, detect

    report = detect(ReportStore(args.reports), args.run_id)
    print(
        f"Deriva {report.current_run_id} vs línea base {report.baseline_run_id}: {report.verdict.value} "
        f"({len(report.regressions)} regresiones, {len(report.ansible_changed_tasks)} tareas con cambios)"
    )
    for change in report.regressions:
        print(f"  REGRESIÓN {change.host} {change.control_id}: {change.before} -> {change.after}")
    for task in report.ansible_changed_tasks:
        print(f"  CAMBIO {task.host}: {task.task}")
    return DRIFT_EXIT_CODE if report.verdict.value == "drift" else 0


def _cmd_baseline(args: argparse.Namespace) -> int:
    from hardening_lab.services.drift import approve_baseline

    baseline = approve_baseline(ReportStore(args.reports), args.run_id, args.approved_by)
    print(f"Línea base aprobada: {baseline.run_id}")
    return 0


def _cmd_exceptions_doc(args: argparse.Namespace) -> int:
    from hardening_lab.report.exceptions_doc import render

    cfg = load_lab_config(args.repo)
    args.out.write_text(render(cfg.catalog, cfg.exceptions), encoding="utf-8", newline="\n")
    print(f"Documento de excepciones generado en {args.out}")
    return 0


def _cmd_schemas(args: argparse.Namespace) -> int:
    from hardening_lab.schemas import write_schemas

    for path in write_schemas(args.out):
        print(path)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hlab", description="Normaliza auditorías, informa y detecta deriva.")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Raíz del repositorio (por defecto, cwd)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="Valida inventario, catálogo y excepciones").set_defaults(func=_cmd_validate)

    ingest = sub.add_parser("ingest", help="Normaliza las salidas crudas de un run")
    ingest.add_argument("--run-dir", type=Path, required=True)
    ingest.add_argument("--phase", choices=[p.value for p in Phase], required=True)
    ingest.add_argument("--force", action="store_true", help="Reescribe un run existente (solo desarrollo)")
    ingest.set_defaults(func=_cmd_ingest)

    report = sub.add_parser("report", help="Genera el informe HTML antes/después")
    report.add_argument("--reports", type=Path, default=Path("reports"))
    report.add_argument("--out", type=Path, default=Path("reports/site"))
    report.add_argument("--images", type=Path, default=None, help="Copia los gráficos también aquí (README)")
    report.set_defaults(func=_cmd_report)

    drift = sub.add_parser("drift", help="Compara la última re-auditoría contra la línea base")
    drift.add_argument("--reports", type=Path, default=Path("reports"))
    drift.add_argument("--run-id", default=None)
    drift.set_defaults(func=_cmd_drift)

    baseline = sub.add_parser("baseline", help="Gestiona la línea base de deriva")
    baseline_sub = baseline.add_subparsers(dest="action", required=True)
    approve = baseline_sub.add_parser("approve", help="Aprueba una auditoría endurecida como línea base")
    approve.add_argument("--reports", type=Path, default=Path("reports"))
    approve.add_argument("--run-id", default=None)
    approve.add_argument("--approved-by", default=DEFAULT_APPROVER)
    approve.set_defaults(func=_cmd_baseline)

    doc = sub.add_parser("exceptions-doc", help="Genera docs/excepciones.md desde controls/exceptions.yml")
    doc.add_argument("--out", type=Path, default=Path("docs/excepciones.md"))
    doc.set_defaults(func=_cmd_exceptions_doc)

    schemas = sub.add_parser("schemas", help="Exporta los JSON Schema de los formatos")
    schemas.add_argument("--out", type=Path, default=Path("schemas/v1"))
    schemas.set_defaults(func=_cmd_schemas)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        code: int = args.func(args)
    except HardeningLabError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return code


if __name__ == "__main__":
    sys.exit(main())
