"""Exporta los JSON Schema 2020-12 de cada formato desde los modelos (contrato versionado en schemas/v1)."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from hardening_lab.domain import (
    Baseline,
    Control,
    ControlException,
    ControlsReport,
    DriftReport,
    HistoryRow,
    Run,
    ToolReport,
)

SCHEMAS: dict[str, type[BaseModel]] = {
    "run": Run,
    "tool-report": ToolReport,
    "controls-report": ControlsReport,
    "history-row": HistoryRow,
    "baseline": Baseline,
    "drift-report": DriftReport,
    "control": Control,
    "exception": ControlException,
}
BASE_ID = "https://github.com/DiegoFranciscoG/hardening-lab/schemas/v1"


def schema_documents() -> dict[str, str]:
    documents = {}
    for name, model in SCHEMAS.items():
        schema = model.model_json_schema(by_alias=True)
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"{BASE_ID}/{name}.schema.json",
            **schema,
        }
        documents[f"{name}.schema.json"] = json.dumps(schema, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    return documents


def write_schemas(directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for filename, content in schema_documents().items():
        path = directory / filename
        path.write_text(content, encoding="utf-8", newline="\n")
        written.append(path)
    return written
