"""Fixtures compartidas: configuración real del repositorio y fábricas de objetos de dominio."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import pytest

from hardening_lab.config import LabConfig, load_lab_config
from hardening_lab.domain import ControlException, RawFinding, Status, Tool

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def repo() -> Path:
    return REPO


@pytest.fixture(scope="session")
def lab_config() -> LabConfig:
    return load_lab_config(REPO)


def raw(tool: Tool, host: str, check_id: str, status: Status, **extra: Any) -> RawFinding:
    title = extra.pop("title", check_id)
    return RawFinding(tool=tool, host=host, check_id=check_id, title=title, status=status, **extra)


def exception(**overrides: Any) -> ControlException:
    data: dict[str, Any] = {
        "exception_id": "EXC-900",
        "control_ids": ["HL-SSH-001"],
        "scope": {"roles": ["web"]},
        "category": "operational_requirement",
        "justification": "Justificación de prueba suficientemente larga para pasar la validación.",
        "compensating_controls": ["Control compensatorio de prueba"],
        "residual_severity": "low",
        "approved_by": "Rol ficticio",
        "approved_on": date(2026, 10, 1),
        "review_by": date(2026, 12, 31),
    }
    data.update(overrides)
    return ControlException.model_validate(data)
