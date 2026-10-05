from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hardening_lab.config import (
    LabConfig,
    hosts_for_roles,
    load_catalog,
    load_exceptions,
    load_inventory,
    validate_consistency,
)
from hardening_lab.domain import Role
from hardening_lab.errors import ConfigurationError


def test_repository_configuration_is_consistent(lab_config: LabConfig) -> None:
    assert validate_consistency(lab_config.inventory, lab_config.catalog, lab_config.exceptions) == []
    assert set(lab_config.inventory.hosts) == {"lab-bastion", "lab-web", "lab-db"}
    assert len(lab_config.catalog.controls) >= 45


def test_every_exception_points_to_real_controls(lab_config: LabConfig) -> None:
    for exc in lab_config.exceptions.exceptions:
        for control_id in exc.control_ids:
            assert lab_config.catalog.get(control_id) is not None


def test_inventory_ips_match_compose_files(repo: Path, lab_config: LabConfig) -> None:
    base = yaml.safe_load((repo / "lab" / "compose.yaml").read_text(encoding="utf-8"))
    hardened_text = (repo / "lab" / "compose.hardened.yaml").read_text(encoding="utf-8")
    hardened = yaml.safe_load(hardened_text.replace("!override", "").replace("!reset", ""))
    service_of = {"lab-bastion": "bastion", "lab-web": "web", "lab-db": "db"}
    for name, host in lab_config.inventory.hosts.items():
        service = service_of[name]
        assert base["services"][service]["networks"]["flat"]["ipv4_address"] == host.ips["baseline"]
        for network, attrs in hardened["services"][service]["networks"].items():
            assert attrs["ipv4_address"] == host.ips[network], f"{name} en {network}"


def test_hosts_for_roles(lab_config: LabConfig) -> None:
    assert hosts_for_roles(lab_config.inventory, [Role.WEB, Role.DB]) == ["lab-db", "lab-web"]


def test_missing_file_raises_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="No existe"):
        load_inventory(tmp_path / "nope.yml")


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    path = tmp_path / "catalog.yml"
    path.write_text("controls: [", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="YAML"):
        load_catalog(path)


def test_duplicate_control_ids_are_rejected(tmp_path: Path) -> None:
    control = {
        "control_id": "HL-SSH-001",
        "domain": "ssh",
        "title_es": "Control duplicado de prueba",
        "severity": "high",
        "method": "examine",
        "applies_to": ["web"],
    }
    path = tmp_path / "catalog.yml"
    path.write_text(yaml.safe_dump({"controls": [control, control]}), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="duplicado"):
        load_catalog(path)


def test_exception_with_unknown_control_is_rejected(tmp_path: Path, lab_config: LabConfig) -> None:
    path = tmp_path / "exceptions.yml"
    data = {
        "exceptions": [
            {
                "exception_id": "EXC-901",
                "control_ids": ["HL-SSH-999"],
                "scope": {"roles": ["web"]},
                "category": "risk_accepted",
                "justification": "Texto suficientemente largo para la validación de la excepción.",
                "compensating_controls": ["algo"],
                "residual_severity": "low",
                "approved_by": "rol",
                "approved_on": "2026-10-01",
                "review_by": "2026-11-01",
            }
        ]
    }
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="inexistentes"):
        load_exceptions(path, lab_config.catalog)


def test_inventory_without_hosts_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "lab.yml"
    path.write_text("all:\n  children: {}\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="no declara hosts"):
        load_inventory(path)
