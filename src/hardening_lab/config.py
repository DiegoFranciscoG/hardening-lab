"""Repositorio de la configuración del laboratorio: inventario, catálogo de controles y excepciones."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from pydantic import TypeAdapter, ValidationError

from hardening_lab.domain import Control, ControlException, Role
from hardening_lab.errors import ConfigurationError


@dataclass(frozen=True)
class Host:
    name: str
    role: Role
    exposure: str
    criticality: str
    owner_role: str
    ips: dict[str, str]
    services: list[dict[str, Any]]


@dataclass(frozen=True)
class Inventory:
    hosts: dict[str, Host]
    sha256: str

    def role_of(self, host: str) -> str | None:
        found = self.hosts.get(host)
        return found.role.value if found else None


def _load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"No existe {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"YAML inválido en {path}: {exc}") from exc


def load_inventory(path: Path) -> Inventory:
    data = _load_yaml(path)
    hosts: dict[str, Host] = {}
    try:
        groups = data["all"]["children"]
        for group in groups.values():
            for name, attrs in (group.get("hosts") or {}).items():
                hosts[name] = Host(
                    name=name,
                    role=Role(attrs["lab_role"]),
                    exposure=attrs["lab_exposure"],
                    criticality=attrs["lab_criticality"],
                    owner_role=attrs["lab_owner_role"],
                    ips={k: str(v) for k, v in attrs["lab_ip"].items()},
                    services=list(attrs.get("lab_services", [])),
                )
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigurationError(f"Inventario con estructura inesperada en {path}: {exc}") from exc
    if not hosts:
        raise ConfigurationError(f"El inventario {path} no declara hosts")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return Inventory(hosts=hosts, sha256=digest)


_CONTROLS = TypeAdapter(list[Control])
_EXCEPTIONS = TypeAdapter(list[ControlException])


@dataclass(frozen=True)
class Catalog:
    controls: dict[str, Control]

    def __iter__(self) -> Any:
        return iter(self.controls.values())

    def get(self, control_id: str) -> Control | None:
        return self.controls.get(control_id)


def load_catalog(path: Path) -> Catalog:
    data = _load_yaml(path)
    try:
        controls = _CONTROLS.validate_python(data.get("controls", []))
    except (ValidationError, AttributeError) as exc:
        raise ConfigurationError(f"Catálogo inválido en {path}: {exc}") from exc
    by_id: dict[str, Control] = {}
    for control in controls:
        if control.control_id in by_id:
            raise ConfigurationError(f"control_id duplicado: {control.control_id}")
        by_id[control.control_id] = control
    return Catalog(controls=by_id)


@dataclass(frozen=True)
class ExceptionRegistry:
    exceptions: list[ControlException]

    def find(self, control_id: str, host: str, role: str | None, today: date) -> ControlException | None:
        for exception in self.exceptions:
            if exception.covers(control_id, host, role, today):
                return exception
        return None


def load_exceptions(path: Path, catalog: Catalog) -> ExceptionRegistry:
    data = _load_yaml(path)
    try:
        exceptions = _EXCEPTIONS.validate_python(data.get("exceptions", []))
    except (ValidationError, AttributeError) as exc:
        raise ConfigurationError(f"Excepciones inválidas en {path}: {exc}") from exc
    seen: set[str] = set()
    for exception in exceptions:
        if exception.exception_id in seen:
            raise ConfigurationError(f"exception_id duplicado: {exception.exception_id}")
        seen.add(exception.exception_id)
        unknown = [cid for cid in exception.control_ids if catalog.get(cid) is None]
        if unknown:
            raise ConfigurationError(f"{exception.exception_id} referencia controles inexistentes: {unknown}")
    return ExceptionRegistry(exceptions=exceptions)


def validate_consistency(inventory: Inventory, catalog: Catalog, registry: ExceptionRegistry) -> list[str]:
    """Reglas de integridad entre archivos; devuelve la lista de problemas (vacía si todo está bien)."""
    problems: list[str] = []
    roles = {host.role for host in inventory.hosts.values()}
    for control in catalog:
        missing = set(control.applies_to) - roles
        if missing:
            problems.append(f"{control.control_id} aplica a roles sin hosts: {sorted(missing)}")
    for exception in registry.exceptions:
        unknown_hosts = [h for h in exception.scope.hosts if h not in inventory.hosts]
        if unknown_hosts:
            problems.append(f"{exception.exception_id} referencia hosts inexistentes: {unknown_hosts}")
    return problems


def hosts_for_roles(inventory: Inventory, roles: Iterable[Role]) -> list[str]:
    wanted = set(roles)
    return sorted(name for name, host in inventory.hosts.items() if host.role in wanted)


@dataclass(frozen=True)
class LabConfig:
    inventory: Inventory
    catalog: Catalog
    exceptions: ExceptionRegistry


def load_lab_config(repo: Path) -> LabConfig:
    """Carga los tres archivos de configuración del repositorio."""
    inventory = load_inventory(repo / "inventory" / "lab.yml")
    catalog = load_catalog(repo / "controls" / "catalog.yml")
    exceptions = load_exceptions(repo / "controls" / "exceptions.yml", catalog)
    return LabConfig(inventory=inventory, catalog=catalog, exceptions=exceptions)
