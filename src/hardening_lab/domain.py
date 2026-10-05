"""Modelo de dominio: catálogos normalizados y entidades de docs/modelo-datos.md."""

from __future__ import annotations

import re
from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION: Literal["1.0"] = "1.0"

RUN_ID_PATTERN = r"^\d{8}T\d{6}Z-(baseline|hardened|drift|scheduled)$"
CONTROL_ID_PATTERN = r"^HL-(SSH|ACC|SUDO|PAM|PERM|SVC|NET|KRN|FW|LOG|AUD|UPD|CTR|WEB|DB)-\d{3}$"
EXCEPTION_ID_PATTERN = r"^EXC-\d{3}$"
MAX_EXCEPTION_DAYS = 180


class Status(StrEnum):
    PASS = "pass"  # noqa: S105 - estado de un control, no una contraseña
    FAIL = "fail"
    EXCEPTION = "exception"
    NOTAPPLICABLE = "notapplicable"
    NOTCHECKED = "notchecked"
    INFO = "info"
    ERROR = "error"

    @property
    def weight(self) -> int:
        """Orden para agregar varias fuentes: gana el estado más grave."""
        return _STATUS_WEIGHT[self]


_STATUS_WEIGHT = {
    Status.FAIL: 6,
    Status.ERROR: 5,
    Status.EXCEPTION: 4,
    Status.PASS: 3,
    Status.NOTCHECKED: 2,
    Status.INFO: 1,
    Status.NOTAPPLICABLE: 0,
}


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Tool(StrEnum):
    LYNIS = "lynis"
    OPENSCAP = "openscap"
    DOCKER_BENCH = "docker-bench"
    TRIVY = "trivy"
    LAB_PROBE = "lab-probe"
    ANSIBLE_CHECK = "ansible-check"


CATALOG_VIEW = "catalog"
"""Pseudo-herramienta para filas agregadas por control del catálogo (history.csv, summary.csv)."""


class Phase(StrEnum):
    BASELINE = "baseline"
    HARDENED = "hardened"
    DRIFT = "drift"
    SCHEDULED = "scheduled"


class Method(StrEnum):
    EXAMINE = "examine"
    TEST = "test"


class Role(StrEnum):
    BASTION = "bastion"
    WEB = "web"
    DB = "db"


class Domain(StrEnum):
    SSH = "ssh"
    ACCOUNTS = "accounts"
    SUDO_PAM = "sudo_pam"
    FILE_PERMISSIONS = "file_permissions"
    SERVICES = "services"
    KERNEL_NETWORK = "kernel_network"
    FIREWALL = "firewall"
    LOGGING = "logging"
    AUDITING = "auditing"
    UPDATES = "updates"
    CONTAINER_RUNTIME = "container_runtime"
    WEB = "web"
    DATABASE = "database"


class Framework(StrEnum):
    CIS_UBUNTU2404_V1 = "cis_ubuntu2404_v1"
    CIS_DOCKER_V1_6 = "cis_docker_v1_6"
    SSG = "ssg"
    LYNIS = "lynis"
    DOCKER_BENCH = "docker_bench"
    TRIVY = "trivy"
    LAB_PROBE = "lab_probe"
    ANSIBLE_CHECK = "ansible_check"


class ExceptionCategory(StrEnum):
    HOST_RESPONSIBILITY = "host_responsibility"
    NOT_APPLICABLE_CONTAINER = "not_applicable_container"
    OPERATIONAL_REQUIREMENT = "operational_requirement"
    RISK_ACCEPTED = "risk_accepted"


class ExceptionStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


def _compile(pattern: str) -> None:
    try:
        re.compile(pattern, re.MULTILINE)
    except re.error as exc:
        raise ValueError(f"regex inválida {pattern!r}: {exc}") from exc


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# --------------------------------------------------------------------------- catálogo de controles


class ControlRef(_Frozen):
    framework: Framework
    ref_id: str = Field(min_length=1)
    match: str | None = Field(default=None, description="Regex opcional sobre título/detalle del hallazgo")

    @field_validator("match")
    @classmethod
    def _valid_regex(cls, value: str | None) -> str | None:
        if value is not None:
            _compile(value)
        return value


class Remediation(_Frozen):
    role: str
    tags: list[str] = Field(default_factory=list)


class Assertion(_Frozen):
    """Expectativa sobre la salida de una sonda de evidencia (regex multilínea)."""

    probe: str
    pattern: str
    expect: Literal["present", "absent"] = "present"

    @field_validator("pattern")
    @classmethod
    def _valid_pattern(cls, value: str) -> str:
        _compile(value)
        return value


class Control(_Frozen):
    control_id: Annotated[str, Field(pattern=CONTROL_ID_PATTERN)]
    domain: Domain
    title_es: str = Field(min_length=10)
    severity: Severity
    method: Method
    applies_to: list[Role] = Field(min_length=1)
    remediation: Remediation | None = None
    evidence: list[str] = Field(default_factory=list)
    refs: list[ControlRef] = Field(default_factory=list)
    assertions: list[Assertion] = Field(default_factory=list)


class ExceptionScope(_Frozen):
    hosts: list[str] = Field(default_factory=list)
    roles: list[Role] = Field(default_factory=list)

    @model_validator(mode="after")
    def _not_empty(self) -> ExceptionScope:
        if not self.hosts and not self.roles:
            raise ValueError("una excepción debe acotar hosts o roles")
        return self


class ControlException(_Frozen):
    """Desviación aprobada de la configuración segura (NIST SP 800-53 CM-6(c))."""

    exception_id: Annotated[str, Field(pattern=EXCEPTION_ID_PATTERN)]
    control_ids: list[Annotated[str, Field(pattern=CONTROL_ID_PATTERN)]] = Field(min_length=1)
    scope: ExceptionScope
    category: ExceptionCategory
    justification: str = Field(min_length=40)
    compensating_controls: list[str] = Field(default_factory=list)
    residual_severity: Severity
    approved_by: str
    approved_on: date
    review_by: date
    status: ExceptionStatus = ExceptionStatus.ACTIVE
    references: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _rules(self) -> ControlException:
        if self.review_by <= self.approved_on:
            raise ValueError("review_by debe ser posterior a approved_on")
        if (self.review_by - self.approved_on).days > MAX_EXCEPTION_DAYS:
            raise ValueError(f"una excepción se revisa como máximo cada {MAX_EXCEPTION_DAYS} días")
        needs_compensation = self.category is not ExceptionCategory.NOT_APPLICABLE_CONTAINER
        if needs_compensation and not self.compensating_controls:
            raise ValueError("toda excepción (salvo not_applicable_container) requiere control compensatorio")
        return self

    def effective_status(self, today: date) -> ExceptionStatus:
        if self.status is ExceptionStatus.ACTIVE and today > self.review_by:
            return ExceptionStatus.EXPIRED
        return self.status

    def covers(self, control_id: str, host: str, role: str | None, today: date) -> bool:
        if self.effective_status(today) is not ExceptionStatus.ACTIVE:
            return False
        if control_id not in self.control_ids:
            return False
        return host in self.scope.hosts or (role is not None and role in self.scope.roles)


# --------------------------------------------------------------------------- resultados


class RawFinding(_Frozen):
    """Hallazgo tal como lo entrega un parser, antes de mapearlo al catálogo."""

    tool: Tool
    host: str
    check_id: str
    title: str
    status: Status
    severity: Severity | None = None
    details: str = ""
    item: str = ""
    refs: list[str] = Field(default_factory=list, description="IDs CIS que declara la herramienta")
    control_hint: str | None = Field(default=None, description="Control que la fuente declara de forma explícita")


class Score(_Frozen):
    host: str
    value: float
    maximum: float | None = None


class RawArtifact(_Frozen):
    path: str
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ParsedReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: Tool
    tool_version: str
    scores: list[Score] = Field(default_factory=list)
    raw: list[RawArtifact] = Field(default_factory=list)
    findings: list[RawFinding] = Field(default_factory=list)


class EvidenceRef(_Frozen):
    path: str
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    method: Method


class Finding(_Frozen):
    finding_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    run_id: Annotated[str, Field(pattern=RUN_ID_PATTERN)]
    host: str
    tool: Tool
    check_id: str
    title: str
    control_id: str | None
    status: Status
    severity: Severity
    exception_id: str | None = None
    details: str = ""
    item: str = ""
    observed_at: datetime


class ToolReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: Annotated[str, Field(pattern=RUN_ID_PATTERN)]
    tool: Tool
    tool_version: str
    generated_at: datetime
    raw: list[RawArtifact]
    scores: list[Score]
    findings: list[Finding]


class ControlResult(_Frozen):
    host: str
    control_id: str
    status: Status
    severity: Severity
    exception_id: str | None = None
    sources: list[str] = Field(default_factory=list, description="tool:check_id que aportaron al estado")
    evidence: list[EvidenceRef] = Field(default_factory=list)


class ControlsReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: Annotated[str, Field(pattern=RUN_ID_PATTERN)]
    generated_at: datetime
    results: list[ControlResult]


class ToolInfo(_Frozen):
    name: str
    version: str
    artifact_sha256: str | None = None


class Benchmark(_Frozen):
    name: str
    version: str
    via: str


class RunStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class Run(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: Annotated[str, Field(pattern=RUN_ID_PATTERN)]
    phase: Phase
    lab_state: Literal["baseline", "hardened"]
    started_at: datetime
    finished_at: datetime
    git_sha: str
    git_dirty: bool
    inventory_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    hosts: list[str]
    tools: list[ToolInfo]
    benchmarks: list[Benchmark]
    status: RunStatus
    errors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _chronology(self) -> Run:
        if self.finished_at < self.started_at:
            raise ValueError("finished_at no puede ser anterior a started_at")
        if not self.run_id.endswith(f"-{self.phase.value}"):
            raise ValueError("run_id debe terminar con la fase")
        return self


class HistoryRow(_Frozen):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: str
    finished_at: datetime
    phase: Phase
    git_sha: str
    host: str
    role: str
    tool: str
    tool_version: str
    native_score: float | None
    passed: int = Field(alias="pass", ge=0)
    fail: int = Field(ge=0)
    exception: int = Field(ge=0)
    notapplicable: int = Field(ge=0)
    notchecked: int = Field(ge=0)
    info: int = Field(ge=0)
    error: int = Field(ge=0)
    critical_fail: int = Field(ge=0)
    high_fail: int = Field(ge=0)
    medium_fail: int = Field(ge=0)
    low_fail: int = Field(ge=0)
    strict_compliance: float | None
    compliance_with_exceptions: float | None

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class Baseline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: Annotated[str, Field(pattern=RUN_ID_PATTERN)]
    approved_at: datetime
    approved_by: str


class DriftChange(_Frozen):
    host: str
    control_id: str
    before: Status | None
    after: Status | None


class DriftTask(_Frozen):
    host: str
    task: str
    control_ids: list[str]


class DriftVerdict(StrEnum):
    NO_DRIFT = "no_drift"
    DRIFT = "drift"


class DriftReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    baseline_run_id: str
    current_run_id: str
    generated_at: datetime
    regressions: list[DriftChange]
    improvements: list[DriftChange]
    new_checks: list[DriftChange]
    missing_checks: list[DriftChange]
    ansible_changed_tasks: list[DriftTask]
    verdict: DriftVerdict
