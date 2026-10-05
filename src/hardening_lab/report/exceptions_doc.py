"""Genera docs/excepciones.md a partir de controls/exceptions.yml (una sola fuente de verdad)."""

from __future__ import annotations

from hardening_lab.config import Catalog, ExceptionRegistry
from hardening_lab.domain import ExceptionCategory

CATEGORY_LABELS = {
    ExceptionCategory.HOST_RESPONSIBILITY: "Responsabilidad del anfitrión",
    ExceptionCategory.NOT_APPLICABLE_CONTAINER: "No aplicable en contenedor",
    ExceptionCategory.OPERATIONAL_REQUIREMENT: "Requisito operativo",
    ExceptionCategory.RISK_ACCEPTED: "Riesgo aceptado",
}


def render(catalog: Catalog, registry: ExceptionRegistry) -> str:
    lines = [
        "# Excepciones justificadas",
        "",
        "> Archivo generado con `hlab exceptions-doc` desde `controls/exceptions.yml`. No editar a mano.",
        "",
        "Cada excepción es una desviación **identificada, documentada y aprobada** de la configuración segura",
        "(NIST SP 800-53 Rev. 5, CM-6(c)), con los controles que mitigan su riesgo (NIST SP 800-128) y una fecha",
        "de revisión de máximo 180 días. Una excepción vencida deja de cubrir el control y el informe lo marca como",
        "falla. El aprobador es un rol ficticio del laboratorio.",
        "",
        "| ID | Controles | Alcance | Categoría | Riesgo residual | Revisión |",
        "|---|---|---|---|---|---|",
    ]
    for exc in registry.exceptions:
        scope = ", ".join([*exc.scope.hosts, *(r.value for r in exc.scope.roles)])
        lines.append(
            f"| {exc.exception_id} | {', '.join(exc.control_ids)} | {scope} | "
            f"{CATEGORY_LABELS[exc.category]} | {exc.residual_severity.value} | {exc.review_by.isoformat()} |"
        )
    for exc in registry.exceptions:
        lines += ["", f"## {exc.exception_id} · {', '.join(exc.control_ids)}", ""]
        for control_id in exc.control_ids:
            control = catalog.get(control_id)
            if control is not None:
                lines.append(f"- **{control_id}**: {control.title_es} (severidad {control.severity.value})")
        lines += [
            f"- **Categoría**: {CATEGORY_LABELS[exc.category]}",
            f"- **Aprobada por**: {exc.approved_by} el {exc.approved_on.isoformat()}; revisión antes del "
            f"{exc.review_by.isoformat()}",
            "",
            f"**Justificación.** {exc.justification}",
            "",
        ]
        if exc.compensating_controls:
            lines.append("**Controles compensatorios:**")
            lines += [f"- {item}" for item in exc.compensating_controls]
            lines.append("")
        if exc.references:
            lines.append("**Referencias:** " + "; ".join(exc.references) + ".")
    return "\n".join(lines).rstrip() + "\n"
