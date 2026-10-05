"""Conteos y métricas de cumplimiento (regla R7): sin ponderaciones inventadas ni mezcla de escalas (R8)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from hardening_lab.domain import Severity, Status


@dataclass(frozen=True)
class Tally:
    counts: Counter[Status]
    failing_by_severity: Counter[Severity]

    def get(self, status: Status) -> int:
        return self.counts.get(status, 0)

    @property
    def strict_compliance(self) -> float | None:
        """pass / (pass + fail + exception)."""
        denominator = self.get(Status.PASS) + self.get(Status.FAIL) + self.get(Status.EXCEPTION)
        return round(self.get(Status.PASS) / denominator, 4) if denominator else None

    @property
    def compliance_with_exceptions(self) -> float | None:
        """(pass + exception) / (pass + fail + exception)."""
        denominator = self.get(Status.PASS) + self.get(Status.FAIL) + self.get(Status.EXCEPTION)
        if not denominator:
            return None
        return round((self.get(Status.PASS) + self.get(Status.EXCEPTION)) / denominator, 4)


def tally(items: Iterable[tuple[Status, Severity]]) -> Tally:
    counts: Counter[Status] = Counter()
    failing: Counter[Severity] = Counter()
    for status, severity in items:
        counts[status] += 1
        if status is Status.FAIL:
            failing[severity] += 1
    return Tally(counts=counts, failing_by_severity=failing)


def delta(before: float | None, after: float | None) -> float | None:
    if before is None or after is None:
        return None
    return round(after - before, 4)
