"""Parsers (adaptadores) de la salida nativa de cada herramienta hacia RawFinding."""

from __future__ import annotations

import hashlib
from pathlib import Path

from hardening_lab.domain import RawArtifact


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path, base: Path) -> RawArtifact:
    """Referencia a un archivo crudo, relativa al directorio del run, con su SHA-256."""
    return RawArtifact(path=path.relative_to(base).as_posix(), sha256=sha256_file(path))
