"""Registra las versiones (y hashes verificados) de las herramientas del controlador en raw/tools.json."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from importlib import metadata
from pathlib import Path


def main(out: Path) -> None:
    trivy = subprocess.run(["trivy", "version", "--format", "json"], capture_output=True, text=True, check=True)
    data = {
        "trivy": json.loads(trivy.stdout).get("Version"),
        "trivy_sha256": os.environ.get("HLAB_TRIVY_SHA256"),
        "ansible-core": metadata.version("ansible-core"),
        "hardening-lab": metadata.version("hardening-lab"),
        "lynis": os.environ.get("HLAB_LYNIS_VERSION"),
        "lynis_sha256": os.environ.get("HLAB_LYNIS_SHA256"),
        "scap-security-guide": os.environ.get("HLAB_SSG_VERSION"),
    }
    out.write_text(json.dumps({k: v for k, v in data.items() if v}, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
