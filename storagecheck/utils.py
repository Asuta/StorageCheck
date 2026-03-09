from __future__ import annotations

import os
from datetime import datetime, timezone


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_path(raw_path: str) -> str:
    path = os.path.expandvars(os.path.expanduser(raw_path.strip().strip('"')))
    normalized = os.path.abspath(os.path.normpath(path))
    if os.name == "nt":
        drive, tail = os.path.splitdrive(normalized)
        if drive and not tail:
            normalized = f"{drive}\\"
    return normalized


def default_label_for_path(path: str) -> str:
    stripped = path.rstrip("\\/")
    name = os.path.basename(stripped)
    return name or path
