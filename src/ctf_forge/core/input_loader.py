from __future__ import annotations

import hashlib
import unicodedata
from pathlib import Path


MAX_INPUT_BYTES = 2 * 1024 * 1024


def load_text(path: str | Path, max_bytes: int = MAX_INPUT_BYTES) -> tuple[str, str]:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"Challenge file does not exist: {source}")
    size = source.stat().st_size
    if size == 0:
        raise ValueError("Challenge file is empty")
    if size > max_bytes:
        raise ValueError(f"Challenge file is {size} bytes; limit is {max_bytes}")
    raw = source.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError(f"Challenge file grew while being read and exceeds the {max_bytes}-byte limit")
    digest = hashlib.sha256(raw).hexdigest()
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:  # latin-1 is total, retained for clarity
        text = raw.decode("latin-1")
    if "\x00" in text:
        raise ValueError("Input looks binary; select a supported artifact analysis workflow")
    return unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n")), digest
