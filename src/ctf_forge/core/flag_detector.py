from __future__ import annotations

import re
from .models import Finding


def find_flags(text: str, source: str = "Input", prefixes: tuple[str, ...] = ("flag", "CTF", "FLAG", "HTB", "picoCTF")) -> list[Finding]:
    escaped = "|".join(re.escape(prefix) for prefix in prefixes)
    # Common CTF flag payloads are token-like. Reject arbitrary transformed punctuation
    # that happens to resemble `prefix{...}`; matches are candidates only, never verified.
    pattern = re.compile(rf"(?i)(?:{escaped})\{{[A-Za-z0-9_-]{{1,200}}\}}")
    results: list[Finding] = []
    for match in pattern.finditer(text):
        results.append(Finding("Flag candidate", match.group(0), source, 0.75, f"Matches configured flag format at character {match.start()}; format alone does not verify it.", False))
    return results
