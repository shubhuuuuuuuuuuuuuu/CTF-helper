from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
import codecs


def decode_candidates(text: str) -> list[tuple[str, str, str]]:
    """Return (technique, output, explanation) only for plausible input forms."""
    out: list[tuple[str, str, str]] = []
    compact = re.sub(r"\s+", "", text)
    if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) >= 2 and len(compact) % 2 == 0:
        try:
            value = bytes.fromhex(compact).decode("utf-8", "strict")
            if value.strip(): out.append(("Hex decode", value, "Even-length hexadecimal decoded as UTF-8."))
        except (ValueError, UnicodeDecodeError):
            pass
    if re.fullmatch(r"[01]{8}(?:[\s,]+[01]{8})*", text.strip()):
        try:
            value = bytes(int(part, 2) for part in re.split(r"[\s,]+", text.strip())).decode("utf-8")
            out.append(("Binary to text", value, "Eight-bit binary groups decoded as UTF-8."))
        except (ValueError, UnicodeDecodeError): pass
    if re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact) and len(compact) >= 8:
        try:
            raw = base64.b64decode(compact, validate=True)
            value = raw.decode("utf-8")
            if value.strip() and any(c.isprintable() for c in value):
                out.append(("Base64 decode", value, "Strict Base64 decoded as UTF-8."))
        except (binascii.Error, ValueError, UnicodeDecodeError): pass
    if re.fullmatch(r"[A-Z2-7]+=*", compact, re.I) and len(compact) >= 8:
        try:
            value = base64.b32decode(compact.upper()).decode("utf-8")
            if value.strip(): out.append(("Base32 decode", value, "Base32 decoded as UTF-8."))
        except (binascii.Error, ValueError, UnicodeDecodeError): pass
    if re.search(r"%[0-9a-fA-F]{2}", text):
        value = urllib.parse.unquote(text)
        if value != text: out.append(("URL decode", value, "Percent-encoded bytes decoded once."))
    if text and all(ord(c) < 128 for c in text) and re.search(r"[A-Za-z]", text):
        rot = codecs.decode(text, "rot_13")
        if rot != text: out.append(("ROT13", rot, "Applied the fixed ROT13 alphabet rotation."))
        for shift in range(1, 26):
            candidate = "".join(chr((ord(c)-65+shift)%26+65) if "A" <= c <= "Z" else chr((ord(c)-97+shift)%26+97) if "a" <= c <= "z" else c for c in text)
            out.append((f"Caesar shift {shift}", candidate, f"Shifted letters forward by {shift}; inspect as a candidate."))
        atbash = "".join(chr(155-ord(c)) if "a" <= c <= "z" else chr(155-ord(c)) if "A" <= c <= "Z" else c for c in text)
        out.append(("Atbash", atbash, "Reflected letters across the alphabet."))
    if text and all(c == " " or 33 <= ord(c) <= 126 for c in text):
        rot47 = "".join(" " if c == " " else chr((ord(c) - 33 + 47) % 94 + 33) for c in text)
        if rot47 != text: out.append(("ROT47", rot47, "Rotated printable ASCII characters by 47 positions."))
    return out
