from __future__ import annotations

import re
from collections import Counter


def classify(text: str) -> list[dict[str, object]]:
    rules = {
        "Encoding and decoding": [(r"(?:base64|base32|hex|decode|encoded|rot13)", 0.30), (r"[A-Za-z0-9+/]{16,}={0,2}", 0.25), (r"(?:[0-9a-fA-F]{2}){4,}", 0.18)],
        "Classical cryptography": [(r"cipher|ciphertext|shift|caesar|vigen[eè]re|substitution|xor", 0.45)],
        "Cryptography": [(r"rsa|\bmodulus\b|public key|private key|\bhash\b|\bencrypt", 0.42)],
        "Digital forensics": [(r"forensic|pcap|memory dump|registry|disk image|metadata", 0.40)],
        "Steganography": [(r"steg|hidden (?:message|data)|image|pixel|lsb", 0.30)],
        "Reverse engineering": [(r"binary|executable|\.exe\b|disassembl|assembly|reverse engineer", 0.38)],
        "Binary exploitation": [(r"buffer overflow|rop chain|pwn|stack canary|heap", 0.45)],
        "Web security": [(r"http|html|javascript|sql injection|xss|jwt|cookie|web page", 0.35)],
        "Network traffic analysis": [(r"network|packet|tcp|udp|dns|pcap|traffic", 0.35)],
        "OSINT": [(r"osint|geolocat|public record|social media|identify (?:the )?person", 0.35)],
        "Miscellaneous mathematics": [(r"equation|prime|factor|modular arithmetic|sequence|probability", 0.30)],
        "Programming and scripting": [(r"write (?:a )?program|script|algorithm|source code|programming", 0.25)],
        "File-format analysis": [(r"file format|archive|zip|png|jpeg|pdf|magic bytes", 0.30)],
    }
    scores: Counter[str] = Counter()
    evidence: dict[str, list[str]] = {}
    lower = text.lower()
    for category, tests in rules.items():
        for pattern, weight in tests:
            if re.search(pattern, lower, re.I):
                scores[category] += weight
                evidence.setdefault(category, []).append(f"Matched indicator: {pattern}")
    if not scores:
        return [{"category": "Unknown or mixed", "confidence": 0.2, "evidence": ["No strong category indicators found."]}]
    top = max(scores.values())
    return [{"category": name, "confidence": round(min(0.96, score / max(0.7, top + 0.45)), 2), "evidence": evidence[name]} for name, score in scores.most_common(4)]
