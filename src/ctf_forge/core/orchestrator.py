from __future__ import annotations

import hashlib
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from .classifier import classify
from .flag_detector import find_flags
from .input_loader import MAX_INPUT_BYTES, load_text
from .models import AnalysisResult, Finding, SolverRun
from ..solvers.classical_crypto import english_score, xor_single_byte
from ..solvers.encoding import decode_candidates
from ..solvers.number_theory import rsa_inspect

MAX_CANDIDATES = 250
MAX_TRANSFORM_DEPTH = 3
MAX_BLOCK_BYTES = 8192
DEFAULT_TIMEOUT_SECONDS = 10.0


def _rsa_parameters(text: str) -> tuple[int, int, int] | None:
    def value(*labels: str) -> int | None:
        choices = "|".join(labels)
        match = re.search(rf"(?im)(?:^|[,;\s])(?:{choices})\s*[:=]\s*(\d+)\b", text)
        return int(match.group(1)) if match else None

    n = value("n", "modulus")
    e = value("e", "exponent", "public exponent")
    c = value("c", "ciphertext", "encrypted")
    if n is None or e is None or c is None:
        return None
    return n, e, c


def analyze_text(
    text: str,
    challenge_name: str = "Untitled challenge",
    digest: str | None = None,
    cancel=None,
    category_override: str | None = None,
    max_duration_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_depth: int = MAX_TRANSFORM_DEPTH,
) -> AnalysisResult:
    if not text.strip():
        raise ValueError("Challenge text is empty")
    if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"Challenge text exceeds the {MAX_INPUT_BYTES}-byte input limit")
    if max_duration_seconds < 0 or max_depth < 0:
        raise ValueError("Timeout and recursion depth must be zero or greater")

    analysis_started = time.perf_counter()
    deadline = analysis_started + max_duration_seconds
    digest = digest or hashlib.sha256(text.encode("utf-8")).hexdigest()
    result = AnalysisResult(
        challenge_name,
        digest,
        f"{len(text)} characters across {len(text.splitlines())} lines",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    result.categories = classify(text)
    if category_override and category_override != "Auto detect":
        result.categories.insert(0, {"category": category_override, "confidence": 1.0, "evidence": ["Selected manually by the user."]})
    result.findings.extend(find_flags(text))

    rsa_params = _rsa_parameters(text)
    if rsa_params:
        started = time.perf_counter()
        if (cancel and cancel()) or time.perf_counter() >= deadline:
            result.runs.append(SolverRun("Small RSA parameter inspection", "skipped", 0.0, "Cancelled or timed out before this bounded solver started."))
        else:
            try:
                rsa = rsa_inspect(*rsa_params)
                if "plaintext_integer" in rsa:
                    number = int(rsa["plaintext_integer"])
                    raw = number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")
                    decoded = raw.decode("utf-8", "replace")
                    verified_math = pow(number, rsa_params[1], rsa_params[0]) == rsa_params[2]
                    result.findings.append(Finding(
                        "RSA plaintext candidate", decoded if decoded.isprintable() else f"integer {number}",
                        "Small RSA parameter inspection", 0.90 if verified_math else 0.45,
                        f"Trial division found p={rsa['p']} and q={rsa['q']}; modular decryption was independently checked by re-encrypting (check={'passed' if verified_math else 'failed'}). The plaintext is still a challenge candidate.",
                        False,
                    ))
                    result.runs.append(SolverRun("Small RSA parameter inspection", "completed" if verified_math else "completed with warnings", (time.perf_counter() - started) * 1000, "Bounded trial division and modular re-encryption check."))
                else:
                    result.runs.append(SolverRun("Small RSA parameter inspection", "completed with warnings", (time.perf_counter() - started) * 1000, str(rsa.get("message", "No plaintext derived."))))
            except (ValueError, OverflowError) as exc:
                result.runs.append(SolverRun("Small RSA parameter inspection", "failed", (time.perf_counter() - started) * 1000, str(exc)))

    content = re.sub(r"(?im)^\s*(?:challenge name|category|description|hint|ciphertext|output|input|question)\s*:\s*", "", text)
    blocks = [line.strip().strip('"\'`') for line in content.splitlines() if 4 <= len(line.strip()) <= MAX_BLOCK_BYTES]
    blocks += re.findall(r"(?:[A-Za-z0-9+/]{12,}={0,2}|(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[\s,:-]?){4,}[0-9a-fA-F]{2}(?![0-9a-fA-F])|[01]{8}(?:\s+[01]{8}){3,})", text)
    seen_inputs: set[str] = set()
    queue: list[tuple[str, int, str]] = []
    for block in blocks[:MAX_CANDIDATES]:
        normalized = re.sub(r"\s+", " ", block).strip()
        if normalized and normalized not in seen_inputs:
            seen_inputs.add(normalized)
            queue.append((normalized, 0, "input"))

    started = analysis_started
    produced = 0
    transforms = 0
    timed_out = False
    cancelled = False
    # Seed with raw input blocks so inverse pairs (for example ROT13 twice)
    # do not get mislabeled as newly recovered plaintext.
    seen_outputs: set[str] = set(seen_inputs)
    cursor = 0
    while cursor < len(queue) and produced < MAX_CANDIDATES:
        if cancel and cancel():
            cancelled = True
            break
        if time.perf_counter() >= deadline:
            timed_out = True
            break
        block, depth, provenance = queue[cursor]
        cursor += 1
        block_started = time.perf_counter()
        source_score = english_score(block)
        variants = decode_candidates(block)
        if source_score >= 0.62:
            # Natural-language prose is not a useful target for blind alphabet brute force.
            # Keep only decoders that require a concrete structural match.
            variants = [item for item in variants if item[0] in {"Base64 decode", "Base32 decode", "Hex decode", "Binary to text", "URL decode"}]
        for technique, value, explanation in variants:
            if cancel and cancel():
                cancelled = True
                break
            if time.perf_counter() >= deadline:
                timed_out = True
                break
            if value == block or not value.strip() or value in seen_outputs:
                continue
            seen_outputs.add(value)
            transforms += 1
            score = english_score(value)
            is_caesar = technique.startswith("Caesar")
            if is_caesar and score < 0.42:
                continue
            # This is a heuristic ranking score, not a calibrated probability or verification.
            confidence = min(0.84, 0.12 + score * 0.72)
            detail = f"{explanation} Heuristic text score={score:.2f}; source={provenance}. Candidate is unverified."
            result.findings.append(Finding(technique, value[:2000], "Encoding and classical cipher analysis", confidence, detail, False))
            if score >= 0.58:
                result.findings.extend(find_flags(value, technique))
            produced += 1
            structural_decode = technique in {"Base64 decode", "Base32 decode", "Hex decode", "Binary to text", "URL decode"}
            likely_ciphertext = depth == 0 and source_score < 0.55 and score < 0.72
            if depth < max_depth and len(value.encode("utf-8", "replace")) <= MAX_BLOCK_BYTES and (structural_decode or likely_ciphertext):
                queue.append((value, depth + 1, f"{provenance} → {technique}"))
            if produced >= MAX_CANDIDATES:
                break
        if variants:
            result.runs.append(SolverRun("Encoding and Caesar analysis", "completed", (time.perf_counter() - block_started) * 1000, f"Inspected {len(variants)} transformations at depth {depth}."))
        if timed_out or cancelled:
            break

        # XOR is only attempted for a complete, explicit byte-hex block.
        compact = re.sub(r"[\s,:-]", "", block)
        if len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
            try:
                xor_start = time.perf_counter()
                xor_candidates = xor_single_byte(bytes.fromhex(compact))
                for score, key, plaintext in xor_candidates:
                    if score < 0.58 or plaintext in seen_outputs:
                        continue
                    seen_outputs.add(plaintext)
                    result.findings.append(Finding("Single-byte XOR candidate", plaintext[:2000], "Single-byte XOR analysis", min(0.82, 0.18 + score * 0.68), f"Key byte 0x{key:02x}; printable ratio and common-word score={score:.2f}. Candidate is unverified.", False))
                    result.findings.extend(find_flags(plaintext, "Single-byte XOR"))
                result.runs.append(SolverRun("Single-byte XOR analysis", "completed", (time.perf_counter() - xor_start) * 1000, f"Tested all 256 one-byte keys against {len(compact)//2} bytes."))
            except ValueError as exc:
                result.runs.append(SolverRun("Single-byte XOR analysis", "failed", 0.0, str(exc)))

    run_status = "timed out" if timed_out else "cancelled" if cancelled else "completed"
    run_detail = f"Analyzed {len(seen_inputs)} distinct input blocks; {transforms} distinct transformations; maximum depth {max_depth}. Challenge content was never executed."
    result.runs.insert(0, SolverRun("Input validation and strategy scheduler", run_status, (time.perf_counter() - started) * 1000, run_detail))
    if timed_out:
        result.warnings.append(f"Analysis reached the configured {max_duration_seconds:g}-second time budget; completed findings are retained.")
    if cancelled:
        result.warnings.append("Analysis was cancelled by the user; completed findings are retained.")

    unique: dict[tuple[str, str], Finding] = {}
    for finding in result.findings:
        key = (finding.title, finding.value)
        if key not in unique or finding.confidence > unique[key].confidence:
            unique[key] = finding
    result.findings = sorted(unique.values(), key=lambda finding: finding.confidence, reverse=True)[:200]
    result.next_steps = ["Compare plaintext candidates with the supplied hint and expected flag format.", "Provide a key, crib, or source artifact if the challenge depends on information not present in the text."]
    if not any(f.title != "Flag candidate" and f.confidence >= 0.75 for f in result.findings):
        result.warnings.append("No strong solution was established. Candidate transformations are hypotheses, not verified answers.")
    return result


def analyze_file(path: str | Path, challenge_name: str | None = None, cancel=None, category_override: str | None = None, **limits) -> AnalysisResult:
    text, digest = load_text(path)
    return analyze_text(text, challenge_name or Path(path).stem, digest, cancel, category_override, **limits)
