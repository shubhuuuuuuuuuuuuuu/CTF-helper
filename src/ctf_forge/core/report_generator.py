from __future__ import annotations

import json
from pathlib import Path
from .models import AnalysisResult


def write_reports(result: AnalysisResult, workspace: Path) -> tuple[Path, Path]:
    workspace.mkdir(parents=True, exist_ok=True)
    stem = "analysis-" + result.input_sha256[:12]
    json_path = workspace / f"{stem}.json"
    md_path = workspace / f"{stem}.md"
    json_path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"# CTF Forge report: {result.challenge_name}", "", f"- Created: {result.created_at}", f"- Input SHA-256: `{result.input_sha256}`", f"- Summary: {result.input_summary}", "", "## Category hypotheses"]
    lines += [f"- **{c['category']}** ({c['confidence']:.0%}): {'; '.join(c['evidence'])}" for c in result.categories]
    lines += ["", "## Solver runs"]
    lines += [f"- {r.module}: {r.status} ({r.duration_ms:.1f} ms) — {r.detail}" for r in result.runs]
    lines += ["", "## Findings"]
    lines += [f"- **{f.title}:** `{f.value}` — confidence {f.confidence:.0%}, {'verified' if f.verified else 'candidate'}; {f.explanation}" for f in result.findings] or ["- No candidate solutions found."]
    lines += ["", "## Warnings"] + ([f"- {w}" for w in result.warnings] or ["- None."])
    lines += ["", "## Recommended next steps"] + ([f"- {s}" for s in result.next_steps] or ["- Review candidate outputs against the challenge prompt."])
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return md_path, json_path
