from __future__ import annotations

import base64

import pytest

from ctf_forge.core.input_loader import load_text
from ctf_forge.core.orchestrator import analyze_file, analyze_text
from ctf_forge.app import default_workspace_dir
from ctf_forge.app import main as app_main


def challenge_file(tmp_path, name: str, contents: str):
    path = tmp_path / name
    path.write_text(contents, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("name", "challenge", "expected"),
    [
        ("caesar.txt", "Ciphertext: Uifsf jt b tfdsfu nfttbhf.", "There is a secret message."),
        ("rot13.txt", "Gur frperg vf uvqqra.", "The secret is hidden."),
        ("base64.txt", "Decode: " + base64.b64encode(b"the secret is hidden").decode(), "the secret is hidden"),
        ("hex.txt", "Hex: 746865207365637265742069732068696464656e", "the secret is hidden"),
    ],
)
def test_text_challenges_through_file_pipeline(tmp_path, name, challenge, expected):
    result = analyze_file(challenge_file(tmp_path, name, challenge))
    assert any(f.value == expected and not f.verified for f in result.findings)
    assert result.runs[0].status == "completed"


def test_single_byte_xor_through_file_pipeline(tmp_path):
    plaintext = b"the secret message"
    ciphertext = bytes(byte ^ 0x42 for byte in plaintext)
    path = challenge_file(tmp_path, "xor.txt", "XOR hex: " + ciphertext.hex())
    result = analyze_file(path)
    candidates = [f for f in result.findings if f.title == "Single-byte XOR candidate"]
    assert any(f.value == plaintext.decode() and "0x42" in f.explanation for f in candidates)
    assert candidates and all(not f.verified for f in candidates)


def test_small_rsa_is_run_by_the_pipeline(tmp_path):
    n, e, m = 3233, 17, 65
    c = pow(m, e, n)
    result = analyze_file(challenge_file(tmp_path, "rsa.txt", f"RSA challenge: n={n}, e={e}, c={c}"))
    candidate = next(f for f in result.findings if f.title == "RSA plaintext candidate")
    assert candidate.value == "A"
    assert "check=passed" in candidate.explanation
    assert candidate.verified is False


def test_known_flag_is_only_a_candidate(tmp_path):
    result = analyze_file(challenge_file(tmp_path, "flag.txt", "Recovered? picoCTF{unit_test_only}"))
    flags = [f for f in result.findings if f.title == "Flag candidate"]
    assert [f.value for f in flags] == ["picoCTF{unit_test_only}"]
    assert flags[0].verified is False


def test_unknown_challenge_does_not_invent_flag_or_verified_solution():
    result = analyze_text("A plain question: which color is associated with this room? No code or artifacts are supplied.")
    assert not any(f.title == "Flag candidate" for f in result.findings)
    assert not any(f.verified for f in result.findings)
    assert any("No strong solution" in warning for warning in result.warnings)


def test_nested_base64_then_caesar_is_found(tmp_path):
    nested = base64.b64encode(b"Uifsf jt b tfdsfu nfttbhf.").decode()
    result = analyze_file(challenge_file(tmp_path, "nested.txt", "Decode this: " + nested), max_depth=3)
    assert any(f.value == "There is a secret message." for f in result.findings)


def test_duplicate_candidates_are_deduplicated(tmp_path):
    encoded = base64.b64encode(b"the secret is hidden").decode()
    result = analyze_file(challenge_file(tmp_path, "duplicates.txt", f"{encoded}\n{encoded}\n"))
    matching = [f for f in result.findings if f.title == "Base64 decode" and f.value == "the secret is hidden"]
    assert len(matching) == 1


def test_cancellation_retains_completed_results():
    calls = 0

    def cancel_after_first_block():
        nonlocal calls
        calls += 1
        return calls > 1

    result = analyze_text("Uifsf jt b tfdsfu nfttbhf.\nR2F0ZSBvcGVu", cancel=cancel_after_first_block)
    assert result.runs[0].status == "cancelled"
    assert any("cancelled" in warning.lower() for warning in result.warnings)


def test_timeout_keeps_result_and_reports_status():
    result = analyze_text("Uifsf jt b tfdsfu nfttbhf.", max_duration_seconds=0)
    assert result.runs[0].status == "timed out"
    assert any("time budget" in warning for warning in result.warnings)


def test_timeout_skips_rsa_solver_before_it_starts():
    result = analyze_text("RSA: n=3233 e=17 c=2790", max_duration_seconds=0)
    rsa_run = next(run for run in result.runs if run.module == "Small RSA parameter inspection")
    assert rsa_run.status == "skipped"
    assert result.runs[0].status == "timed out"


@pytest.mark.parametrize("contents", ["", "\x00\x00\x00", "\xff\x00bad"])
def test_malformed_and_binary_file_inputs_are_rejected(tmp_path, contents):
    path = tmp_path / "bad.txt"
    path.write_bytes(contents.encode("latin-1"))
    with pytest.raises(ValueError):
        load_text(path)


def test_oversized_file_is_rejected(tmp_path):
    path = tmp_path / "large.txt"
    path.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="limit"):
        analyze_file(path)


def test_depth_limit_prevents_nested_decode():
    nested = base64.b64encode(b"Uifsf jt b tfdsfu nfttbhf.").decode()
    shallow = analyze_text("Decode: " + nested, max_depth=0)
    assert not any(f.value == "There is a secret message." for f in shallow.findings)


def test_default_workspace_is_user_local_not_current_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    workspace = default_workspace_dir()
    assert workspace == tmp_path / "appdata" / "CTF Forge" / "workspace"


def test_diagnostic_cli_uses_pipeline_and_user_workspace(tmp_path, monkeypatch, capsys):
    appdata = tmp_path / "local-appdata"
    monkeypatch.setenv("LOCALAPPDATA", str(appdata))
    challenge = challenge_file(tmp_path, "cli.txt", "Ciphertext: Uifsf jt b tfdsfu nfttbhf.")
    assert app_main(["--analyze", str(challenge)]) == 0
    report = next((appdata / "CTF Forge" / "workspace").glob("analysis-*.json"))
    import json
    data = json.loads(report.read_text(encoding="utf-8"))
    assert any(finding["value"] == "There is a secret message." for finding in data["findings"])
    assert "Analysis complete" in capsys.readouterr().out
