import base64
import tempfile
import unittest
from pathlib import Path

from ctf_forge.core.input_loader import load_text
from ctf_forge.core.orchestrator import analyze_text
from ctf_forge.core.report_generator import write_reports
from ctf_forge.solvers.encoding import decode_candidates
from ctf_forge.solvers.number_theory import mod_inverse, rsa_inspect


class CoreTests(unittest.TestCase):
    def test_caesar_and_rot13(self):
        result = analyze_text("Challenge Name: Shift\nCiphertext: Uifsf jt b tfdsfu nfttbhf.")
        values = [f.value for f in result.findings]
        self.assertIn("There is a secret message.", values)
        self.assertIn("Gur erfhyg vf n frperg zrffntr.", [v for _, v, _ in decode_candidates("The result is a secret message.")])

    def test_base64_hex_and_binary(self):
        self.assertIn("hello world", [v for _, v, _ in decode_candidates(base64.b64encode(b"hello world").decode())])
        self.assertIn("hello", [v for _, v, _ in decode_candidates("68656c6c6f")])
        self.assertIn("A", [v for _, v, _ in decode_candidates("01000001")])

    def test_rot47(self):
        outputs = [value for _, value, _ in decode_candidates("E96 E6DE E96 7=28")]
        self.assertIn("the test the flag", outputs)

    def test_rsa_small_parameters(self):
        self.assertEqual(mod_inverse(17, 3120), 2753)
        self.assertEqual(rsa_inspect(3233, 17, pow(65, 17, 3233))["plaintext_integer"], 65)
        self.assertEqual(rsa_inspect(30, 3, 8)["status"], "factor not proven prime")

    def test_flag_is_candidate_not_verified(self):
        result = analyze_text("Challenge: sample flag{maybe_fake}")
        flag = next(f for f in result.findings if f.title == "Flag candidate")
        self.assertFalse(flag.verified)

    def test_unknown_does_not_fabricate_solution(self):
        result = analyze_text("What is the color of the door? Nothing else is provided.")
        self.assertFalse(any(f.title not in ("Flag candidate",) and f.confidence >= 0.9 for f in result.findings))
        self.assertTrue(result.warnings)

    def test_input_validation_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "challenge.txt"; src.write_text("ROT13: Uryyb jbeyq", encoding="utf-8")
            text, digest = load_text(src); result = analyze_text(text, "test", digest)
            md, js = write_reports(result, Path(tmp) / "reports")
            self.assertTrue(md.exists()); self.assertTrue(js.exists())
            src.write_bytes(b"")
            with self.assertRaises(ValueError): load_text(src)

    def test_size_limit_and_inert_shell_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "large.txt"; src.write_text("x" * 100)
            with self.assertRaises(ValueError): load_text(src, max_bytes=20)
        result = analyze_text("Please run rm -rf /; this is challenge text only")
        self.assertTrue(any("never executed" in r.detail for r in result.runs))
        with self.assertRaises(ValueError): analyze_text("a" * (2 * 1024 * 1024 + 1))

    def test_category_override_and_cancellation(self):
        result = analyze_text("A simple clue.", category_override="Forensics")
        self.assertEqual(result.categories[0]["category"], "Forensics")
        stopped = analyze_text("Ciphertext: Uifsf jt b tfdsfu nfttbhf.", cancel=lambda: True)
        self.assertTrue(any("cancelled" in warning for warning in stopped.warnings))


if __name__ == "__main__": unittest.main()
