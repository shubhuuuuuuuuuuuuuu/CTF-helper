# Implementation status

## Audit

- The GUI invokes `analyze_file`/`analyze_text` in a `QThread`, renders the returned categories/findings/runs, and writes reports from that same result.
- The initial README overstated available solvers: the single-byte XOR and RSA helpers were not previously called from the orchestrator. They are now connected for explicit hex input and explicit decimal RSA `n`, `e`, `c`/`ciphertext` labels.
- Nested decoding, solver timeout status, duplicate-output suppression, and candidate evidence were missing or incomplete. The pipeline now bounds transformations/depth/time and checks cancellation between operations.
- Candidate scoring previously rewarded common-letter frequency too heavily. It now includes common-word coverage and letter-bigram evidence. Scores are heuristic rankings, not calibrated probabilities.
- Flag-shaped strings remain unverified. The detector now requires token-like flag payload characters to avoid punctuation noise produced by transformations.
- GUI file edits were previously ignored because the worker reread the selected file. Modified editor content now runs as text. File browsing uses the same bounded loader as analysis.
- The app previously defaulted reports to the current working directory, which could be read-only for a packaged install. The default is now `%LOCALAPPDATA%\\CTF Forge\\workspace` (with a user-local fallback); custom workspace values apply per run and are not saved.
- The old build scripts used a global Python interpreter. They now use/create `.venv` and install the project's `.[dev]` extra before building.

## Windows verification

- Python: 3.14.3; project-local `.venv` created.
- Installed in `.venv`: PySide6 6.12.0, pytest 9.1.1, PyInstaller 6.22.3 and project editable package.
- `python -m compileall -q src tests main.py`: passed.
- `python -m pytest -q`: 31 passed.
- Final PyInstaller 6.22.3 build from `app.spec`: succeeded. Directory distribution contains 206 files (119,178,499 bytes); `CTF-Forge.exe` is 2,143,102 bytes.
- Final packaged diagnostic was run with temporary `.txt` files for Base64-wrapped Caesar ciphertext and toy RSA parameters. Both invocations exited 0, the reports contained the expected plaintext and RSA candidate, and both Markdown/JSON report pairs were written under a temporary `%LOCALAPPDATA%\\CTF Forge\\workspace` directory.
- Final normal packaged GUI process starts and Windows reports `Responding=True`; its user-local workspace directory and bundled `qwindows.dll` are present. The GUI smoke test also creates the PySide window, drives a real file through the worker/pipeline, verifies the rendered finding and both report files, and checks cancelled-result status text.
- The computer-use helper in this environment exposes no native app windows, so I could not capture/inspect the final packaged window visually. The normal process responsiveness and offscreen PySide event-loop test are verified; visual inspection remains a manual check on an interactive desktop.

## Remaining limits

No image, PCAP, archive, PE, hash cracking, Vigenere/repeating-key, substitution, remote/local AI, CSV, or persistent SQLite history modules. RSA extraction expects explicit decimal labels and bounded trial division. The timeout is checked between operations; it cannot preempt a single active Python call. Settings are not persisted. Flag matches and plaintext candidates are not marked verified.
