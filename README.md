# CTF Forge

CTF Forge is an offline-first Windows desktop application for analyzing challenge text. The current functional core validates text input, hashes it, classifies likely categories with explainable rules, selects bounded text transformations, ranks plaintext candidates using common-word and letter-bigram evidence, performs single-byte XOR checks on explicit hex input, inspects simple RSA parameter sets, detects flag-shaped candidates, and writes Markdown and JSON reports. Candidate ranking scores are heuristics, not calibrated probabilities, and candidates remain unverified unless a separate verification step is implemented. Challenge content is data: the program does not execute supplied commands or source code, run binaries, or contact external systems.

## Requirements and setup

Python 3.10 or newer is required. The current Windows environment uses Python 3.14.3. Install and run from the repository root:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
python main.py
```

PySide6 is required for the GUI. The analysis modules use the Python standard library. To install test and packaging tools, run `python -m pip install -e '.[dev]'`.

## Tests

Run `python -m pytest`. The suite covers the text-file pipeline, Caesar, ROT13, Base64, hex, nested decoding, single-byte XOR, toy RSA, flag candidates, unknown input, duplicate suppression, cancellation, timeouts, malformed/binary files, and size/depth limits.

## Windows executable

Run `build_exe.ps1` from PowerShell or `build_exe.bat` from Command Prompt. Both scripts create/reuse the project `.venv`, install `.[dev]`, and build a directory distribution at `dist\CTF-Forge\CTF-Forge.exe`. The executable has no console in normal GUI mode. A successful build and packaged diagnostic run are recorded in `IMPLEMENTATION_STATUS.md`; the window process started and remained responsive, though this environment could not provide a native-window screenshot.

For a console diagnostic run that uses the same file pipeline and report writer without opening the GUI, run `dist\CTF-Forge\CTF-Forge.exe --analyze path\to\challenge.txt`.

## Current scope and limitations

Implemented: desktop tabs for dashboard, challenge input, analysis console, report history, and non-persistent workspace settings; file browsing and pasted text; asynchronous analysis with cancellation checks between bounded solver operations; safe UTF-8/common Windows text reading with a 2 MiB cap; SHA-256 input identity; rule-based category hypotheses and manual category override; strict Base64/Base32/hex/binary/URL decoding; ROT13, ROT47, Atbash, and bounded Caesar candidates; nested decoding up to depth 3; single-byte XOR testing for explicit hex blocks; labeled small-RSA parameter extraction and bounded trial factoring; candidate ranking based on common words and bigrams; unverified flag candidate detection; Markdown/JSON reports; report reopen/delete/Markdown export.

Not implemented yet: persistent settings, image/PCAP/archive/PE analysis, repeating-key/Vigenere/substitution analysis, hash identification or wordlist verification, optional Z3/Capstone/pefile integrations, remote/local AI, CSV output, SQLite history, stage-level progress details, or rich structured error logs. The GUI accepts text files and pasted text; only text is parsed. RSA parsing is limited to explicit `n`, `e`, and `c`/`ciphertext` decimal labels, and trial division is bounded. Timeouts are checked between solver operations rather than interrupting an individual Python operation. Candidate scores are heuristic rankings, and flags are never verified by format alone.

By default, reports are stored in `%LOCALAPPDATA%\CTF Forge\workspace` (or the user's local AppData fallback), not beside the installed executable. Users may set a different workspace in the GUI for the current run; settings are not persisted. Reports use `analysis-<input-hash-prefix>.md` and `.json`. Avoid putting secrets in challenge descriptions; input text itself is not copied into reports, but derived findings may contain recovered plaintext.
