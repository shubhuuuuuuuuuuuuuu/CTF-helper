from __future__ import annotations
import sys
import os
from pathlib import Path

from .core.orchestrator import analyze_file
from .core.report_generator import write_reports


def default_workspace_dir() -> Path:
    local_appdata = os.environ.get("LOCALAPPDATA")
    data_root = Path(local_appdata) if local_appdata else Path.home() / "AppData" / "Local"
    return data_root / "CTF Forge" / "workspace"


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        if len(arguments) != 2 or arguments[0] != "--analyze":
            print("Usage: CTF-Forge.exe [--analyze challenge.txt]")
            return 2
        try:
            result = analyze_file(arguments[1])
            markdown, machine = write_reports(result, default_workspace_dir())
            print(f"Analysis complete.\nMarkdown: {markdown}\nJSON: {machine}")
            return 0
        except Exception as exc:
            print(f"Analysis failed: {exc}", file=sys.stderr)
            return 1
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("CTF Forge GUI requires PySide6. Install dependencies with: python -m pip install -r requirements.txt")
        return 2
    from .gui.main_window import MainWindow
    app = QApplication(sys.argv)
    app.setApplicationName("CTF Forge")
    window = MainWindow(default_workspace_dir())
    window.show()
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())
