from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from ctf_forge.gui.main_window import MainWindow
from ctf_forge.core.orchestrator import analyze_text
from ctf_forge.core.report_generator import write_reports


def test_window_runs_real_file_analysis_and_renders_results(tmp_path):
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "user-data" / "workspace"
    challenge = tmp_path / "caesar.txt"
    challenge.write_text("Ciphertext: Uifsf jt b tfdsfu nfttbhf.", encoding="utf-8")

    window = MainWindow(workspace)
    window.show()
    app.processEvents()
    assert window.tabs.count() == 5
    window.name.setText("GUI smoke")
    window.path.setText(str(challenge))
    loop = QEventLoop()
    window.start()
    worker = window.worker
    worker.finished.connect(loop.quit)
    QTimer.singleShot(10000, loop.quit)
    loop.exec()
    worker.wait(2000)

    assert window.last_result is not None
    assert any(f.value == "There is a secret message." for f in window.last_result.findings)
    assert any("There is a secret message." in window.findings.item(i).text() for i in range(window.findings.count()))
    assert list(workspace.glob("analysis-*.md"))
    assert list(workspace.glob("analysis-*.json"))
    assert window.history.count() == 1
    window.close()


def test_cancelled_result_is_not_labeled_completed(tmp_path):
    app = QApplication.instance() or QApplication([])
    workspace = tmp_path / "workspace"
    window = MainWindow(workspace)
    result = analyze_text("Ciphertext: Uifsf jt b tfdsfu nfttbhf.", cancel=lambda: True)
    reports = write_reports(result, workspace)
    window.finished(result, reports)
    assert window.console.toPlainText().startswith("Cancelled (partial results):")
    assert window.stats.text().endswith("Cancelled (partial results)")
    window.close()
