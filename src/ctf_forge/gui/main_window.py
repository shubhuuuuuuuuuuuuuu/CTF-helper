from __future__ import annotations
import json
from pathlib import Path
from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QProgressBar, QTabWidget, QTextEdit, QVBoxLayout, QWidget, QComboBox, QListWidget, QSplitter)
from ..core.orchestrator import analyze_file, analyze_text
from ..core.report_generator import write_reports
from ..core.input_loader import load_text

class Worker(QThread):
    completed = Signal(object, object)
    failed = Signal(str)
    def __init__(self, text, path, name, workspace, category):
        super().__init__(); self.text=text; self.path=path; self.name=name; self.workspace=workspace; self.category=category
    def run(self):
        try:
            cancelled = lambda: self.isInterruptionRequested()
            result=analyze_file(self.path,self.name,cancelled,self.category) if self.path else analyze_text(self.text,self.name,cancel=cancelled,category_override=self.category)
            reports=write_reports(result,self.workspace); self.completed.emit(result,reports)
        except Exception as exc: self.failed.emit(str(exc))

class MainWindow(QMainWindow):
    def __init__(self, workspace: Path):
        super().__init__(); self.workspace=workspace; self.workspace.mkdir(parents=True,exist_ok=True)
        self.setWindowTitle("CTF Forge — Offline Challenge Analyzer"); self.resize(1120,760)
        self.setStyleSheet("QMainWindow,QWidget{background:#111820;color:#e5edf5;font-size:13px} QLineEdit,QTextEdit,QComboBox,QListWidget{background:#18232e;border:1px solid #314252;border-radius:5px;padding:7px} QPushButton{background:#167c80;color:white;border:0;border-radius:5px;padding:9px 16px} QPushButton:hover{background:#20999b} QTabBar::tab{padding:10px 18px;background:#18232e} QTabBar::tab:selected{background:#167c80}")
        self.tabs=QTabWidget(); self.tabs.addTab(self.dashboard(),"Dashboard"); self.tabs.addTab(self.input_page(),"Challenge Input"); self.tabs.addTab(self.console_page(),"Analysis Console"); self.tabs.addTab(self.history_page(),"History"); self.tabs.addTab(self.settings_page(),"Settings"); self.setCentralWidget(self.tabs); self.worker=None; self.last_result=None; self.loaded_file_path=None; self.loaded_file_text=None; self.refresh_history()
    def dashboard(self):
        page=QWidget(); l=QVBoxLayout(page); title=QLabel("CTF FORGE"); title.setStyleSheet("font-size:28px;font-weight:bold;color:#71e0d3"); l.addWidget(title); l.addWidget(QLabel("Offline-first analysis for authorized CTF challenges and learning labs.")); self.stats=QLabel("No completed analyses in this workspace."); l.addWidget(self.stats); l.addWidget(QLabel("Local modules: safe input validation, category heuristics, encoding decoders, Caesar/Atbash, flag candidate detection, and reproducible reports.")); l.addWidget(QLabel("Challenge commands and code remain inert. No network activity or binary execution is performed.")); l.addStretch(); return page
    def input_page(self):
        page=QWidget(); l=QVBoxLayout(page); form=QFormLayout(); self.name=QLineEdit("Untitled challenge"); self.category=QComboBox(); self.category.addItems(["Auto detect","Cryptography","Classical ciphers","Encoding and decoding","Forensics","Web security","Reverse engineering","Other"]); form.addRow("Challenge name",self.name); form.addRow("Category override",self.category); l.addLayout(form)
        row=QHBoxLayout(); self.path=QLineEdit(); self.path.setPlaceholderText("Optional .txt file path"); browse=QPushButton("Browse…"); browse.clicked.connect(self.browse); row.addWidget(self.path); row.addWidget(browse); l.addLayout(row)
        self.editor=QTextEdit(); self.editor.setPlaceholderText("Paste challenge text or select a .txt file. Embedded commands remain inert."); l.addWidget(self.editor,1)
        actions=QHBoxLayout(); self.start_btn=QPushButton("Start Analysis"); self.cancel_btn=QPushButton("Cancel"); reset=QPushButton("Reset"); self.start_btn.clicked.connect(self.start); self.cancel_btn.clicked.connect(self.cancel); reset.clicked.connect(self.reset); actions.addWidget(self.start_btn); actions.addWidget(self.cancel_btn); actions.addWidget(reset); l.addLayout(actions); self.progress=QProgressBar(); self.progress.setRange(0,0); self.progress.hide(); l.addWidget(self.progress); return page
    def console_page(self):
        page=QWidget(); l=QVBoxLayout(page); split=QSplitter(); self.console=QTextEdit(); self.console.setReadOnly(True); self.findings=QListWidget(); split.addWidget(self.console); split.addWidget(self.findings); l.addWidget(split); export=QPushButton("Export Report"); export.clicked.connect(self.export); l.addWidget(export); return page
    def history_page(self):
        page=QWidget(); l=QVBoxLayout(page); self.history=QListWidget(); l.addWidget(self.history); row=QHBoxLayout(); open_btn=QPushButton("Open Report"); delete=QPushButton("Delete Session"); open_btn.clicked.connect(self.open_history); delete.clicked.connect(self.delete_history); row.addWidget(open_btn); row.addWidget(delete); l.addLayout(row); return page
    def settings_page(self):
        page=QWidget(); l=QVBoxLayout(page); l.addWidget(QLabel("Session workspace")); self.workspace_field=QLineEdit(str(self.workspace)); l.addWidget(self.workspace_field); l.addWidget(QLabel("Defaults: 2 MiB input limit; at most 250 candidate transformations; no remote AI, network activity, command execution, or binary execution.")); l.addWidget(QLabel("Custom flag prefixes and advanced optional analyzers are not yet available.")); l.addStretch(); return page
    def browse(self):
        path,_=QFileDialog.getOpenFileName(self,"Choose challenge text","","Text files (*.txt);;All files (*)")
        if path:
            self.path.setText(path)
            try:
                content, _ = load_text(path)
                self.editor.setPlainText(content)
                self.loaded_file_path = Path(path).resolve()
                self.loaded_file_text = content
            except (OSError,UnicodeError) as exc: QMessageBox.warning(self,"Read error",str(exc))
            except ValueError as exc: QMessageBox.warning(self,"Input rejected",str(exc))
    def start(self):
        path=self.path.text().strip(); text=self.editor.toPlainText()
        if not path and not text.strip(): QMessageBox.information(self,"Input required","Select a text file or enter challenge text."); return
        if path and self.loaded_file_path and Path(path).resolve()==self.loaded_file_path and text != self.loaded_file_text:
            path = ""  # Analyze the user's editor changes instead of silently rereading the old file.
        try:
            self.workspace=Path(self.workspace_field.text()).expanduser(); self.workspace.mkdir(parents=True,exist_ok=True)
        except OSError as exc:
            QMessageBox.critical(self,"Workspace error",str(exc)); return
        self.progress.show(); self.start_btn.setEnabled(False); self.console.append("Starting safe offline analysis…")
        self.worker=Worker(text,path,self.name.text().strip() or "Untitled challenge",self.workspace,self.category.currentText()); self.worker.completed.connect(self.finished); self.worker.failed.connect(self.error); self.worker.start()
    def cancel(self):
        if self.worker and self.worker.isRunning(): self.worker.requestInterruption(); self.console.append("Cancellation requested; bounded current analysis stage will finish shortly.")
    def finished(self,result,reports):
        scheduler = next((run for run in result.runs if run.module == "Input validation and strategy scheduler"), None)
        status = scheduler.status if scheduler else "completed with warnings"
        display_status = {"completed": "Completed", "cancelled": "Cancelled (partial results)", "timed out": "Timed out (partial results)"}.get(status, "Completed with warnings")
        self.last_result=result; self.progress.hide(); self.start_btn.setEnabled(True); self.console.clear(); self.findings.clear(); self.console.append(f"{display_status}: {result.challenge_name}\nSHA-256: {result.input_sha256}\n\nCategories:\n"+"\n".join(f"• {c['category']} — {c['confidence']:.0%}: {', '.join(c['evidence'])}" for c in result.categories)); self.console.append("\nSolvers:\n"+"\n".join(f"• {r.module}: {r.status} ({r.duration_ms:.1f} ms)" for r in result.runs))
        for f in result.findings: self.findings.addItem(f"[{f.confidence:.0%}] {f.title}: {f.value[:220]}")
        self.console.append("\nWarnings:\n"+("\n".join(result.warnings) or "None")+f"\n\nReports saved:\n{reports[0]}\n{reports[1]}"); self.tabs.setCurrentIndex(2); self.refresh_history(); self.stats.setText(f"Reports in workspace: {len(list(self.workspace.glob('analysis-*.json')))}    Latest status: {display_status}")
    def error(self,message):
        self.progress.hide(); self.start_btn.setEnabled(True); self.console.append("ERROR: "+message); QMessageBox.critical(self,"Analysis failed",message)
    def reset(self): self.name.setText("Untitled challenge"); self.path.clear(); self.editor.clear(); self.loaded_file_path=None; self.loaded_file_text=None; self.findings.clear(); self.console.clear()
    def export(self):
        if not self.last_result: QMessageBox.information(self,"No report","Run an analysis first."); return
        path,_=QFileDialog.getSaveFileName(self,"Export Markdown report",str(self.workspace),"Markdown (*.md)")
        if path: Path(path).write_text((self.workspace/f"analysis-{self.last_result.input_sha256[:12]}.md").read_text(encoding="utf-8"),encoding="utf-8")
    def refresh_history(self):
        if not hasattr(self,"history"): return
        self.history.clear()
        for p in sorted(self.workspace.glob("analysis-*.json"),key=lambda q:q.stat().st_mtime,reverse=True): self.history.addItem(p.name)
    def open_history(self):
        item=self.history.currentItem()
        if item: self.console.setPlainText(json.dumps(json.loads((self.workspace/item.text()).read_text(encoding="utf-8")),indent=2)); self.tabs.setCurrentIndex(2)
    def delete_history(self):
        item=self.history.currentItem()
        if not item: return
        p=self.workspace/item.text()
        if p.parent.resolve()==self.workspace.resolve() and p.name.startswith("analysis-"): p.unlink(missing_ok=True); p.with_suffix(".md").unlink(missing_ok=True); self.refresh_history()
