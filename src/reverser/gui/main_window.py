from __future__ import annotations

import json
from pathlib import Path

from reverser.analysis.exporters.json_exporter import export_json
from reverser.analysis.exporters.markdown_exporter import export_markdown
from reverser.gui.worker import run_analysis
from reverser.models import AnalysisReport


def launch() -> int:
    try:
        from PySide6.QtCore import QMimeData, QObject, QRunnable, Qt, QThreadPool, Signal
        from PySide6.QtWidgets import (
            QApplication,
            QFileDialog,
            QHBoxLayout,
            QLabel,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QPlainTextEdit,
            QSpinBox,
            QSplitter,
            QVBoxLayout,
            QWidget,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "PySide6 is not installed. Install it with `python -m pip install -e .[gui]`."
        ) from exc

    class WorkerSignals(QObject):
        finished = Signal(object)
        failed = Signal(str)

    class AnalysisTask(QRunnable):
        def __init__(self, target: str, max_strings: int) -> None:
            super().__init__()
            self.target = target
            self.max_strings = max_strings
            self.signals = WorkerSignals()

        def run(self) -> None:
            try:
                report = run_analysis(self.target, max_strings=self.max_strings)
            except Exception as exc:
                self.signals.failed.emit(str(exc))
                return
            self.signals.finished.emit(report)

    class DropPanel(QLabel):
        def __init__(self, on_path_selected) -> None:
            super().__init__()
            self.on_path_selected = on_path_selected
            self.setAcceptDrops(True)
            self.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.setWordWrap(True)
            self.setStyleSheet(
                """
                QLabel {
                    border: 2px dashed #2563eb;
                    border-radius: 16px;
                    padding: 34px;
                    font-size: 18px;
                    font-weight: 600;
                    background: #0f172a;
                    color: #e2e8f0;
                }
                """
            )
            self.setText(
                "Drop a file or game folder here\n\n"
                "Inspect hashes, strings, archives, PE headers, and engine markers."
            )

        def dragEnterEvent(self, event) -> None:  # type: ignore[override]
            mime_data: QMimeData = event.mimeData()
            if mime_data.hasUrls():
                event.acceptProposedAction()

        def dropEvent(self, event) -> None:  # type: ignore[override]
            mime_data: QMimeData = event.mimeData()
            if not mime_data.hasUrls():
                return
            first = mime_data.urls()[0].toLocalFile()
            if first:
                self.on_path_selected(first)
                event.acceptProposedAction()

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.thread_pool = QThreadPool()
            self.current_path: str | None = None
            self.current_report: AnalysisReport | None = None
            self.setWindowTitle("Reverser Workbench")
            self.resize(1320, 820)
            self._build_ui()

        def _build_ui(self) -> None:
            root = QWidget()
            root.setStyleSheet(
                """
                QWidget {
                    background: #f8fafc;
                    color: #0f172a;
                }
                QPushButton {
                    background: #0f172a;
                    color: #f8fafc;
                    padding: 10px 14px;
                    border-radius: 10px;
                    font-weight: 600;
                }
                QPushButton:disabled {
                    background: #94a3b8;
                }
                QPlainTextEdit {
                    background: #e2e8f0;
                    border: 1px solid #cbd5e1;
                    border-radius: 12px;
                    padding: 8px;
                }
                """
            )
            self.setCentralWidget(root)
            outer = QVBoxLayout(root)
            outer.setContentsMargins(18, 18, 18, 18)
            outer.setSpacing(14)

            header = QLabel("Authorized Binary and Game Asset Analysis")
            header.setStyleSheet("font-size: 28px; font-weight: 700; color: #0f172a;")
            outer.addWidget(header)

            subheader = QLabel(
                "Desktop UI for the same structured engine used by the headless CLI, so humans and AI see the same report."
            )
            subheader.setWordWrap(True)
            subheader.setStyleSheet("color: #334155; font-size: 14px;")
            outer.addWidget(subheader)

            controls = QHBoxLayout()
            self.pick_button = QPushButton("Choose Target")
            self.pick_button.clicked.connect(self._pick_target)
            controls.addWidget(self.pick_button)

            self.analyze_button = QPushButton("Analyze")
            self.analyze_button.clicked.connect(self._start_analysis)
            self.analyze_button.setEnabled(False)
            controls.addWidget(self.analyze_button)

            controls.addWidget(QLabel("Max Strings"))
            self.max_strings = QSpinBox()
            self.max_strings.setRange(25, 5000)
            self.max_strings.setValue(200)
            controls.addWidget(self.max_strings)

            self.export_json_button = QPushButton("Export JSON")
            self.export_json_button.clicked.connect(self._export_json)
            self.export_json_button.setEnabled(False)
            controls.addWidget(self.export_json_button)

            self.export_md_button = QPushButton("Export Markdown")
            self.export_md_button.clicked.connect(self._export_markdown)
            self.export_md_button.setEnabled(False)
            controls.addWidget(self.export_md_button)
            controls.addStretch(1)
            outer.addLayout(controls)

            splitter = QSplitter(Qt.Orientation.Horizontal)
            outer.addWidget(splitter, 1)

            left = QWidget()
            left_layout = QVBoxLayout(left)
            left_layout.setContentsMargins(0, 0, 0, 0)
            self.path_label = QLabel("No target selected")
            self.path_label.setWordWrap(True)
            self.path_label.setStyleSheet("font-size: 13px; color: #475569;")
            left_layout.addWidget(self.path_label)
            self.drop_panel = DropPanel(self._set_target)
            left_layout.addWidget(self.drop_panel, 1)

            right = QWidget()
            right_layout = QVBoxLayout(right)
            right_layout.setContentsMargins(0, 0, 0, 0)
            self.summary = QPlainTextEdit()
            self.summary.setReadOnly(True)
            self.summary.setPlaceholderText("Structured summary will appear here.")
            right_layout.addWidget(self.summary, 1)
            self.raw = QPlainTextEdit()
            self.raw.setReadOnly(True)
            self.raw.setPlaceholderText("Raw JSON will appear here.")
            right_layout.addWidget(self.raw, 1)

            splitter.addWidget(left)
            splitter.addWidget(right)
            splitter.setSizes([420, 900])

        def _pick_target(self) -> None:
            chosen = QFileDialog.getExistingDirectory(self, "Choose a folder")
            if not chosen:
                chosen, _ = QFileDialog.getOpenFileName(self, "Choose a file")
            if chosen:
                self._set_target(chosen)

        def _set_target(self, path: str) -> None:
            self.current_path = path
            self.path_label.setText(f"Selected target:\n{path}")
            self.analyze_button.setEnabled(True)

        def _start_analysis(self) -> None:
            if not self.current_path:
                return
            self.summary.setPlainText("Running analysis...")
            self.raw.clear()
            self.analyze_button.setEnabled(False)

            task = AnalysisTask(self.current_path, self.max_strings.value())
            task.signals.finished.connect(self._analysis_finished)
            task.signals.failed.connect(self._analysis_failed)
            self.thread_pool.start(task)

        def _analysis_finished(self, report: AnalysisReport) -> None:
            self.current_report = report
            self.analyze_button.setEnabled(True)
            self.export_json_button.setEnabled(True)
            self.export_md_button.setEnabled(True)
            self.summary.setPlainText(_report_summary(report))
            self.raw.setPlainText(json.dumps(report.to_dict(), indent=2))

        def _analysis_failed(self, message: str) -> None:
            self.analyze_button.setEnabled(True)
            QMessageBox.critical(self, "Analysis failed", message)

        def _export_json(self) -> None:
            if not self.current_report:
                return
            destination, _ = QFileDialog.getSaveFileName(self, "Export JSON", "report.json", "JSON Files (*.json)")
            if destination:
                export_json(self.current_report, Path(destination))

        def _export_markdown(self) -> None:
            if not self.current_report:
                return
            destination, _ = QFileDialog.getSaveFileName(
                self, "Export Markdown", "report.md", "Markdown Files (*.md)"
            )
            if destination:
                export_markdown(self.current_report, Path(destination))

    def _report_summary(report: AnalysisReport) -> str:
        lines = [
            f"Target: {report.target.path}",
            f"Kind: {report.target.kind}",
            f"Size: {report.target.size_bytes} bytes",
            f"Analyzers: {', '.join(report.analyzers_run) or 'none'}",
            "",
        ]
        if report.findings:
            lines.append("Findings:")
            for finding in report.findings:
                lines.append(f"- [{finding.severity.upper()}] {finding.title}: {finding.summary}")
            lines.append("")
        for section_name, payload in report.sections.items():
            lines.append(f"{section_name.replace('_', ' ').title()}:")
            lines.append(json.dumps(payload, indent=2))
            lines.append("")
        if report.warnings:
            lines.append("Warnings:")
            lines.extend(f"- {item}" for item in report.warnings)
        if report.errors:
            lines.append("Errors:")
            lines.extend(f"- {item}" for item in report.errors)
        return "\n".join(lines)

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()
