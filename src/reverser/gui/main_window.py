from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from reverser.analysis.exporters.index_exporter import export_scan_json
from reverser.analysis.exporters.json_exporter import export_json
from reverser.analysis.exporters.markdown_exporter import export_markdown
from reverser.gui.worker import run_analysis, run_scan
from reverser.models import AnalysisReport, BatchScanIndex


def launch() -> int:
    try:
        from PySide6.QtCore import QEvent, QMimeData, QObject, QRunnable, Qt, QThreadPool, Signal
        from PySide6.QtGui import QPalette
        from PySide6.QtWidgets import (
            QAbstractSpinBox,
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

    @dataclass(frozen=True)
    class ThemePalette:
        window: str
        panel: str
        panel_alt: str
        text: str
        muted_text: str
        border: str
        border_strong: str
        accent: str
        accent_hover: str
        accent_pressed: str
        accent_soft: str
        button_text: str
        disabled_bg: str
        disabled_text: str
        input_bg: str
        input_text: str
        input_border: str
        input_button_bg: str
        input_button_hover: str
        selection_bg: str
        selection_text: str
        drop_bg: str
        drop_border: str
        splitter: str

    LIGHT_THEME = ThemePalette(
        window="#f3f7fb",
        panel="#ffffff",
        panel_alt="#e7eef7",
        text="#102033",
        muted_text="#516176",
        border="#c5d1df",
        border_strong="#9fb2c8",
        accent="#1d4ed8",
        accent_hover="#1e40af",
        accent_pressed="#1e3a8a",
        accent_soft="#dbeafe",
        button_text="#f8fbff",
        disabled_bg="#d7e0ea",
        disabled_text="#76879a",
        input_bg="#f8fbff",
        input_text="#102033",
        input_border="#bcc9d8",
        input_button_bg="#e2eaf4",
        input_button_hover="#d3dfec",
        selection_bg="#bfdbfe",
        selection_text="#0f172a",
        drop_bg="#edf4ff",
        drop_border="#2563eb",
        splitter="#d6e0eb",
    )
    DARK_THEME = ThemePalette(
        window="#0b1220",
        panel="#111b2e",
        panel_alt="#18253b",
        text="#e5edf7",
        muted_text="#9eb0c5",
        border="#2c3c54",
        border_strong="#3a4e6b",
        accent="#60a5fa",
        accent_hover="#93c5fd",
        accent_pressed="#3b82f6",
        accent_soft="#15263f",
        button_text="#08111e",
        disabled_bg="#243247",
        disabled_text="#7d8ea4",
        input_bg="#152033",
        input_text="#f3f7fb",
        input_border="#33455f",
        input_button_bg="#203049",
        input_button_hover="#29405f",
        selection_bg="#1d4ed8",
        selection_text="#eff6ff",
        drop_bg="#132238",
        drop_border="#60a5fa",
        splitter="#203049",
    )

    def _detect_color_scheme(app: QApplication) -> str:
        style_hints = app.styleHints()
        if hasattr(style_hints, "colorScheme") and hasattr(Qt, "ColorScheme"):
            color_scheme = style_hints.colorScheme()
            if color_scheme == Qt.ColorScheme.Dark:
                return "dark"
            if color_scheme == Qt.ColorScheme.Light:
                return "light"

        window_color = app.palette().color(QPalette.ColorRole.Window)
        return "dark" if window_color.lightness() < 128 else "light"

    def _theme_for_scheme(scheme: str) -> ThemePalette:
        return DARK_THEME if scheme == "dark" else LIGHT_THEME

    def _build_stylesheet(theme: ThemePalette) -> str:
        return f"""
        QWidget#root {{
            background: {theme.window};
            color: {theme.text};
        }}
        QWidget#leftPane,
        QWidget#rightPane {{
            background: transparent;
        }}
        QLabel#headerLabel {{
            color: {theme.text};
            font-size: 28px;
            font-weight: 700;
        }}
        QLabel#subheaderLabel,
        QLabel#pathLabel,
        QLabel#controlLabel {{
            color: {theme.muted_text};
        }}
        QLabel#subheaderLabel {{
            font-size: 14px;
        }}
        QLabel#pathLabel {{
            font-size: 13px;
        }}
        QPushButton {{
            background: {theme.accent};
            color: {theme.button_text};
            border: 1px solid {theme.accent};
            padding: 10px 14px;
            border-radius: 10px;
            font-weight: 600;
        }}
        QPushButton:hover:enabled {{
            background: {theme.accent_hover};
            border-color: {theme.accent_hover};
        }}
        QPushButton:pressed:enabled {{
            background: {theme.accent_pressed};
            border-color: {theme.accent_pressed};
        }}
        QPushButton:disabled {{
            background: {theme.disabled_bg};
            color: {theme.disabled_text};
            border-color: {theme.disabled_bg};
        }}
        QPlainTextEdit {{
            background: {theme.panel};
            color: {theme.input_text};
            border: 1px solid {theme.border};
            border-radius: 12px;
            padding: 8px;
            selection-background-color: {theme.selection_bg};
            selection-color: {theme.selection_text};
        }}
        QPlainTextEdit[readOnly="true"] {{
            background: {theme.panel_alt};
        }}
        QSpinBox,
        QAbstractSpinBox {{
            background: {theme.input_bg};
            color: {theme.input_text};
            border: 1px solid {theme.input_border};
            border-radius: 10px;
            padding: 6px 8px;
            min-height: 20px;
            selection-background-color: {theme.selection_bg};
            selection-color: {theme.selection_text};
        }}
        QSpinBox:hover,
        QAbstractSpinBox:hover,
        QPlainTextEdit:hover {{
            border-color: {theme.border_strong};
        }}
        QSpinBox:focus,
        QAbstractSpinBox:focus,
        QPlainTextEdit:focus {{
            border-color: {theme.accent};
        }}
        QSpinBox::up-button,
        QSpinBox::down-button,
        QAbstractSpinBox::up-button,
        QAbstractSpinBox::down-button {{
            background: {theme.input_button_bg};
            border-left: 1px solid {theme.input_border};
            width: 20px;
            color: {theme.input_text};
            font-weight: 700;
        }}
        QSpinBox::up-button:hover,
        QSpinBox::down-button:hover,
        QAbstractSpinBox::up-button:hover,
        QAbstractSpinBox::down-button:hover {{
            background: {theme.input_button_hover};
        }}
        QSpinBox::up-arrow,
        QSpinBox::down-arrow,
        QAbstractSpinBox::up-arrow,
        QAbstractSpinBox::down-arrow {{
            width: 9px;
            height: 9px;
        }}
        QSplitter::handle {{
            background: {theme.splitter};
            margin: 8px 0;
            width: 2px;
        }}
        """

    class WorkerSignals(QObject):
        finished = Signal(object)
        failed = Signal(str)

    class AnalysisTask(QRunnable):
        def __init__(self, target: str, max_strings: int, mode: str, max_files: int) -> None:
            super().__init__()
            self.target = target
            self.max_strings = max_strings
            self.mode = mode
            self.max_files = max_files
            self.signals = WorkerSignals()

        def run(self) -> None:
            try:
                if self.mode == "scan":
                    report = run_scan(
                        self.target,
                        max_strings=self.max_strings,
                        max_files=self.max_files,
                    )
                else:
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
            self.setText(
                "Drop a file or game folder here\n\n"
                "Inspect hashes, strings, archives, PE headers, and engine markers."
            )
            self.apply_theme(LIGHT_THEME)

        def apply_theme(self, theme: ThemePalette) -> None:
            self.setStyleSheet(
                f"""
                QLabel {{
                    border: 2px dashed {theme.drop_border};
                    border-radius: 16px;
                    padding: 34px;
                    font-size: 18px;
                    font-weight: 600;
                    background: {theme.drop_bg};
                    color: {theme.text};
                }}
                """
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
            self.current_scan: BatchScanIndex | None = None
            self._active_scheme = "light"
            self.setWindowTitle("Reverser Workbench")
            self.resize(1320, 820)
            self._build_ui()
            self._install_theme_sync()
            self._apply_theme()

        def _build_ui(self) -> None:
            self.root = QWidget()
            self.root.setObjectName("root")
            self.setCentralWidget(self.root)
            outer = QVBoxLayout(self.root)
            outer.setContentsMargins(18, 18, 18, 18)
            outer.setSpacing(14)

            self.header = QLabel("Authorized Binary and Game Asset Analysis")
            self.header.setObjectName("headerLabel")
            outer.addWidget(self.header)

            self.subheader = QLabel(
                "Desktop UI for the same structured engine used by the headless CLI, so humans and AI see the same report."
            )
            self.subheader.setObjectName("subheaderLabel")
            self.subheader.setWordWrap(True)
            outer.addWidget(self.subheader)

            controls = QHBoxLayout()
            self.pick_button = QPushButton("Choose Target")
            self.pick_button.clicked.connect(self._pick_target)
            controls.addWidget(self.pick_button)

            self.analyze_button = QPushButton("Analyze")
            self.analyze_button.clicked.connect(self._start_analysis)
            self.analyze_button.setEnabled(False)
            controls.addWidget(self.analyze_button)

            self.scan_button = QPushButton("Batch Scan Folder")
            self.scan_button.clicked.connect(self._start_scan)
            self.scan_button.setEnabled(False)
            controls.addWidget(self.scan_button)

            self.max_strings_label = QLabel("Max Strings")
            self.max_strings_label.setObjectName("controlLabel")
            controls.addWidget(self.max_strings_label)
            self.max_strings = QSpinBox()
            self.max_strings.setRange(25, 5000)
            self.max_strings.setValue(200)
            self.max_strings.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.PlusMinus)
            controls.addWidget(self.max_strings)

            self.max_files_label = QLabel("Max Files")
            self.max_files_label.setObjectName("controlLabel")
            controls.addWidget(self.max_files_label)
            self.max_files = QSpinBox()
            self.max_files.setRange(10, 5000)
            self.max_files.setValue(250)
            self.max_files.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.PlusMinus)
            controls.addWidget(self.max_files)

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
            left.setObjectName("leftPane")
            left_layout = QVBoxLayout(left)
            left_layout.setContentsMargins(0, 0, 20, 0)
            self.path_label = QLabel("No target selected")
            self.path_label.setObjectName("pathLabel")
            self.path_label.setWordWrap(True)
            left_layout.addWidget(self.path_label)
            self.drop_panel = DropPanel(self._set_target)
            left_layout.addWidget(self.drop_panel, 1)

            right = QWidget()
            right.setObjectName("rightPane")
            right_layout = QVBoxLayout(right)
            right_layout.setContentsMargins(20, 0, 0, 0)
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

        def _install_theme_sync(self) -> None:
            app = QApplication.instance()
            if not app:
                return

            style_hints = app.styleHints()
            if hasattr(style_hints, "colorSchemeChanged"):
                style_hints.colorSchemeChanged.connect(self._apply_theme)

        def _apply_theme(self, *_args) -> None:
            app = QApplication.instance()
            if not app:
                return

            self._active_scheme = _detect_color_scheme(app)
            theme = _theme_for_scheme(self._active_scheme)
            self.root.setStyleSheet(_build_stylesheet(theme))
            self.drop_panel.apply_theme(theme)

        def changeEvent(self, event) -> None:  # type: ignore[override]
            if event.type() in {
                QEvent.Type.ApplicationPaletteChange,
                QEvent.Type.PaletteChange,
                QEvent.Type.StyleChange,
                getattr(QEvent.Type, "ThemeChange", QEvent.Type.None_),
            }:
                self._apply_theme()
            super().changeEvent(event)

        def _pick_target(self) -> None:
            chosen = QFileDialog.getExistingDirectory(self, "Choose a folder")
            if not chosen:
                chosen, _ = QFileDialog.getOpenFileName(self, "Choose a file")
            if chosen:
                self._set_target(chosen)

        def _set_target(self, path: str) -> None:
            self.current_path = path
            self.current_report = None
            self.current_scan = None
            self.path_label.setText(f"Selected target:\n{path}")
            self.analyze_button.setEnabled(True)
            self.scan_button.setEnabled(Path(path).is_dir())

        def _start_analysis(self) -> None:
            if not self.current_path:
                return
            self._begin_work("Running analysis...")

            task = AnalysisTask(self.current_path, self.max_strings.value(), "analyze", self.max_files.value())
            task.signals.finished.connect(self._analysis_finished)
            task.signals.failed.connect(self._analysis_failed)
            self.thread_pool.start(task)

        def _start_scan(self) -> None:
            if not self.current_path:
                return
            self._begin_work("Running batch scan...")

            task = AnalysisTask(self.current_path, self.max_strings.value(), "scan", self.max_files.value())
            task.signals.finished.connect(self._analysis_finished)
            task.signals.failed.connect(self._analysis_failed)
            self.thread_pool.start(task)

        def _begin_work(self, message: str) -> None:
            self.summary.setPlainText(message)
            self.raw.clear()
            self.analyze_button.setEnabled(False)
            self.scan_button.setEnabled(False)
            self.export_json_button.setEnabled(False)
            self.export_md_button.setEnabled(False)

        def _analysis_finished(self, payload: object) -> None:
            self.analyze_button.setEnabled(True)
            self.scan_button.setEnabled(bool(self.current_path and Path(self.current_path).is_dir()))
            self.export_json_button.setEnabled(True)

            if isinstance(payload, BatchScanIndex):
                self.current_scan = payload
                self.current_report = None
                self.export_md_button.setEnabled(False)
                self.summary.setPlainText(_scan_summary(payload))
                self.raw.setPlainText(json.dumps(payload.to_dict(), indent=2))
                return

            report = payload
            if not isinstance(report, AnalysisReport):
                self._analysis_failed("Unexpected analysis payload.")
                return

            self.current_report = report
            self.current_scan = None
            self.export_md_button.setEnabled(True)
            self.summary.setPlainText(_report_summary(report))
            self.raw.setPlainText(json.dumps(report.to_dict(), indent=2))

        def _analysis_failed(self, message: str) -> None:
            self.analyze_button.setEnabled(True)
            self.scan_button.setEnabled(bool(self.current_path and Path(self.current_path).is_dir()))
            QMessageBox.critical(self, "Analysis failed", message)

        def _export_json(self) -> None:
            if not self.current_report and not self.current_scan:
                return
            destination, _ = QFileDialog.getSaveFileName(self, "Export JSON", "report.json", "JSON Files (*.json)")
            if destination:
                if self.current_report:
                    export_json(self.current_report, Path(destination))
                elif self.current_scan:
                    export_scan_json(self.current_scan, Path(destination))

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

    def _scan_summary(index: BatchScanIndex) -> str:
        summary = index.summary
        lines = [
            f"Root: {index.root_path}",
            f"Analyzed files: {summary['entry_count']}",
            f"Skipped files: {summary['skipped_count']}",
            "",
            "Severity counts:",
            json.dumps(summary["severity_counts"], indent=2),
            "",
            "Signature counts:",
            json.dumps(summary["signature_counts"], indent=2),
            "",
        ]
        if summary["engine_counts"]:
            lines.extend(["Engine counts:", json.dumps(summary["engine_counts"], indent=2), ""])

        if index.entries:
            lines.append("Top entries:")
            for entry in index.entries[:15]:
                lines.append(
                    f"- {entry.relative_path} | signature={entry.signature} | findings={entry.finding_count} | tags={', '.join(entry.tags)}"
                )
        return "\n".join(lines)

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()
