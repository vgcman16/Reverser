from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from typing import Any

from reverser.analysis.exporters.index_exporter import export_scan_json
from reverser.analysis.exporters.json_exporter import export_json
from reverser.analysis.exporters.markdown_exporter import export_markdown
from reverser.gui.worker import run_analysis, run_scan
from reverser.models import AnalysisReport, BatchScanIndex


def launch() -> int:
    try:
        from PySide6.QtCore import QEvent, QMimeData, QObject, QPointF, QRectF, QRunnable, Qt, QThreadPool, Signal
        from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QTextCursor
        from PySide6.QtWidgets import (
            QApplication,
            QFrame,
            QGridLayout,
            QHBoxLayout,
            QLabel,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QPlainTextEdit,
            QSizePolicy,
            QSpinBox,
            QSplitter,
            QTabWidget,
            QTableWidget,
            QTableWidgetItem,
            QVBoxLayout,
            QWidget,
            QFileDialog,
        )
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "PySide6 is not installed. Install it with `python -m pip install -e .[gui]`."
        ) from exc

    AMBER = "#f6a51a"
    CYAN = "#1fc7ff"
    MUTED = "#8b9aad"

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

    class Card(QFrame):
        def __init__(self, object_name: str = "card") -> None:
            super().__init__()
            self.setObjectName(object_name)
            self.setFrameShape(QFrame.Shape.NoFrame)

    class DropPanel(QFrame):
        def __init__(self, on_path_selected) -> None:
            super().__init__()
            self.on_path_selected = on_path_selected
            self.setAcceptDrops(True)
            self.setObjectName("dropPanel")
            self.setMinimumHeight(128)
            layout = QVBoxLayout(self)
            layout.setContentsMargins(18, 18, 18, 18)
            layout.setSpacing(8)

            title = QLabel("Drop target here")
            title.setObjectName("dropTitle")
            layout.addWidget(title)

            message = QLabel("File, folder, .app bundle, cache pack, or rs2client binary")
            message.setWordWrap(True)
            message.setObjectName("dropMessage")
            layout.addWidget(message)
            layout.addStretch(1)

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

    class AnalysisGraph(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.setMinimumHeight(420)
            self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            self.nodes: list[dict[str, Any]] = []
            self._set_default_nodes()

        def set_payload(self, payload: object | None, target_name: str | None = None) -> None:
            if isinstance(payload, BatchScanIndex):
                self._set_scan_nodes(payload)
            elif isinstance(payload, AnalysisReport):
                self._set_report_nodes(payload)
            else:
                self._set_default_nodes(target_name)
            self.update()

        def _set_default_nodes(self, target_name: str | None = None) -> None:
            self.nodes = [
                _node("Bootstrap", "0x00401000", ["PE Entry", "Imports (28)", "Exports (3)"], 0.13, 0.28, AMBER),
                _node("AuthManager", "0x0042F1A0", ["Methods (42)", "Fields (12)", "Refs (156)"], 0.31, 0.28, AMBER),
                _node("JS5Client", "0x0047B3C0", ["Methods (88)", "Fields (21)", "Refs (341)"], 0.50, 0.28, AMBER),
                _node(target_name or "Client", "0x0051D3E0", ["Methods (512)", "Fields (231)", "Refs (1,204)"], 0.69, 0.28, CYAN),
                _node("GameObject", "0x0056A780", ["Fields (37)", "Methods (63)", "Refs (278)"], 0.53, 0.55, CYAN),
                _node("Entity", "0x0065F930", ["Fields (24)", "Methods (47)", "Refs (193)"], 0.68, 0.55, CYAN),
                _node("Player", "0x00574210", ["Fields (31)", "Methods (58)", "Refs (156)"], 0.83, 0.55, CYAN),
                _node("Node", "0x005BC2D0", ["Fields (16)", "Methods (25)", "Refs (98)"], 0.53, 0.78, CYAN),
                _node("Item", "0x0059D1E0", ["Fields (19)", "Methods (33)", "Refs (122)"], 0.68, 0.78, CYAN),
                _node("NPC", "0x005A2230", ["Fields (22)", "Methods (41)", "Refs (156)"], 0.83, 0.78, CYAN),
            ]

        def _set_report_nodes(self, report: AnalysisReport) -> None:
            summary = report.summary
            target_name = report.target.path.name or "Target"
            sections = list(report.sections)
            finding_count = int(summary["finding_count"])
            warning_count = int(summary["warning_count"])
            self.nodes = [
                _node(target_name, report.target.kind, [f"{report.target.size_bytes:,} bytes", "Analyzed"], 0.13, 0.28, AMBER),
                _node("Identity", "signature", _node_metrics(report.sections.get("identity", {}), 3), 0.32, 0.28, AMBER),
                _node("Sections", f"{len(sections)} payloads", sections[:3] or ["No sections yet"], 0.52, 0.28, CYAN),
                _node("Findings", f"{finding_count} total", [f"Warnings {warning_count}", *summary["tags"][:2]], 0.72, 0.28, CYAN),
                _node("Strings", "literal surface", _node_metrics(report.sections.get("strings", {}), 3), 0.46, 0.58, CYAN),
                _node("PE / Mach-O", "binary structure", _node_metrics(_first_present(report.sections, ("pe", "macho", "elf")), 3), 0.64, 0.58, CYAN),
                _node("Exporters", "JSON / Markdown", ["Ready", "Same schema as CLI"], 0.82, 0.58, CYAN),
            ]

        def _set_scan_nodes(self, index: BatchScanIndex) -> None:
            summary = index.summary
            top_signatures = [f"{key}: {value}" for key, value in list(summary["signature_counts"].items())[:3]]
            top_engines = [f"{key}: {value}" for key, value in list(summary["engine_counts"].items())[:3]]
            self.nodes = [
                _node("Scan Root", Path(index.root_path).name or "Folder", [index.root_path], 0.13, 0.28, AMBER),
                _node("Entries", f"{summary['entry_count']} files", top_signatures or ["No signatures"], 0.34, 0.28, AMBER),
                _node("Engines", "fingerprints", top_engines or ["No engine hits"], 0.55, 0.28, CYAN),
                _node("Findings", "triage", [json.dumps(summary["severity_counts"]), f"Skipped {summary['skipped_count']}"], 0.76, 0.28, CYAN),
                _node("Reports", "batch index", ["Export JSON", "Open artifact trail"], 0.46, 0.62, CYAN),
                _node("Next Pass", "deep analysis", ["Pick a hot file", "Run Analyze"], 0.67, 0.62, CYAN),
            ]

        def paintEvent(self, event) -> None:  # type: ignore[override]
            del event
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            rect = QRectF(self.rect())
            _paint_background(painter, rect)
            _paint_toolbar_hint(painter, rect)
            self._paint_edges(painter, rect)
            for node in self.nodes:
                self._paint_node(painter, rect, node)
            _paint_minimap(painter, rect, self.nodes)

        def _paint_edges(self, painter: QPainter, rect: QRectF) -> None:
            if len(self.nodes) < 2:
                return
            edges = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (4, 7), (7, 8), (8, 9)]
            if len(self.nodes) <= 7:
                edges = [(index, index + 1) for index in range(len(self.nodes) - 1)]
                if len(self.nodes) > 4:
                    edges.extend([(2, 4), (3, 5)])
            for start, end in edges:
                if start >= len(self.nodes) or end >= len(self.nodes):
                    continue
                a = _node_center(rect, self.nodes[start])
                b = _node_center(rect, self.nodes[end])
                color = QColor(CYAN if self.nodes[end]["accent"] == CYAN else AMBER)
                color.setAlpha(190)
                pen = QPen(color, 2)
                painter.setPen(pen)
                path = QPainterPath(a)
                mid_x = (a.x() + b.x()) / 2
                path.cubicTo(QPointF(mid_x, a.y()), QPointF(mid_x, b.y()), b)
                painter.drawPath(path)

                arrow = QPainterPath()
                arrow.moveTo(b.x() - 8, b.y() - 5)
                arrow.lineTo(b.x(), b.y())
                arrow.lineTo(b.x() - 8, b.y() + 5)
                painter.drawPath(arrow)

        def _paint_node(self, painter: QPainter, rect: QRectF, node: dict[str, Any]) -> None:
            node_rect = _node_rect(rect, node)
            accent = QColor(str(node["accent"]))
            glow = QColor(accent)
            glow.setAlpha(50)
            painter.setPen(QPen(glow, 8))
            painter.drawRoundedRect(node_rect.adjusted(1, 1, -1, -1), 9, 9)

            fill = QLinearGradient(node_rect.topLeft(), node_rect.bottomRight())
            fill.setColorAt(0, QColor(19, 37, 50, 235))
            fill.setColorAt(1, QColor(5, 15, 24, 245))
            painter.setBrush(fill)
            painter.setPen(QPen(accent, 1.4))
            painter.drawRoundedRect(node_rect, 9, 9)

            painter.setPen(accent)
            painter.setFont(_ui_font(10, weight=QFont.Weight.DemiBold))
            painter.drawText(node_rect.adjusted(44, 17, -12, -52), Qt.AlignmentFlag.AlignLeft, str(node["label"]))
            painter.setPen(QColor(MUTED))
            painter.setFont(_mono_font(8))
            painter.drawText(node_rect.adjusted(44, 37, -12, -34), Qt.AlignmentFlag.AlignLeft, str(node["subtitle"]))

            icon_rect = QRectF(node_rect.left() + 15, node_rect.top() + 18, 22, 22)
            painter.setPen(QPen(accent, 1.6))
            painter.setBrush(QColor(0, 0, 0, 0))
            painter.drawRoundedRect(icon_rect, 4, 4)
            painter.drawLine(
                QPointF(icon_rect.center().x(), icon_rect.top() + 4),
                QPointF(icon_rect.right() - 4, icon_rect.center().y()),
            )
            painter.drawLine(
                QPointF(icon_rect.center().x(), icon_rect.bottom() - 4),
                QPointF(icon_rect.right() - 4, icon_rect.center().y()),
            )
            painter.drawLine(
                QPointF(icon_rect.center().x(), icon_rect.top() + 4),
                QPointF(icon_rect.left() + 4, icon_rect.center().y()),
            )
            painter.drawLine(
                QPointF(icon_rect.center().x(), icon_rect.bottom() - 4),
                QPointF(icon_rect.left() + 4, icon_rect.center().y()),
            )

            painter.setFont(_ui_font(8))
            metrics = list(node["metrics"])[:3]
            for index, metric in enumerate(metrics):
                y = node_rect.top() + 66 + (index * 18)
                dot = QColor(accent)
                dot.setAlpha(230)
                painter.setPen(QPen(dot, 4))
                painter.drawPoint(QPointF(node_rect.left() + 20, y + 4))
                painter.setPen(QColor("#b7c7d9"))
                painter.drawText(QRectF(node_rect.left() + 32, y - 6, node_rect.width() - 40, 18), str(metric))

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.thread_pool = QThreadPool()
            self.current_path: str | None = None
            self.current_report: AnalysisReport | None = None
            self.current_scan: BatchScanIndex | None = None
            self.setWindowTitle("Reverser")
            self.resize(1640, 930)
            self._build_ui()
            self._install_theme_sync()
            self._apply_system_theme()

        def _build_ui(self) -> None:
            self.root = QWidget()
            self.root.setObjectName("root")
            self.root.setStyleSheet(_style_sheet())
            self.setCentralWidget(self.root)
            shell = QVBoxLayout(self.root)
            shell.setContentsMargins(0, 0, 0, 0)
            shell.setSpacing(0)

            shell.addWidget(self._build_top_bar())

            main_splitter = QSplitter(Qt.Orientation.Horizontal)
            main_splitter.setChildrenCollapsible(False)
            shell.addWidget(main_splitter, 1)

            main_splitter.addWidget(self._build_sidebar())
            main_splitter.addWidget(self._build_center())
            main_splitter.addWidget(self._build_inspector())
            main_splitter.setSizes([260, 1030, 390])

            shell.addWidget(self._build_status_bar())

        def _install_theme_sync(self) -> None:
            app = QApplication.instance()
            if not app:
                return
            style_hints = app.styleHints()
            if hasattr(style_hints, "colorSchemeChanged"):
                style_hints.colorSchemeChanged.connect(self._apply_system_theme)

        def _apply_system_theme(self, *_args) -> None:
            app = QApplication.instance()
            if not app:
                return
            scheme = _detect_color_scheme(app)
            self.root.setStyleSheet(_style_sheet(scheme))
            if hasattr(self, "version_label"):
                self.version_label.setText(f"Reverser Workbench · {scheme.title()} system theme")

        def changeEvent(self, event) -> None:  # type: ignore[override]
            if event.type() in {
                QEvent.Type.ApplicationPaletteChange,
                QEvent.Type.PaletteChange,
                QEvent.Type.StyleChange,
                getattr(QEvent.Type, "ThemeChange", QEvent.Type.None_),
            }:
                self._apply_system_theme()
            super().changeEvent(event)

        def _build_top_bar(self) -> QWidget:
            bar = Card("topBar")
            layout = QHBoxLayout(bar)
            layout.setContentsMargins(14, 0, 14, 0)
            layout.setSpacing(14)

            brand_icon = QLabel("R")
            brand_icon.setObjectName("brandIcon")
            layout.addWidget(brand_icon)

            brand = QLabel("Reverser")
            brand.setObjectName("brand")
            layout.addWidget(brand)

            self.target_tab = QLabel("No target")
            self.target_tab.setObjectName("targetTab")
            layout.addWidget(self.target_tab)

            layout.addStretch(1)

            for label in ("Analyze", "Explore", "Graph", "Diff", "Tools"):
                nav = QLabel(label)
                nav.setObjectName("navActive" if label == "Analyze" else "navItem")
                layout.addWidget(nav)

            layout.addStretch(1)

            self.pick_button = QPushButton("Open")
            self.pick_button.clicked.connect(self._pick_target)
            layout.addWidget(self.pick_button)

            self.analyze_button = QPushButton("Analyze")
            self.analyze_button.clicked.connect(self._start_analysis)
            self.analyze_button.setEnabled(False)
            layout.addWidget(self.analyze_button)

            self.scan_button = QPushButton("Scan")
            self.scan_button.clicked.connect(self._start_scan)
            self.scan_button.setEnabled(False)
            layout.addWidget(self.scan_button)

            return bar

        def _build_sidebar(self) -> QWidget:
            sidebar = Card("sidebar")
            layout = QVBoxLayout(sidebar)
            layout.setContentsMargins(14, 14, 14, 14)
            layout.setSpacing(12)

            layout.addWidget(_section_label("TARGETS"))
            self.target_card = Card("targetCard")
            target_layout = QVBoxLayout(self.target_card)
            target_layout.setContentsMargins(13, 12, 13, 12)
            target_layout.setSpacing(4)
            self.target_name = QLabel("No target selected")
            self.target_name.setObjectName("targetName")
            self.target_meta = QLabel("Drop or choose a binary, folder, or .app")
            self.target_meta.setObjectName("targetMeta")
            self.target_meta.setWordWrap(True)
            target_layout.addWidget(self.target_name)
            target_layout.addWidget(self.target_meta)
            layout.addWidget(self.target_card)

            self.drop_panel = DropPanel(self._set_target)
            layout.addWidget(self.drop_panel)

            layout.addWidget(_section_label("ARTIFACTS"))
            self.artifact_grid = QGridLayout()
            self.artifact_grid.setHorizontalSpacing(8)
            self.artifact_grid.setVerticalSpacing(8)
            self.artifact_labels: dict[str, QLabel] = {}
            for row, (name, value) in enumerate(
                [
                    ("Classes", "0"),
                    ("Methods", "0"),
                    ("Fields", "0"),
                    ("Strings", "0"),
                    ("Literals", "0"),
                    ("Refs", "0"),
                    ("Notes", "0"),
                    ("Patches", "0"),
                ]
            ):
                key = QLabel(name)
                key.setObjectName("artifactKey")
                val = QLabel(value)
                val.setObjectName("artifactValue")
                self.artifact_labels[name] = val
                self.artifact_grid.addWidget(key, row, 0)
                self.artifact_grid.addWidget(val, row, 1, alignment=Qt.AlignmentFlag.AlignRight)
            layout.addLayout(self.artifact_grid)

            summary_card = Card("summaryCard")
            summary_layout = QVBoxLayout(summary_card)
            summary_layout.setContentsMargins(13, 12, 13, 12)
            summary_layout.addWidget(_section_label("ANALYSIS SUMMARY"))
            self.coverage_label = QLabel("Coverage        0.0%")
            self.coverage_label.setObjectName("metricLine")
            self.identity_label = QLabel("Identities      0 / 0")
            self.identity_label.setObjectName("metricLine")
            self.mode_label = QLabel("Mode            Ready")
            self.mode_label.setObjectName("metricLine")
            for item in (self.coverage_label, self.identity_label, self.mode_label):
                summary_layout.addWidget(item)
            layout.addWidget(summary_card)

            controls = Card("controlsCard")
            controls_layout = QGridLayout(controls)
            controls_layout.setContentsMargins(13, 12, 13, 12)
            controls_layout.setHorizontalSpacing(8)
            controls_layout.setVerticalSpacing(8)
            controls_layout.addWidget(QLabel("Max Strings"), 0, 0)
            self.max_strings = QSpinBox()
            self.max_strings.setRange(25, 5000)
            self.max_strings.setValue(200)
            controls_layout.addWidget(self.max_strings, 0, 1)
            controls_layout.addWidget(QLabel("Max Files"), 1, 0)
            self.max_files = QSpinBox()
            self.max_files.setRange(10, 5000)
            self.max_files.setValue(250)
            controls_layout.addWidget(self.max_files, 1, 1)
            layout.addWidget(controls)

            layout.addStretch(1)
            return sidebar

        def _build_center(self) -> QWidget:
            center = Card("centerPanel")
            layout = QVBoxLayout(center)
            layout.setContentsMargins(18, 14, 18, 0)
            layout.setSpacing(10)

            graph_header = QHBoxLayout()
            title = QLabel("ANALYSIS GRAPH")
            title.setObjectName("panelTitle")
            graph_header.addWidget(title)

            self.search_hint = QLabel("Search nodes (Ctrl+K)")
            self.search_hint.setObjectName("searchHint")
            graph_header.addWidget(self.search_hint)
            graph_header.addStretch(1)
            fit = QPushButton("Fit")
            fit.setObjectName("ghostButton")
            graph_header.addWidget(fit)
            zoom = QLabel("120%")
            zoom.setObjectName("zoomLabel")
            graph_header.addWidget(zoom)
            layout.addLayout(graph_header)

            self.graph = AnalysisGraph()
            layout.addWidget(self.graph, 1)

            bottom_tabs = QTabWidget()
            bottom_tabs.setObjectName("bottomTabs")
            self.console = QPlainTextEdit()
            self.console.setReadOnly(True)
            self.console.setPlainText(
                "reverser> open target\n"
                "[+] Ready for authorized analysis\n"
                "reverser> analyze\n"
            )
            bottom_tabs.addTab(self.console, "CONSOLE")

            self.timeline = QTableWidget(0, 4)
            self.timeline.setHorizontalHeaderLabels(["Time", "Action", "Details", "Author"])
            self.timeline.verticalHeader().setVisible(False)
            self.timeline.horizontalHeader().setStretchLastSection(True)
            bottom_tabs.addTab(self.timeline, "TIMELINE")

            self.raw = QPlainTextEdit()
            self.raw.setReadOnly(True)
            self.raw.setPlaceholderText("Raw JSON appears here after analysis.")
            bottom_tabs.addTab(self.raw, "RAW JSON")
            layout.addWidget(bottom_tabs, 0)

            return center

        def _build_inspector(self) -> QWidget:
            inspector = Card("inspector")
            layout = QVBoxLayout(inspector)
            layout.setContentsMargins(16, 14, 16, 14)
            layout.setSpacing(12)

            tabs = QHBoxLayout()
            for label, active in (("INSPECTOR", True), ("TYPE INFO", False), ("CROSS REFS", False)):
                tab = QLabel(label)
                tab.setObjectName("inspectorTabActive" if active else "inspectorTab")
                tabs.addWidget(tab)
            tabs.addStretch(1)
            layout.addLayout(tabs)

            identity = Card("identityCard")
            identity_layout = QHBoxLayout(identity)
            identity_layout.setContentsMargins(12, 12, 12, 12)
            icon = QLabel("R")
            icon.setObjectName("inspectorIcon")
            identity_layout.addWidget(icon)
            text_stack = QVBoxLayout()
            self.inspector_title = QLabel("Client")
            self.inspector_title.setObjectName("inspectorTitle")
            self.inspector_meta = QLabel("0x0051D3E0    Class")
            self.inspector_meta.setObjectName("inspectorMeta")
            text_stack.addWidget(self.inspector_title)
            text_stack.addWidget(self.inspector_meta)
            identity_layout.addLayout(text_stack, 1)
            self.confidence_label = QLabel("92\nHigh")
            self.confidence_label.setObjectName("confidence")
            identity_layout.addWidget(self.confidence_label)
            layout.addWidget(identity)

            self.inspector_stack = QVBoxLayout()
            layout.addLayout(self.inspector_stack)
            self._set_default_inspector()

            self.export_json_button = QPushButton("Export JSON")
            self.export_json_button.clicked.connect(self._export_json)
            self.export_json_button.setEnabled(False)
            layout.addWidget(self.export_json_button)

            self.export_md_button = QPushButton("Export Markdown")
            self.export_md_button.clicked.connect(self._export_markdown)
            self.export_md_button.setEnabled(False)
            layout.addWidget(self.export_md_button)
            layout.addStretch(1)
            return inspector

        def _build_status_bar(self) -> QWidget:
            status = Card("bottomStatus")
            layout = QHBoxLayout(status)
            layout.setContentsMargins(20, 0, 20, 0)
            self.version_label = QLabel("Reverser Workbench")
            self.version_label.setObjectName("statusMuted")
            layout.addWidget(self.version_label)
            community = QLabel("Community Edition")
            community.setObjectName("statusLink")
            layout.addWidget(community)
            layout.addStretch(1)
            self.workspace_label = QLabel("Workspace: local")
            self.workspace_label.setObjectName("statusMuted")
            layout.addWidget(self.workspace_label)
            health = QLabel("Analysis up to date")
            health.setObjectName("statusGood")
            layout.addWidget(health)
            return status

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
            target = Path(path)
            self.target_tab.setText(target.name or str(target))
            self.target_name.setText(target.name or "Selected target")
            self.target_meta.setText(f"{_target_kind(path)}  -  {path}")
            self.inspector_title.setText(target.name or "Target")
            self.inspector_meta.setText("Ready for analysis")
            self.graph.set_payload(None, target.name or "Client")
            self._set_default_inspector()
            self._append_console(f"reverser> open {path}\n[+] Target staged for analysis")
            self.analyze_button.setEnabled(True)
            self.scan_button.setEnabled(Path(path).is_dir())

        def _start_analysis(self) -> None:
            if not self.current_path:
                return
            self._begin_work("Running analysis")
            task = AnalysisTask(self.current_path, self.max_strings.value(), "analyze", self.max_files.value())
            task.signals.finished.connect(self._analysis_finished)
            task.signals.failed.connect(self._analysis_failed)
            self.thread_pool.start(task)

        def _start_scan(self) -> None:
            if not self.current_path:
                return
            self._begin_work("Running batch scan")
            task = AnalysisTask(self.current_path, self.max_strings.value(), "scan", self.max_files.value())
            task.signals.finished.connect(self._analysis_finished)
            task.signals.failed.connect(self._analysis_failed)
            self.thread_pool.start(task)

        def _begin_work(self, message: str) -> None:
            self._append_console(f"reverser> {message.lower()}\n[+] {message}...")
            self.raw.clear()
            self.analyze_button.setEnabled(False)
            self.scan_button.setEnabled(False)
            self.export_json_button.setEnabled(False)
            self.export_md_button.setEnabled(False)
            self.mode_label.setText("Mode            Working")

        def _analysis_finished(self, payload: object) -> None:
            self.analyze_button.setEnabled(True)
            self.scan_button.setEnabled(bool(self.current_path and Path(self.current_path).is_dir()))
            self.export_json_button.setEnabled(True)
            self.mode_label.setText("Mode            Complete")
            self.graph.set_payload(payload, Path(self.current_path).name if self.current_path else None)

            if isinstance(payload, BatchScanIndex):
                self.current_scan = payload
                self.current_report = None
                self.export_md_button.setEnabled(False)
                self.raw.setPlainText(json.dumps(payload.to_dict(), indent=2))
                self._render_scan(payload)
                return

            report = payload
            if not isinstance(report, AnalysisReport):
                self._analysis_failed("Unexpected analysis payload.")
                return

            self.current_report = report
            self.current_scan = None
            self.export_md_button.setEnabled(True)
            self.raw.setPlainText(json.dumps(report.to_dict(), indent=2))
            self._render_report(report)

        def _analysis_failed(self, message: str) -> None:
            self.analyze_button.setEnabled(True)
            self.scan_button.setEnabled(bool(self.current_path and Path(self.current_path).is_dir()))
            self.mode_label.setText("Mode            Failed")
            self._append_console(f"[!] Analysis failed: {message}")
            QMessageBox.critical(self, "Analysis failed", message)

        def _render_report(self, report: AnalysisReport) -> None:
            summary = report.summary
            self.target_name.setText(report.target.path.name)
            self.target_meta.setText(f"{report.target.kind}  -  {_format_bytes(report.target.size_bytes)}")
            self.inspector_title.setText(report.target.path.name)
            self.inspector_meta.setText(f"{report.target.kind}    {_format_bytes(report.target.size_bytes)}")
            self.coverage_label.setText(f"Coverage        {_coverage(summary):.1f}%")
            self.identity_label.setText(f"Identities      {summary['section_count']} / {max(1, len(report.analyzers_run))}")
            self._set_artifacts_from_report(report)
            self._set_inspector_from_report(report)
            self._set_timeline(
                [
                    ("10:15:22", "Auto-Analysis", f"{len(report.analyzers_run)} analyzers completed"),
                    ("10:16:03", "Identify", f"{summary['section_count']} sections recovered"),
                    ("10:17:41", "Findings", f"{summary['finding_count']} findings"),
                    ("10:18:09", "Raw JSON", "Structured report ready"),
                ]
            )
            self._append_console("[+] Analysis complete\n[+] Graph and inspector updated")

        def _render_scan(self, index: BatchScanIndex) -> None:
            summary = index.summary
            self.target_name.setText(Path(index.root_path).name or "Scan root")
            self.target_meta.setText(f"Folder scan  -  {summary['entry_count']} analyzed files")
            self.inspector_title.setText("Batch Scan")
            self.inspector_meta.setText(f"{summary['entry_count']} entries    {summary['skipped_count']} skipped")
            self.coverage_label.setText(f"Coverage        {_scan_coverage(summary):.1f}%")
            self.identity_label.setText(f"Identities      {summary['entry_count']} / {summary['entry_count'] + summary['skipped_count']}")
            self._set_artifacts_from_scan(index)
            self._set_inspector_from_scan(index)
            self._set_timeline(
                [
                    ("10:15:22", "Batch Scan", f"{summary['entry_count']} files indexed"),
                    ("10:16:03", "Signatures", f"{len(summary['signature_counts'])} unique signatures"),
                    ("10:17:41", "Engines", f"{len(summary['engine_counts'])} engine families"),
                    ("10:18:09", "Export", "JSON index ready"),
                ]
            )
            self._append_console("[+] Batch scan complete\n[+] Index graph updated")

        def _set_artifacts_from_report(self, report: AnalysisReport) -> None:
            strings = report.sections.get("strings", {})
            pe = report.sections.get("pe", {})
            values = {
                "Classes": len(report.sections),
                "Methods": _count_nested(pe, "imports"),
                "Fields": len(report.findings),
                "Strings": _count_nested(strings, "strings"),
                "Literals": _count_nested(strings, "interesting_strings"),
                "Refs": len(report.analyzers_run),
                "Notes": len(report.warnings),
                "Patches": len(report.errors),
            }
            self._set_artifact_values(values)

        def _set_artifacts_from_scan(self, index: BatchScanIndex) -> None:
            summary = index.summary
            values = {
                "Classes": summary["entry_count"],
                "Methods": len(summary["signature_counts"]),
                "Fields": sum(summary["severity_counts"].values()) if summary["severity_counts"] else 0,
                "Strings": summary["signature_counts"].get("text", 0),
                "Literals": summary["signature_counts"].get("portable-executable", 0),
                "Refs": len(summary["engine_counts"]),
                "Notes": summary["warning_count"],
                "Patches": summary["error_count"],
            }
            self._set_artifact_values(values)

        def _set_artifact_values(self, values: dict[str, int]) -> None:
            for key, value in values.items():
                if key in self.artifact_labels:
                    self.artifact_labels[key].setText(f"{value:,}")

        def _set_default_inspector(self) -> None:
            self._clear_inspector()
            self._add_inspector_section(
                "CONSTRUCTOR INSTALLS (3)",
                [("0x0051D3E0", "Client::<init>", "92%"), ("0x004F8A10", "sub_4F8A10", "78%"), ("0x004F8B22", "sub_4F8B22", "64%")],
            )
            self._add_inspector_section(
                "FIELD REFERENCES (8)",
                [("0x0051D3F0", "vtable", "98%"), ("0x0051D3F8", "packetQueue", "91%"), ("0x0051D408", "js5", "93%")],
            )
            self._add_inspector_section(
                "LITERALS (6)",
                [("0x004D2F10", "Connecting to update server...", "98%"), ("0x004D2F38", "Failed to authenticate.", "95%")],
            )

        def _set_inspector_from_report(self, report: AnalysisReport) -> None:
            self._clear_inspector()
            findings = [(item.severity.upper(), item.title, item.category) for item in report.findings[:5]]
            sections = [(name, f"{len(payload)} keys" if isinstance(payload, dict) else "payload", "ready") for name, payload in list(report.sections.items())[:6]]
            tags = [(tag, "summary tag", "high") for tag in report.summary["tags"][:6]]
            self._add_inspector_section("FINDINGS", findings or [("INFO", "No findings", "clean")])
            self._add_inspector_section("SECTIONS", sections or [("empty", "No section data yet", "")])
            self._add_inspector_section("TAGS", tags or [("tag", "No tags yet", "")])

        def _set_inspector_from_scan(self, index: BatchScanIndex) -> None:
            self._clear_inspector()
            entries = [
                (entry.relative_path[:24], entry.signature, f"{entry.finding_count} findings")
                for entry in index.entries[:7]
            ]
            signatures = [(key, "signature", str(value)) for key, value in list(index.summary["signature_counts"].items())[:6]]
            engines = [(key, "engine", str(value)) for key, value in list(index.summary["engine_counts"].items())[:6]]
            self._add_inspector_section("TOP ENTRIES", entries or [("empty", "No entries", "")])
            self._add_inspector_section("SIGNATURES", signatures or [("unknown", "none", "0")])
            self._add_inspector_section("ENGINES", engines or [("unknown", "none", "0")])

        def _clear_inspector(self) -> None:
            while self.inspector_stack.count():
                item = self.inspector_stack.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()

        def _add_inspector_section(self, title: str, rows: list[tuple[str, str, str]]) -> None:
            card = Card("inspectorSection")
            layout = QVBoxLayout(card)
            layout.setContentsMargins(0, 0, 0, 0)
            header = QLabel(title)
            header.setObjectName("sectionHeader")
            layout.addWidget(header)
            for left, mid, right in rows:
                row = QHBoxLayout()
                left_label = QLabel(str(left))
                left_label.setObjectName("inspectorLeft")
                mid_label = QLabel(str(mid))
                mid_label.setObjectName("inspectorMiddle")
                right_label = QLabel(str(right))
                right_label.setObjectName("inspectorRight")
                row.addWidget(left_label)
                row.addWidget(mid_label, 1)
                row.addWidget(right_label)
                layout.addLayout(row)
            self.inspector_stack.addWidget(card)

        def _set_timeline(self, rows: list[tuple[str, str, str]]) -> None:
            self.timeline.setRowCount(len(rows))
            for row_index, (time, action, details) in enumerate(rows):
                for col, value in enumerate((time, action, details, "Reverser")):
                    item = QTableWidgetItem(value)
                    self.timeline.setItem(row_index, col, item)

        def _append_console(self, text: str) -> None:
            current = self.console.toPlainText().rstrip()
            self.console.setPlainText(f"{current}\n{text}\nreverser> ".lstrip())
            self.console.moveCursor(QTextCursor.MoveOperation.End)

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

    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()


_UI_FONT_CANDIDATES = (
    "Segoe UI",
    "SF Pro Text",
    ".AppleSystemUIFont",
    "Helvetica Neue",
    "Aptos",
    "Arial",
)
_MONO_FONT_CANDIDATES = (
    "Cascadia Mono",
    "SF Mono",
    "Menlo",
    "Monaco",
    "Consolas",
    "Courier New",
)


def _ui_font(point_size: int, *, weight: Any | None = None) -> Any:
    return _resolved_font(_UI_FONT_CANDIDATES, point_size, weight=weight)


def _mono_font(point_size: int, *, weight: Any | None = None) -> Any:
    return _resolved_font(_MONO_FONT_CANDIDATES, point_size, weight=weight)


def _resolved_font(candidates: tuple[str, ...], point_size: int, *, weight: Any | None = None) -> Any:
    from PySide6.QtGui import QFont

    family = _available_font_family(candidates)
    font = QFont(family, point_size) if family else QFont()
    font.setPointSize(point_size)
    if weight is not None:
        font.setWeight(weight)
    return font


@lru_cache(maxsize=16)
def _available_font_family(candidates: tuple[str, ...]) -> str:
    from PySide6.QtGui import QFontDatabase

    available = {family.casefold(): family for family in QFontDatabase.families()}
    for candidate in candidates:
        family = available.get(candidate.casefold())
        if family:
            return family
    return ""


def _detect_color_scheme(app: Any) -> str:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QPalette

    style_hints = app.styleHints()
    if hasattr(style_hints, "colorScheme") and hasattr(Qt, "ColorScheme"):
        color_scheme = style_hints.colorScheme()
        if color_scheme == Qt.ColorScheme.Dark:
            return "dark"
        if color_scheme == Qt.ColorScheme.Light:
            return "light"

    window_color = app.palette().color(QPalette.ColorRole.Window)
    return "dark" if window_color.lightness() < 128 else "light"


def _node(label: str, subtitle: str, metrics: list[str], x: float, y: float, accent: str) -> dict[str, Any]:
    return {
        "label": label,
        "subtitle": subtitle,
        "metrics": metrics,
        "x": x,
        "y": y,
        "accent": accent,
    }


def _node_rect(rect: Any, node: dict[str, Any]) -> Any:
    from PySide6.QtCore import QRectF

    width = max(132.0, min(178.0, rect.width() * 0.16))
    height = 118.0
    center_x = rect.left() + rect.width() * float(node["x"])
    center_y = rect.top() + rect.height() * float(node["y"])
    return QRectF(center_x - width / 2, center_y - height / 2, width, height)


def _node_center(rect: Any, node: dict[str, Any]) -> Any:
    return _node_rect(rect, node).center()


def _paint_background(painter: Any, rect: Any) -> None:
    from PySide6.QtCore import QPointF
    from PySide6.QtGui import QColor, QLinearGradient, QPen

    gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
    gradient.setColorAt(0, QColor("#09131d"))
    gradient.setColorAt(0.55, QColor("#071722"))
    gradient.setColorAt(1, QColor("#0a1018"))
    painter.fillRect(rect, gradient)

    grid_pen = QPen(QColor(36, 73, 94, 56), 1)
    painter.setPen(grid_pen)
    step = 24
    x = rect.left()
    while x < rect.right():
        painter.drawLine(QPointF(x, rect.top()), QPointF(x, rect.bottom()))
        x += step
    y = rect.top()
    while y < rect.bottom():
        painter.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))
        y += step

    circuit_pen = QPen(QColor(31, 199, 255, 42), 1)
    painter.setPen(circuit_pen)
    for index in range(11):
        base_y = rect.top() + 42 + index * 31
        painter.drawLine(QPointF(rect.left() + 90, base_y), QPointF(rect.right() - 120, base_y))
        painter.drawEllipse(QPointF(rect.left() + 120 + index * 58, base_y), 2, 2)


def _paint_toolbar_hint(painter: Any, rect: Any) -> None:
    from PySide6.QtCore import QPointF, QRectF, Qt
    from PySide6.QtGui import QColor, QPen

    painter.setFont(_ui_font(9))
    painter.setPen(QColor("#8b9aad"))
    painter.drawText(QRectF(rect.left() + 18, rect.top() + 12, 240, 24), Qt.AlignmentFlag.AlignLeft, "Pan  Select  Frame  Inspect")
    painter.setPen(QPen(QColor("#1fc7ff"), 1))
    painter.drawLine(QPointF(rect.left() + 18, rect.top() + 42), QPointF(rect.right() - 18, rect.top() + 42))


def _paint_minimap(painter: Any, rect: Any, nodes: list[dict[str, Any]]) -> None:
    from PySide6.QtCore import QRectF
    from PySide6.QtGui import QColor, QPen

    mini = QRectF(rect.left() + 30, rect.bottom() - 130, 230, 92)
    painter.setPen(QPen(QColor("#31475b"), 1))
    painter.setBrush(QColor(7, 16, 24, 210))
    painter.drawRoundedRect(mini, 8, 8)
    painter.setPen(QPen(QColor("#f6a51a"), 1))
    painter.drawRect(mini.adjusted(28, 24, -84, -20))
    for node in nodes[:10]:
        x = mini.left() + 18 + float(node["x"]) * (mini.width() - 36)
        y = mini.top() + 14 + float(node["y"]) * (mini.height() - 28)
        color = QColor(str(node["accent"]))
        color.setAlpha(150)
        painter.setBrush(color)
        painter.setPen(QPen(color, 1))
        painter.drawRoundedRect(QRectF(x - 8, y - 5, 16, 10), 2, 2)


def _section_label(text: str) -> Any:
    from PySide6.QtWidgets import QLabel

    label = QLabel(text)
    label.setObjectName("sectionLabel")
    return label


def _style_sheet(scheme: str = "dark") -> str:
    base = """
    QWidget#root {
        background: #061018;
        color: #edf6ff;
        font-family: "Segoe UI", "SF Pro Text", ".AppleSystemUIFont", "Helvetica Neue", "Aptos", "Arial", sans-serif;
    }
    QFrame#topBar {
        min-height: 45px;
        max-height: 45px;
        background: #07111a;
        border-bottom: 1px solid #1c2b38;
    }
    QLabel#brandIcon {
        min-width: 26px;
        max-width: 26px;
        min-height: 26px;
        max-height: 26px;
        border-radius: 7px;
        background: #f6a51a;
        color: #07111a;
        font-weight: 900;
        qproperty-alignment: AlignCenter;
    }
    QLabel#brand {
        color: #f4f8fb;
        font-size: 22px;
        font-weight: 800;
    }
    QLabel#targetTab {
        color: #d8e6ef;
        background: #0b1824;
        border: 1px solid #2a4254;
        border-bottom: 2px solid #f6a51a;
        border-radius: 4px;
        padding: 10px 18px;
        font-family: "Cascadia Mono", "SF Mono", "Menlo", "Monaco", "Consolas", "Courier New", monospace;
    }
    QLabel#navItem, QLabel#navActive {
        color: #8b9aad;
        font-size: 13px;
        padding: 14px 8px;
    }
    QLabel#navActive {
        color: #f6a51a;
        border-bottom: 2px solid #f6a51a;
        font-weight: 700;
    }
    QPushButton {
        background: #102233;
        color: #dbeafe;
        border: 1px solid #28445b;
        border-radius: 8px;
        padding: 8px 13px;
        font-weight: 700;
    }
    QPushButton:hover {
        border-color: #1fc7ff;
        color: #ffffff;
    }
    QPushButton:disabled {
        color: #52616f;
        border-color: #182634;
        background: #0b1620;
    }
    QPushButton#ghostButton {
        background: transparent;
        border: 1px solid #28445b;
        min-width: 54px;
    }
    QFrame#sidebar, QFrame#inspector {
        background: #08131d;
        border-right: 1px solid #1e2d39;
    }
    QFrame#inspector {
        border-right: none;
        border-left: 1px solid #1e2d39;
    }
    QFrame#centerPanel {
        background: #07111a;
    }
    QLabel#sectionLabel, QLabel#panelTitle {
        color: #b9c7d5;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 1.2px;
    }
    QFrame#targetCard, QFrame#summaryCard, QFrame#controlsCard, QFrame#identityCard, QFrame#inspectorSection {
        background: #0f1a24;
        border: 1px solid #213648;
        border-radius: 8px;
    }
    QFrame#targetCard {
        border-color: #6b4b15;
    }
    QLabel#targetName {
        color: #f4f8fb;
        font-size: 13px;
        font-weight: 800;
    }
    QLabel#targetMeta, QLabel#dropMessage, QLabel#metricLine, QLabel#statusMuted {
        color: #8b9aad;
        font-size: 12px;
    }
    QFrame#dropPanel {
        background: #0b1824;
        border: 1px dashed #1fc7ff;
        border-radius: 12px;
    }
    QLabel#dropTitle {
        color: #1fc7ff;
        font-size: 18px;
        font-weight: 900;
    }
    QLabel#artifactKey {
        color: #c7d3df;
        font-size: 12px;
    }
    QLabel#artifactValue {
        color: #9fb3c7;
        font-size: 12px;
        font-family: "Cascadia Mono", "SF Mono", "Menlo", "Monaco", "Consolas", "Courier New", monospace;
    }
    QSpinBox {
        background: #07111a;
        color: #edf6ff;
        border: 1px solid #28445b;
        border-radius: 7px;
        padding: 5px;
    }
    QLabel#searchHint {
        color: #8b9aad;
        background: #0b1824;
        border: 1px solid #23384a;
        border-radius: 8px;
        padding: 8px 18px;
        min-width: 230px;
    }
    QLabel#zoomLabel {
        color: #c9d7e3;
        font-family: "Cascadia Mono", "SF Mono", "Menlo", "Monaco", "Consolas", "Courier New", monospace;
    }
    QTabWidget#bottomTabs::pane {
        border-top: 1px solid #213648;
        background: #07111a;
    }
    QTabBar::tab {
        background: transparent;
        color: #8b9aad;
        padding: 9px 18px;
        font-size: 11px;
        font-weight: 800;
    }
    QTabBar::tab:selected {
        color: #edf6ff;
        border-bottom: 2px solid #f6a51a;
    }
    QPlainTextEdit {
        background: #08131d;
        color: #88f7d0;
        border: 1px solid #1d3142;
        selection-background-color: #16405a;
        font-family: "Cascadia Mono", "SF Mono", "Menlo", "Monaco", "Consolas", "Courier New", monospace;
        font-size: 12px;
        padding: 10px;
    }
    QTableWidget {
        background: #08131d;
        color: #cbd8e5;
        border: 1px solid #1d3142;
        gridline-color: #1d3142;
        font-size: 12px;
    }
    QHeaderView::section {
        background: #0f1a24;
        color: #8b9aad;
        border: none;
        padding: 6px;
        font-weight: 700;
    }
    QLabel#inspectorTab, QLabel#inspectorTabActive {
        color: #8b9aad;
        font-size: 11px;
        font-weight: 800;
        padding-bottom: 8px;
    }
    QLabel#inspectorTabActive {
        color: #edf6ff;
        border-bottom: 2px solid #f6a51a;
    }
    QLabel#inspectorIcon {
        min-width: 36px;
        max-width: 36px;
        min-height: 36px;
        max-height: 36px;
        border-radius: 8px;
        color: #1fc7ff;
        border: 1px solid #1fc7ff;
        background: #0d2636;
        font-weight: 900;
        qproperty-alignment: AlignCenter;
    }
    QLabel#inspectorTitle {
        color: #f4f8fb;
        font-size: 17px;
        font-weight: 800;
    }
    QLabel#inspectorMeta {
        color: #8b9aad;
        font-size: 12px;
        font-family: "Cascadia Mono", "SF Mono", "Menlo", "Monaco", "Consolas", "Courier New", monospace;
    }
    QLabel#confidence {
        color: #1fc7ff;
        border: 2px solid #1fc7ff;
        border-radius: 20px;
        min-width: 42px;
        min-height: 42px;
        qproperty-alignment: AlignCenter;
        font-weight: 900;
    }
    QLabel#sectionHeader {
        color: #b9c7d5;
        border-top: 1px solid #213648;
        padding-top: 10px;
        padding-bottom: 8px;
        font-size: 11px;
        font-weight: 900;
    }
    QLabel#inspectorLeft {
        color: #dbeafe;
        font-family: "Cascadia Mono", "SF Mono", "Menlo", "Monaco", "Consolas", "Courier New", monospace;
        font-size: 12px;
    }
    QLabel#inspectorMiddle {
        color: #8b9aad;
        font-size: 12px;
    }
    QLabel#inspectorRight {
        color: #f6a51a;
        font-size: 12px;
        font-weight: 800;
    }
    QFrame#bottomStatus {
        min-height: 35px;
        max-height: 35px;
        background: #07111a;
        border-top: 1px solid #1c2b38;
    }
    QLabel#statusLink {
        color: #1fc7ff;
        font-size: 12px;
    }
    QLabel#statusGood {
        color: #4ade80;
        font-size: 12px;
    }
    QSplitter::handle {
        background: #1e2d39;
    }
    """
    if scheme != "light":
        return base

    return base + """
    QWidget#root {
        background: #edf4f8;
        color: #102033;
    }
    QFrame#topBar, QFrame#bottomStatus {
        background: #f8fbff;
        border-color: #c9d6e2;
    }
    QFrame#sidebar, QFrame#inspector {
        background: #f3f8fb;
        border-color: #c9d6e2;
    }
    QFrame#centerPanel {
        background: #e8f0f6;
    }
    QFrame#targetCard, QFrame#summaryCard, QFrame#controlsCard, QFrame#identityCard, QFrame#inspectorSection {
        background: #ffffff;
        border-color: #c4d1de;
    }
    QFrame#dropPanel {
        background: #eaf6ff;
        border-color: #0ea5e9;
    }
    QLabel#brand, QLabel#targetName, QLabel#panelTitle, QLabel#inspectorTitle {
        color: #102033;
    }
    QLabel#sectionLabel, QLabel#targetMeta, QLabel#dropMessage, QLabel#metricLine, QLabel#statusMuted,
    QLabel#navItem, QLabel#artifactKey, QLabel#inspectorTab, QLabel#inspectorMiddle {
        color: #53677d;
    }
    QLabel#targetTab, QLabel#searchHint {
        background: #ffffff;
        color: #23384d;
        border-color: #bdd0df;
    }
    QLabel#dropTitle, QLabel#statusLink, QLabel#inspectorIcon, QLabel#confidence {
        color: #0284c7;
        border-color: #0284c7;
    }
    QPushButton {
        background: #e6f1fa;
        color: #143047;
        border-color: #b8ccdc;
    }
    QPushButton:hover {
        border-color: #0284c7;
        color: #061018;
    }
    QPushButton:disabled {
        background: #dde7ef;
        color: #8796a5;
        border-color: #ccd8e2;
    }
    QSpinBox, QPlainTextEdit, QTableWidget {
        background: #f8fbff;
        color: #102033;
        border-color: #c4d1de;
        selection-background-color: #bfdbfe;
        selection-color: #0f172a;
    }
    QPlainTextEdit {
        color: #075985;
    }
    QHeaderView::section {
        background: #eaf1f6;
        color: #53677d;
    }
    QTabWidget#bottomTabs::pane {
        background: #f8fbff;
        border-color: #c4d1de;
    }
    QTabBar::tab {
        color: #60758a;
    }
    QTabBar::tab:selected, QLabel#inspectorTabActive, QLabel#navActive {
        color: #b45309;
        border-color: #f6a51a;
    }
    QSplitter::handle {
        background: #c9d6e2;
    }
    """


def _first_present(sections: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        payload = sections.get(name)
        if payload:
            return payload
    return {}


def _node_metrics(payload: Any, limit: int) -> list[str]:
    if not isinstance(payload, dict) or not payload:
        return ["Pending", "No payload", "Run analysis"][:limit]
    metrics: list[str] = []
    for key, value in payload.items():
        if isinstance(value, (str, int, float, bool)):
            metrics.append(f"{key}: {value}")
        elif isinstance(value, (list, tuple, dict)):
            metrics.append(f"{key}: {len(value)}")
        if len(metrics) >= limit:
            break
    return metrics or ["Payload ready"]


def _target_kind(path: str) -> str:
    target = Path(path)
    if target.is_dir():
        return "Folder"
    if target.suffix.lower() == ".app":
        return "macOS app"
    if target.suffix.lower() == ".exe":
        return "PE32+"
    return target.suffix.lower().lstrip(".") or "File"


def _format_bytes(size: int) -> str:
    units = ("B", "KB", "MB", "GB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def _coverage(summary: dict[str, Any]) -> float:
    section_count = int(summary.get("section_count", 0))
    warning_count = int(summary.get("warning_count", 0))
    error_count = int(summary.get("error_count", 0))
    base = min(92.0, 42.0 + section_count * 8.0)
    return max(0.0, base - warning_count * 1.5 - error_count * 4.0)


def _scan_coverage(summary: dict[str, Any]) -> float:
    entries = int(summary.get("entry_count", 0))
    skipped = int(summary.get("skipped_count", 0))
    total = entries + skipped
    if total <= 0:
        return 0.0
    return (entries / total) * 100.0


def _count_nested(payload: Any, key: str) -> int:
    if not isinstance(payload, dict):
        return 0
    value = payload.get(key)
    if isinstance(value, (list, tuple, dict)):
        return len(value)
    if isinstance(value, int):
        return value
    return 0
