from __future__ import annotations

from datetime import datetime
from pathlib import Path
import json
import shutil
import sys

from PySide6.QtCore import Qt, QThread, QUrl, QSize
from PySide6.QtGui import QDesktopServices, QIcon, QGuiApplication
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from gui.settings import DEFAULTS, load_settings, save_settings
from gui.theme import APP_STYLESHEET
from gui.workers import ScanWorker
from gui.history import (
    append_history,
    clear_history,
    load_history,
    latest_snapshot_for_target,
)
from gui.queue import QueueItem, load_queue, save_queue
from gui.targets import load_targets, add_target, remove_target
from gui.template_manager import list_templates, toggle_template
from gui.workspace import load_workspace, save_workspace
from analysis.diff import compare_scans
from analysis.export import export_findings_csv


def make_card(title: str, value: str = "-") -> tuple[QFrame, QLabel]:
    frame = QFrame()
    frame.setObjectName("Card")

    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 14)

    title_label = QLabel(title)
    title_label.setObjectName("CardTitle")

    value_label = QLabel(value)
    value_label.setObjectName("CardValue")

    layout.addWidget(title_label)
    layout.addWidget(value_label)

    return frame, value_label


class MainWindow(QMainWindow):
    PAGE_DASHBOARD = 0
    PAGE_SCAN = 1
    PAGE_RESULTS = 2
    PAGE_PROJECT = 3
    PAGE_SETTINGS = 4

    def __init__(self) -> None:
        super().__init__()

        self.settings = load_settings()
        self.result: dict = {}
        self.scan_diff: dict = {}
        self.scan_queue = load_queue()
        self.current_queue_item_id: str | None = None

        self.thread: QThread | None = None
        self.worker: ScanWorker | None = None

        self.setWindowTitle("A.C.R Vuln — Security Scanner")
        self.resize(1420, 880)
        self.setMinimumSize(1080, 700)

        self._build_ui()
        self._load_settings_to_ui()

        self.populate_history()
        self.populate_queue()
        self.populate_saved_targets()
        self.populate_templates()

        self.show_page(self.PAGE_DASHBOARD)

    def _icon(self, name: str) -> QIcon:
        path = Path(__file__).resolve().parent / "icons" / name
        return QIcon(str(path))

    def _set_button_icon(self, button: QPushButton, icon_name: str) -> None:
        button.setIcon(self._icon(icon_name))
        button.setIconSize(QSize(16, 16))

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)

        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._build_sidebar(layout)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        self._build_dashboard()
        self._build_scan_page()
        self._build_results_page()
        self._build_project_page()
        self._build_settings_page()

    def _build_sidebar(self, root_layout: QHBoxLayout) -> None:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(210)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 22, 16, 18)
        layout.setSpacing(8)

        brand_row = QHBoxLayout()
        brand_row.setSpacing(0)

        left = QLabel("A.C.R ")
        left.setObjectName("Brand")

        right = QLabel("Vuln")
        right.setObjectName("BrandAccent")

        brand_row.addWidget(left)
        brand_row.addWidget(right)
        brand_row.addStretch()

        subtitle = QLabel("Security Scanner")
        subtitle.setObjectName("Subtitle")

        layout.addLayout(brand_row)
        layout.addWidget(subtitle)
        layout.addSpacing(22)

        nav_items = (
            ("Dashboard", "dashboard.svg", self.PAGE_DASHBOARD),
            ("New Scan", "scan.svg", self.PAGE_SCAN),
            ("Results", "findings.svg", self.PAGE_RESULTS),
            ("Project", "targets.svg", self.PAGE_PROJECT),
            ("Settings", "settings.svg", self.PAGE_SETTINGS),
        )

        self.nav_buttons: list[tuple[QPushButton, int]] = []

        for label, icon_name, page in nav_items:
            button = QPushButton(label)
            button.setObjectName("NavButton")
            button.setCursor(Qt.PointingHandCursor)
            self._set_button_icon(button, icon_name)
            button.clicked.connect(
                lambda checked=False, p=page: self.show_page(p)
            )
            layout.addWidget(button)
            self.nav_buttons.append((button, page))

        layout.addStretch()

        version = QLabel("A.C.R Vuln • V8")
        version.setObjectName("Subtitle")
        layout.addWidget(version)

        root_layout.addWidget(sidebar)

    def _page(self, title: str, subtitle: str) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        title_label = QLabel(title)
        title_label.setObjectName("SectionTitle")

        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("SectionDescription")

        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)

        return page, layout

    def _create_table(self, headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        return table

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def _build_dashboard(self) -> None:
        page, layout = self._page(
            "Dashboard",
            "Summary of the latest scan.",
        )

        row1 = QHBoxLayout()

        self.card_target, self.dashboard_target = make_card("TARGET")
        self.card_quality, self.dashboard_quality = make_card("QUALITY")
        self.card_risk, self.dashboard_risk = make_card("RISK SCORE")
        self.card_findings, self.dashboard_findings = make_card("FINDINGS")

        for widget in (
            self.card_target,
            self.card_quality,
            self.card_risk,
            self.card_findings,
        ):
            row1.addWidget(widget)

        layout.addLayout(row1)

        row2 = QHBoxLayout()

        self.card_ports, self.dashboard_ports = make_card("OPEN PORTS")
        self.card_tech, self.dashboard_tech = make_card("TECHNOLOGIES")
        self.card_cves, self.dashboard_cves = make_card("CVEs")
        self.card_coverage, self.dashboard_coverage = make_card("COVERAGE")

        for widget in (
            self.card_ports,
            self.card_tech,
            self.card_cves,
            self.card_coverage,
        ):
            row2.addWidget(widget)

        layout.addLayout(row2)

        quality_row = QHBoxLayout()
        self.card_confirmed, self.dashboard_confirmed = make_card("CONFIRMED")
        self.card_likely, self.dashboard_likely = make_card("LIKELY")
        self.card_detected, self.dashboard_detected = make_card("DETECTED")
        self.card_false_positive, self.dashboard_false_positive = make_card("FALSE POSITIVES")
        for widget in (self.card_confirmed, self.card_likely, self.card_detected, self.card_false_positive):
            quality_row.addWidget(widget)
        layout.addLayout(quality_row)

        self.dashboard_log = QPlainTextEdit()
        self.dashboard_log.setReadOnly(True)
        self.dashboard_log.setPlaceholderText(
            "Latest scan events will appear here."
        )

        layout.addWidget(self.dashboard_log, 1)

        self.stack.addWidget(page)

    # ------------------------------------------------------------------
    # Scan page
    # ------------------------------------------------------------------

    def _build_scan_page(self) -> None:
        page, layout = self._page(
            "New Scan",
            "Choose a target and profile, then start the scan.",
        )

        panel = QFrame()
        panel.setObjectName("Card")

        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(20, 20, 20, 20)
        panel_layout.setSpacing(12)

        row = QHBoxLayout()

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(
            "Domain or IP, e.g. demo.owasp-juice.shop"
        )
        self.target_input.returnPressed.connect(self.start_scan)

        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["FAST", "NORMAL", "DEEP"])

        self.start_button = QPushButton("Start Scan")
        self.start_button.setObjectName("Primary")
        self._set_button_icon(self.start_button, "play.svg")
        self.start_button.clicked.connect(self.start_scan)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("Danger")
        self._set_button_icon(self.cancel_button, "stop.svg")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)

        row.addWidget(self.target_input, 1)
        row.addWidget(self.profile_combo)
        row.addWidget(self.start_button)
        row.addWidget(self.cancel_button)

        panel_layout.addLayout(row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)

        self.scan_status = QLabel("Ready")
        self.scan_status.setObjectName("SectionDescription")

        panel_layout.addWidget(self.progress)
        panel_layout.addWidget(self.scan_status)

        layout.addWidget(panel)

        self.scan_log = QPlainTextEdit()
        self.scan_log.setReadOnly(True)

        layout.addWidget(self.scan_log, 1)

        self.stack.addWidget(page)

    # ------------------------------------------------------------------
    # Results page — everything grouped in tabs
    # ------------------------------------------------------------------

    def _build_results_page(self) -> None:
        page, layout = self._page(
            "Results",
            "All scan results are grouped here to keep navigation simple.",
        )

        self.results_tabs = QTabWidget()

        self._build_overview_tab()
        self._build_recon_tab()
        self._build_findings_tab()
        self._build_technologies_tab()
        self._build_correlation_tab()
        self._build_cve_tab()
        self._build_diff_tab()
        self._build_reports_tab()

        layout.addWidget(self.results_tabs, 1)

        self.stack.addWidget(page)

    def _build_overview_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.surface_table = self._create_table(
            [
                "Asset",
                "Port",
                "Service",
                "Technology",
                "Version",
                "Finding",
            ]
        )

        self.asset_table = self._create_table(
            ["Type", "Value", "Source"]
        )

        inner = QTabWidget()
        inner.addTab(self.surface_table, "Attack Surface")
        inner.addTab(self.asset_table, "Assets")
        self.endpoint_table = self._create_table(["Method", "Categories", "Source", "Status", "URL"])
        self.js_table = self._create_table(["Type", "Value"])
        self.api_table = self._create_table(["Field", "Value"])
        self.tls_table = self._create_table(["Field", "Value"])
        inner.addTab(self.endpoint_table, "Endpoints")
        inner.addTab(self.js_table, "JavaScript")
        inner.addTab(self.api_table, "API")
        inner.addTab(self.tls_table, "TLS")

        layout.addWidget(inner)

        self.results_tabs.addTab(tab, "Overview")

    def _build_recon_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        inner = QTabWidget()

        self.ports_table = self._create_table(
            ["Port", "Protocol", "Service", "Product", "Version", "Extra"]
        )
        self.dns_table = self._create_table(
            ["Record", "Value"]
        )
        self.http_table = self._create_table(
            ["Field", "Value"]
        )
        self.crawl_table = self._create_table(
            ["Status", "Depth", "Content Type", "URL"]
        )
        self.forms_table = self._create_table(
            ["Method", "Action", "Parameters"]
        )

        inner.addTab(self.ports_table, "Ports")
        inner.addTab(self.dns_table, "DNS")
        inner.addTab(self.http_table, "HTTP")
        inner.addTab(self.crawl_table, "Crawler")
        inner.addTab(self.forms_table, "Forms")

        layout.addWidget(inner)
        self.results_tabs.addTab(tab, "Recon")

    def _build_findings_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        controls = QHBoxLayout()

        self.finding_filter = QComboBox()
        self.finding_filter.addItems(
            ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        )
        self.finding_filter.currentTextChanged.connect(self.populate_findings)

        self.finding_search = QLineEdit()
        self.finding_search.setPlaceholderText(
            "Filter by title, category or URL"
        )
        self.finding_search.textChanged.connect(self.populate_findings)

        export_button = QPushButton("Export CSV")
        export_button.setObjectName("Secondary")
        self._set_button_icon(export_button, "export.svg")
        export_button.clicked.connect(self.export_findings_csv)

        controls.addWidget(self.finding_filter)
        controls.addWidget(self.finding_search, 1)
        controls.addWidget(export_button)

        self.findings_table = self._create_table(
            [
                "Severity",
                "Type",
                "Verification",
                "Title",
                "Confidence",
                "URL",
            ]
        )
        self.findings_table.itemSelectionChanged.connect(
            self.show_finding_details
        )

        self.finding_details = QPlainTextEdit()
        self.finding_details.setReadOnly(True)
        self.finding_details.setMaximumHeight(210)

        layout.addLayout(controls)
        layout.addWidget(self.findings_table, 1)
        layout.addWidget(self.finding_details)

        self.results_tabs.addTab(tab, "Findings")

    def _build_technologies_tab(self) -> None:
        self.technologies_table = self._create_table(
            [
                "Technology",
                "Version",
                "Port",
                "Confidence",
                "Intel Score",
                "Version Confidence",
                "Source",
            ]
        )
        self.results_tabs.addTab(self.technologies_table, "Technologies")

    def _build_correlation_tab(self) -> None:
        self.correlation_table = self._create_table(
            ["Endpoint", "Technologies", "Findings", "CVEs"]
        )
        self.results_tabs.addTab(self.correlation_table, "Correlation")

    def _build_cve_tab(self) -> None:
        tab = QTabWidget()

        self.cpe_table = self._create_table(
            ["Product", "Version", "Status", "Confidence", "Mode", "Reason"]
        )
        self.cve_table = self._create_table(
            ["CVE", "Technology", "Version", "Severity", "CVSS", "Port", "Match"]
        )

        tab.addTab(self.cpe_table, "CPE")
        tab.addTab(self.cve_table, "CVE")

        self.results_tabs.addTab(tab, "CVE / CPE")

    def _build_diff_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.diff_summary = QLabel(
            "No previous scan of this target is available."
        )
        self.diff_summary.setObjectName("SectionDescription")

        self.diff_table = self._create_table(
            ["Change", "Type", "Item", "Details"]
        )

        layout.addWidget(self.diff_summary)
        layout.addWidget(self.diff_table, 1)

        self.results_tabs.addTab(tab, "Changes")

    def _build_reports_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.report_json_label = QLabel("JSON: -")
        self.report_html_label = QLabel("HTML: -")
        self.report_md_label = QLabel("Markdown: -")
        self.report_pentest_label = QLabel("Pentest V2: -")

        for label in (
            self.report_json_label,
            self.report_html_label,
            self.report_md_label,
            self.report_pentest_label,
        ):
            label.setWordWrap(True)
            layout.addWidget(label)

        actions = QHBoxLayout()

        open_html = QPushButton("Open HTML")
        open_html.setObjectName("Primary")
        open_html.clicked.connect(lambda: self.open_report("html"))

        open_json = QPushButton("Open JSON")
        open_json.setObjectName("Secondary")
        open_json.clicked.connect(lambda: self.open_report("json"))

        open_md = QPushButton("Open Markdown")
        open_md.setObjectName("Secondary")
        open_md.clicked.connect(lambda: self.open_report("markdown"))

        open_pentest = QPushButton("Open Pentest V2")
        open_pentest.setObjectName("Secondary")
        open_pentest.clicked.connect(lambda: self.open_report("pentest_v2"))

        open_folder = QPushButton("Open Folder")
        open_folder.setObjectName("Secondary")
        open_folder.clicked.connect(self.open_reports_folder)

        actions.addWidget(open_html)
        actions.addWidget(open_json)
        actions.addWidget(open_md)
        actions.addWidget(open_pentest)
        actions.addWidget(open_folder)
        actions.addStretch()

        layout.addLayout(actions)
        layout.addStretch()

        self.results_tabs.addTab(tab, "Reports")

    # ------------------------------------------------------------------
    # Project page — targets, queue, workspace, history
    # ------------------------------------------------------------------

    def _build_project_page(self) -> None:
        page, layout = self._page(
            "Project",
            "Targets, queue, notes and history are grouped here.",
        )

        self.project_tabs = QTabWidget()

        self._build_targets_tab()
        self._build_queue_tab()
        self._build_workspace_tab()
        self._build_history_tab()

        layout.addWidget(self.project_tabs, 1)

        self.stack.addWidget(page)

    def _build_targets_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        controls = QHBoxLayout()

        self.saved_target_input = QLineEdit()
        self.saved_target_input.setPlaceholderText("Domain or IP")

        self.saved_target_label = QLineEdit()
        self.saved_target_label.setPlaceholderText("Label")

        self.saved_target_profile = QComboBox()
        self.saved_target_profile.addItems(["FAST", "NORMAL", "DEEP"])

        add_button = QPushButton("Save")
        add_button.setObjectName("Secondary")
        add_button.clicked.connect(self.save_current_target)

        scan_button = QPushButton("Scan Selected")
        scan_button.setObjectName("Primary")
        scan_button.clicked.connect(self.scan_selected_saved_target)

        remove_button = QPushButton("Remove")
        remove_button.setObjectName("Secondary")
        remove_button.clicked.connect(self.remove_selected_saved_target)

        controls.addWidget(self.saved_target_input, 1)
        controls.addWidget(self.saved_target_label)
        controls.addWidget(self.saved_target_profile)
        controls.addWidget(add_button)
        controls.addWidget(scan_button)
        controls.addWidget(remove_button)

        self.saved_targets_table = self._create_table(
            ["Label", "Target", "Profile"]
        )

        layout.addLayout(controls)
        layout.addWidget(self.saved_targets_table, 1)

        self.project_tabs.addTab(tab, "Targets")

    def _build_queue_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        controls = QHBoxLayout()

        self.queue_target_input = QLineEdit()
        self.queue_target_input.setPlaceholderText("Domain or IP")

        self.queue_profile_combo = QComboBox()
        self.queue_profile_combo.addItems(["FAST", "NORMAL", "DEEP"])

        add_button = QPushButton("Add")
        add_button.setObjectName("Secondary")
        add_button.clicked.connect(self.add_queue_item)

        run_button = QPushButton("Run Next")
        run_button.setObjectName("Primary")
        run_button.clicked.connect(self.run_next_queue_item)

        clear_button = QPushButton("Clear Completed")
        clear_button.setObjectName("Secondary")
        clear_button.clicked.connect(self.clear_completed_queue)

        controls.addWidget(self.queue_target_input, 1)
        controls.addWidget(self.queue_profile_combo)
        controls.addWidget(add_button)
        controls.addWidget(run_button)
        controls.addWidget(clear_button)

        self.queue_table = self._create_table(
            ["ID", "Target", "Profile", "Status", "Summary"]
        )

        layout.addLayout(controls)
        layout.addWidget(self.queue_table, 1)

        self.project_tabs.addTab(tab, "Queue")

    def _build_workspace_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        form = QFormLayout()

        self.workspace_target = QLineEdit()
        self.workspace_target.setPlaceholderText("Target domain or IP")

        self.workspace_scope = QPlainTextEdit()
        self.workspace_scope.setPlaceholderText("One scope entry per line")
        self.workspace_scope.setMaximumHeight(110)

        self.workspace_notes = QPlainTextEdit()
        self.workspace_notes.setPlaceholderText("Pentest notes")

        form.addRow("Target", self.workspace_target)
        form.addRow("Scope", self.workspace_scope)
        form.addRow("Notes", self.workspace_notes)

        actions = QHBoxLayout()

        load_button = QPushButton("Load")
        load_button.setObjectName("Secondary")
        load_button.clicked.connect(self.load_workspace_ui)

        save_button = QPushButton("Save")
        save_button.setObjectName("Primary")
        save_button.clicked.connect(self.save_workspace_ui)

        actions.addWidget(load_button)
        actions.addWidget(save_button)
        actions.addStretch()

        self.workspace_last_scan = QPlainTextEdit()
        self.workspace_last_scan.setReadOnly(True)

        layout.addLayout(form)
        layout.addLayout(actions)
        layout.addWidget(self.workspace_last_scan, 1)

        self.project_tabs.addTab(tab, "Workspace")

    def _build_history_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        actions = QHBoxLayout()

        refresh_button = QPushButton("Refresh")
        refresh_button.setObjectName("Secondary")
        refresh_button.clicked.connect(self.populate_history)

        open_button = QPushButton("Open HTML")
        open_button.setObjectName("Secondary")
        open_button.clicked.connect(self.open_history_report)

        clear_button = QPushButton("Clear")
        clear_button.setObjectName("Danger")
        clear_button.clicked.connect(self.clear_scan_history)

        actions.addWidget(refresh_button)
        actions.addWidget(open_button)
        actions.addWidget(clear_button)
        actions.addStretch()

        self.history_table = self._create_table(
            [
                "Date",
                "Target",
                "Profile",
                "Quality",
                "Coverage",
                "Risk",
                "Findings",
                "CVEs",
                "Duration",
            ]
        )

        layout.addLayout(actions)
        layout.addWidget(self.history_table, 1)

        self.project_tabs.addTab(tab, "History")

    # ------------------------------------------------------------------
    # Settings — scanner options + templates only
    # ------------------------------------------------------------------

    def _build_settings_page(self) -> None:
        page, layout = self._page(
            "Settings",
            "Scanner defaults and template management.",
        )

        tabs = QTabWidget()

        scanner_tab = QWidget()
        form = QFormLayout(scanner_tab)

        self.settings_profile = QComboBox()
        self.settings_profile.addItems(["FAST", "NORMAL", "DEEP"])

        self.settings_json = QCheckBox("Generate JSON report")
        self.settings_html = QCheckBox("Generate HTML report")
        self.settings_auto_open = QCheckBox("Open HTML after scan")
        self.settings_remember_target = QCheckBox("Remember last target")
        self.settings_history = QCheckBox("Store scan history")
        self.settings_confirm = QCheckBox("Confirm before scan")
        self.settings_allow_subdomains = QCheckBox("Allow in-scope subdomains")
        self.settings_resume = QCheckBox("Resume interrupted scans")
        self.settings_scope_exclusions = QLineEdit()
        self.settings_scope_exclusions.setPlaceholderText("*.excluded.example, admin.example.com")

        self.settings_max_cves = QSpinBox()
        self.settings_max_cves.setRange(10, 5000)
        self.settings_max_cves.setSingleStep(50)

        self.settings_reports = QLineEdit()
        browse_reports = QPushButton("Browse")
        browse_reports.setObjectName("Secondary")
        browse_reports.clicked.connect(self.choose_reports_dir)

        reports_row = QWidget()
        reports_layout = QHBoxLayout(reports_row)
        reports_layout.setContentsMargins(0, 0, 0, 0)
        reports_layout.addWidget(self.settings_reports, 1)
        reports_layout.addWidget(browse_reports)

        self.settings_templates = QLineEdit()
        browse_templates = QPushButton("Browse")
        browse_templates.setObjectName("Secondary")
        browse_templates.clicked.connect(self.choose_templates_dir)

        templates_row = QWidget()
        templates_layout = QHBoxLayout(templates_row)
        templates_layout.setContentsMargins(0, 0, 0, 0)
        templates_layout.addWidget(self.settings_templates, 1)
        templates_layout.addWidget(browse_templates)

        form.addRow("Default profile", self.settings_profile)
        form.addRow("Max CVEs / technology", self.settings_max_cves)
        form.addRow("Reports directory", reports_row)
        form.addRow("Templates directory", templates_row)
        form.addRow("", self.settings_json)
        form.addRow("", self.settings_html)
        form.addRow("", self.settings_auto_open)
        form.addRow("", self.settings_remember_target)
        form.addRow("", self.settings_history)
        form.addRow("", self.settings_confirm)
        form.addRow("", self.settings_allow_subdomains)
        form.addRow("Scope exclusions", self.settings_scope_exclusions)
        form.addRow("", self.settings_resume)

        system_label = QLabel(self._system_status_text())
        system_label.setWordWrap(True)
        system_label.setObjectName("SectionDescription")
        form.addRow("Environment", system_label)

        actions = QWidget()
        action_layout = QHBoxLayout(actions)
        action_layout.setContentsMargins(0, 0, 0, 0)

        save_button = QPushButton("Save Settings")
        save_button.setObjectName("Primary")
        save_button.clicked.connect(self.save_settings_from_ui)

        reset_button = QPushButton("Reset")
        reset_button.setObjectName("Secondary")
        reset_button.clicked.connect(self.reset_settings)

        action_layout.addWidget(save_button)
        action_layout.addWidget(reset_button)
        action_layout.addStretch()

        form.addRow("", actions)

        templates_tab = QWidget()
        templates_layout_main = QVBoxLayout(templates_tab)

        template_actions = QHBoxLayout()

        refresh_templates = QPushButton("Refresh")
        refresh_templates.setObjectName("Secondary")
        refresh_templates.clicked.connect(self.populate_templates)

        toggle_templates = QPushButton("Toggle Selected")
        toggle_templates.setObjectName("Secondary")
        toggle_templates.clicked.connect(self.toggle_selected_template)

        template_actions.addWidget(refresh_templates)
        template_actions.addWidget(toggle_templates)
        template_actions.addStretch()

        self.templates_table = self._create_table(
            ["Enabled", "ID", "Name", "Severity", "Tags", "File"]
        )

        templates_layout_main.addLayout(template_actions)
        templates_layout_main.addWidget(self.templates_table, 1)

        tabs.addTab(scanner_tab, "Scanner")
        tabs.addTab(templates_tab, "Templates")

        layout.addWidget(tabs, 1)

        self.stack.addWidget(page)

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def show_page(self, page: int) -> None:
        self.stack.setCurrentIndex(page)

        for button, button_page in self.nav_buttons:
            button.setProperty("active", button_page == page)
            button.style().unpolish(button)
            button.style().polish(button)

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def _system_status_text(self) -> str:
        nmap_path = shutil.which("nmap")

        return (
            f"Python {sys.version_info.major}.{sys.version_info.minor}"
            + " | "
            + (f"Nmap: {nmap_path}" if nmap_path else "Nmap: not found in PATH")
        )

    def _load_settings_to_ui(self) -> None:
        profile = str(self.settings.get("profile", "NORMAL")).upper()

        self.profile_combo.setCurrentText(profile)
        self.settings_profile.setCurrentText(profile)

        self.settings_json.setChecked(bool(self.settings.get("save_json", True)))
        self.settings_html.setChecked(bool(self.settings.get("save_html", True)))
        self.settings_auto_open.setChecked(
            bool(self.settings.get("auto_open_report", False))
        )
        self.settings_remember_target.setChecked(
            bool(self.settings.get("remember_target", False))
        )
        self.settings_history.setChecked(
            bool(self.settings.get("history_enabled", True))
        )
        self.settings_confirm.setChecked(
            bool(self.settings.get("confirm_before_scan", False))
        )
        self.settings_allow_subdomains.setChecked(bool(self.settings.get("allow_subdomains", True)))
        self.settings_scope_exclusions.setText(str(self.settings.get("scope_exclusions", "")))
        self.settings_resume.setChecked(bool(self.settings.get("resume_enabled", True)))

        self.settings_max_cves.setValue(
            int(self.settings.get("max_cves", 500))
        )
        self.settings_reports.setText(
            str(self.settings.get("reports_dir", ""))
        )
        self.settings_templates.setText(
            str(self.settings.get("templates_dir", ""))
        )

        if self.settings.get("remember_target"):
            self.target_input.setText(
                str(self.settings.get("last_target", ""))
            )

    def scan_options(self) -> dict:
        return {
            "save_json": bool(self.settings.get("save_json", True)),
            "save_html": bool(self.settings.get("save_html", True)),
            "reports_dir": self.settings.get("reports_dir"),
            "templates_dir": self.settings.get("templates_dir"),
            "max_cves": int(self.settings.get("max_cves", 500)),
            "allow_subdomains": bool(self.settings.get("allow_subdomains", True)),
            "scope_exclusions": [x.strip() for x in str(self.settings.get("scope_exclusions", "")).split(",") if x.strip()],
            "resume_enabled": bool(self.settings.get("resume_enabled", True)),
        }

    def save_settings_from_ui(self) -> None:
        self.settings.update(
            {
                "profile": self.settings_profile.currentText(),
                "save_json": self.settings_json.isChecked(),
                "save_html": self.settings_html.isChecked(),
                "auto_open_report": self.settings_auto_open.isChecked(),
                "remember_target": self.settings_remember_target.isChecked(),
                "history_enabled": self.settings_history.isChecked(),
                "confirm_before_scan": self.settings_confirm.isChecked(),
                "allow_subdomains": self.settings_allow_subdomains.isChecked(),
                "scope_exclusions": self.settings_scope_exclusions.text().strip(),
                "resume_enabled": self.settings_resume.isChecked(),
                "max_cves": self.settings_max_cves.value(),
                "reports_dir": self.settings_reports.text().strip(),
                "templates_dir": self.settings_templates.text().strip(),
            }
        )

        save_settings(self.settings)
        self.profile_combo.setCurrentText(self.settings["profile"])
        self.populate_templates()

        QMessageBox.information(
            self,
            "Settings",
            "Settings saved.",
        )

    def reset_settings(self) -> None:
        self.settings = dict(DEFAULTS)
        save_settings(self.settings)
        self._load_settings_to_ui()

    def choose_reports_dir(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select reports directory",
            self.settings_reports.text(),
        )
        if directory:
            self.settings_reports.setText(directory)

    def choose_templates_dir(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select templates directory",
            self.settings_templates.text(),
        )
        if directory:
            self.settings_templates.setText(directory)

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------

    def start_scan(self) -> None:
        if self.thread is not None:
            return

        target = self.target_input.text().strip()

        if not target:
            QMessageBox.warning(
                self,
                "A.C.R Vuln",
                "Enter a domain or IP address.",
            )
            return

        templates_dir = Path(
            str(self.settings.get("templates_dir", ""))
        )

        if not templates_dir.exists():
            QMessageBox.warning(
                self,
                "Templates directory",
                f"Templates directory not found:\n{templates_dir}",
            )
            return

        profile = self.profile_combo.currentText()

        if self.settings.get("confirm_before_scan", False):
            response = QMessageBox.question(
                self,
                "Start scan",
                (
                    f"Start a {profile} scan against:\n{target}\n\n"
                    "Continue only if you are authorized to assess this target."
                ),
            )

            if response != QMessageBox.Yes:
                return

        if self.settings.get("remember_target"):
            self.settings["last_target"] = target
            save_settings(self.settings)

        self.scan_log.clear()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.scan_status.setText("Starting scan...")

        self.start_button.setEnabled(False)
        self.cancel_button.setEnabled(True)

        self.show_page(self.PAGE_SCAN)

        self.thread = QThread(self)
        self.worker = ScanWorker(
            target,
            profile,
            self.scan_options(),
        )
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.on_progress)
        self.worker.log.connect(self.on_log)
        self.worker.completed.connect(self.on_scan_completed)
        self.worker.failed.connect(self.on_scan_failed)
        self.worker.cancelled_signal.connect(self.on_scan_cancelled)

        self.worker.completed.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.worker.cancelled_signal.connect(self.thread.quit)
        self.thread.finished.connect(self.cleanup_worker)

        self.thread.start()

    def cancel_scan(self) -> None:
        if self.worker is not None:
            self.worker.cancel()
            self.scan_status.setText("Cancellation requested...")

    def cleanup_worker(self) -> None:
        if self.worker is not None:
            self.worker.deleteLater()

        if self.thread is not None:
            self.thread.deleteLater()

        self.worker = None
        self.thread = None

        self.start_button.setEnabled(True)
        self.cancel_button.setEnabled(False)

    def on_progress(self, value: int, message: str) -> None:
        long_stage = any(
            marker in message.casefold()
            for marker in (
                "nmap",
                "ports and services",
                "cpe",
                "cve",
            )
        )

        if long_stage:
            self.progress.setRange(0, 0)
        else:
            if self.progress.maximum() == 0:
                self.progress.setRange(0, 100)
            self.progress.setValue(value)

        self.scan_status.setText(message)

    def on_log(self, message: str) -> None:
        self.scan_log.appendPlainText(f"[+] {message}")
        self.dashboard_log.appendPlainText(message)

    def on_scan_completed(self, result: dict) -> None:
        self.result = result

        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.scan_status.setText(
            f"Completed in {result.get('duration', 0)}s"
        )

        previous_snapshot = latest_snapshot_for_target(
            (result.get("target") or {}).get("original", "")
        )
        self.scan_diff = compare_scans(
            previous_snapshot,
            result,
        )

        self.populate_result_views()

        if self.settings.get("history_enabled", True):
            append_history(result)

        self.populate_history()

        if self.current_queue_item_id:
            for item in self.scan_queue:
                if item.id == self.current_queue_item_id:
                    item.status = "DONE"
                    item.result_summary = {
                        "findings": len(result.get("findings") or []),
                        "cves": len(result.get("vulnerabilities") or []),
                        "risk": (result.get("risk") or {}).get("score"),
                    }
                    break

            save_queue(self.scan_queue)
            self.current_queue_item_id = None
            self.populate_queue()

        html_path = (result.get("reports") or {}).get("html")

        if self.settings.get("auto_open_report") and html_path:
            QDesktopServices.openUrl(
                QUrl.fromLocalFile(
                    str(Path(html_path).resolve())
                )
            )

        self.show_page(self.PAGE_DASHBOARD)

    def on_scan_failed(self, error: str) -> None:
        self.progress.setRange(0, 100)
        self.scan_status.setText("Scan failed")
        self.scan_log.appendPlainText(f"[!] {error}")

        if self.current_queue_item_id:
            for item in self.scan_queue:
                if item.id == self.current_queue_item_id:
                    item.status = "FAILED"
                    break
            save_queue(self.scan_queue)
            self.current_queue_item_id = None
            self.populate_queue()

        QMessageBox.critical(
            self,
            "Scan failed",
            error,
        )

    def on_scan_cancelled(self) -> None:
        self.progress.setRange(0, 100)
        self.scan_status.setText("Scan cancelled")
        self.scan_log.appendPlainText("[!] Scan cancelled")

        if self.current_queue_item_id:
            for item in self.scan_queue:
                if item.id == self.current_queue_item_id:
                    item.status = "CANCELLED"
                    break
            save_queue(self.scan_queue)
            self.current_queue_item_id = None
            self.populate_queue()

    # ------------------------------------------------------------------
    # Populate results
    # ------------------------------------------------------------------

    def populate_result_views(self) -> None:
        result = self.result

        target = result.get("target") or {}
        health = result.get("scan_health") or {}
        risk = result.get("risk") or {}

        self.dashboard_target.setText(
            str(target.get("original") or "-")
        )
        self.dashboard_quality.setText(
            str(health.get("quality") or "-")
        )
        self.dashboard_risk.setText(
            f"{risk.get('score', 0)}/100"
            if health.get("risk_available", True)
            else "N/A"
        )
        self.dashboard_findings.setText(
            str(len(result.get("findings") or []))
        )
        self.dashboard_ports.setText(
            str(len(result.get("nmap") or {}))
        )
        self.dashboard_tech.setText(
            str(len(result.get("technologies") or []))
        )
        self.dashboard_cves.setText(
            str(len(result.get("vulnerabilities") or []))
        )
        self.dashboard_coverage.setText(
            f"{health.get('coverage', 0)}%"
        )

        verification_counts = {"CONFIRMED": 0, "LIKELY": 0, "DETECTED": 0, "FALSE_POSITIVE": 0}
        for finding in result.get("findings") or []:
            state = str(finding.get("verification_state") or finding.get("verification") or "DETECTED").upper()
            if state in verification_counts:
                verification_counts[state] += 1
        self.dashboard_confirmed.setText(str(verification_counts["CONFIRMED"]))
        self.dashboard_likely.setText(str(verification_counts["LIKELY"]))
        self.dashboard_detected.setText(str(verification_counts["DETECTED"]))
        self.dashboard_false_positive.setText(str(verification_counts["FALSE_POSITIVE"]))

        self.populate_attack_surface()
        self.populate_assets()
        self.populate_endpoint_intelligence()
        self.populate_js_analysis()
        self.populate_api_analysis()
        self.populate_tls_analysis()
        self.populate_recon()
        self.populate_findings()
        self.populate_technologies()
        self.populate_correlation()
        self.populate_cpe()
        self.populate_cves()
        self.populate_diff()

        reports = result.get("reports") or {}

        self.report_json_label.setText(
            f"JSON: {reports.get('json', '-')}"
        )
        self.report_html_label.setText(
            f"HTML: {reports.get('html', '-')}"
        )
        self.report_md_label.setText(
            f"Markdown: {reports.get('markdown', '-')}"
        )
        self.report_pentest_label.setText(
            f"Pentest V2: {reports.get('pentest_v2', '-')}"
        )

    def populate_attack_surface(self) -> None:
        target = self.result.get("target") or {}
        nmap = self.result.get("nmap") or {}
        technologies = self.result.get("technologies") or []
        findings = self.result.get("findings") or []

        tech_by_port = {}

        for technology in technologies:
            port = technology.get("port")
            if port is not None:
                tech_by_port.setdefault(
                    str(port),
                    [],
                ).append(technology)

        rows = []

        for port, service in nmap.items():
            service = service if isinstance(service, dict) else {}
            candidates = tech_by_port.get(str(port), [{}])

            for technology in candidates:
                related = [
                    finding
                    for finding in findings
                    if str(finding.get("port") or "") == str(port)
                ]

                rows.append(
                    [
                        target.get("original", ""),
                        port,
                        service.get("service", "-"),
                        technology.get("name")
                        or service.get("product", "-"),
                        technology.get("version")
                        or service.get("version")
                        or "Unknown",
                        ", ".join(
                            str(item.get("title") or item.get("id"))
                            for item in related[:2]
                        )
                        or "-",
                    ]
                )

        self.surface_table.setRowCount(len(rows))

        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                self.surface_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value)),
                )

    def populate_assets(self) -> None:
        assets = (
            self.result.get("assets")
            or {}
        ).get("assets") or []

        self.asset_table.setRowCount(len(assets))

        for row, asset in enumerate(assets):
            values = [
                asset.get("type", ""),
                asset.get("value", ""),
                asset.get("source", ""),
            ]

            for column, value in enumerate(values):
                self.asset_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value)),
                )

    def populate_endpoint_intelligence(self) -> None:
        items = (self.result.get("endpoint_intel") or {}).get("endpoints") or []
        self.endpoint_table.setRowCount(len(items))
        for row, item in enumerate(items):
            vals=[item.get("method",""), ", ".join(item.get("categories") or []), item.get("source",""), item.get("status","-"), item.get("url","")]
            for col,val in enumerate(vals): self.endpoint_table.setItem(row,col,QTableWidgetItem(str(val)))

    def populate_js_analysis(self) -> None:
        data=self.result.get("js_analysis") or {}; rows=[]
        rows += [("API Endpoint",x) for x in data.get("api_endpoints") or []]
        rows += [("WebSocket",x) for x in data.get("websocket_endpoints") or []]
        rows += [("Parameter",x) for x in data.get("parameters") or []]
        rows += [("Source Map",x) for x in data.get("source_maps") or []]
        rows += [("Technology",f"{x.get('name')} ({x.get('confidence')})") for x in data.get("technologies") or []]
        self.js_table.setRowCount(len(rows))
        for row,(kind,val) in enumerate(rows): self.js_table.setItem(row,0,QTableWidgetItem(str(kind))); self.js_table.setItem(row,1,QTableWidgetItem(str(val)))

    def populate_api_analysis(self) -> None:
        data=self.result.get("api_analysis") or {}; rows=[("Types",", ".join(data.get("types") or []) or "-"),("Methods",", ".join(data.get("methods") or []) or "-"),("Endpoint Count",data.get("endpoint_count",0)),("Parameter Count",data.get("parameter_count",0)),("Documentation",", ".join(data.get("documentation_endpoints") or []) or "-"),("Public Candidates",len(data.get("public_candidates") or []))]
        self.api_table.setRowCount(len(rows))
        for row,(field,val) in enumerate(rows): self.api_table.setItem(row,0,QTableWidgetItem(str(field))); self.api_table.setItem(row,1,QTableWidgetItem(str(val)))

    def populate_tls_analysis(self) -> None:
        data=self.result.get("tls") or {}; cert=data.get("certificate") or {}; rows=[("Enabled",data.get("enabled",False)),("Host",data.get("host","-")),("Port",data.get("port","-")),("TLS Version",data.get("version","-")),("Cipher",data.get("cipher","-")),("Days Remaining",data.get("days_remaining","-")),("SANs",", ".join(cert.get("sans") or []) or "-"),("Issuer",json.dumps(cert.get("issuer") or {},ensure_ascii=False))]
        self.tls_table.setRowCount(len(rows))
        for row,(field,val) in enumerate(rows): self.tls_table.setItem(row,0,QTableWidgetItem(str(field))); self.tls_table.setItem(row,1,QTableWidgetItem(str(val)))

    def populate_recon(self) -> None:
        dns = self.result.get("dns") or {}

        dns_rows = []

        for record_type, values in dns.items():
            values = (
                values
                if isinstance(values, (list, tuple, set))
                else [values]
            )

            for value in values:
                if value:
                    dns_rows.append((record_type, value))

        self.dns_table.setRowCount(len(dns_rows))

        for row, (record_type, value) in enumerate(dns_rows):
            self.dns_table.setItem(
                row,
                0,
                QTableWidgetItem(str(record_type)),
            )
            self.dns_table.setItem(
                row,
                1,
                QTableWidgetItem(str(value)),
            )

        nmap = self.result.get("nmap") or {}

        self.ports_table.setRowCount(len(nmap))

        for row, (port, service) in enumerate(nmap.items()):
            service = service if isinstance(service, dict) else {}

            values = [
                port,
                service.get("protocol", "-"),
                service.get("service", "-"),
                service.get("product", "-"),
                service.get("version", "-"),
                service.get("extra", "-"),
            ]

            for column, value in enumerate(values):
                self.ports_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(
                        str(value if value is not None else "-")
                    ),
                )

        http = self.result.get("http") or {}

        http_rows = [
            (key, value)
            for key, value in http.items()
            if not isinstance(
                value,
                (dict, list, tuple, set, bytes),
            )
        ]

        self.http_table.setRowCount(len(http_rows))

        for row, (key, value) in enumerate(http_rows):
            self.http_table.setItem(
                row,
                0,
                QTableWidgetItem(str(key)),
            )
            self.http_table.setItem(
                row,
                1,
                QTableWidgetItem(str(value)),
            )

        crawl = self.result.get("crawl") or {}
        pages = crawl.get("pages") or []

        self.crawl_table.setRowCount(len(pages))

        for row, page in enumerate(pages):
            values = [
                page.get("status", "-"),
                page.get("depth", "-"),
                page.get("content_type", "-"),
                page.get("url", "-"),
            ]

            for column, value in enumerate(values):
                self.crawl_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value)),
                )

        forms = crawl.get("forms") or []

        self.forms_table.setRowCount(len(forms))

        for row, form in enumerate(forms):
            values = [
                form.get("method", "GET"),
                form.get("action", ""),
                ", ".join(form.get("parameters") or []),
            ]

            for column, value in enumerate(values):
                self.forms_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value)),
                )

    def populate_findings(self) -> None:
        findings = self.result.get("findings") or []

        severity_filter = self.finding_filter.currentText()
        query = self.finding_search.text().strip().casefold()

        filtered = []

        for finding in findings:
            severity = str(
                finding.get("severity") or "UNKNOWN"
            ).upper()

            if severity_filter != "ALL" and severity != severity_filter:
                continue

            haystack = " ".join(
                str(finding.get(key) or "")
                for key in (
                    "title",
                    "category",
                    "url",
                    "evidence",
                    "id",
                )
            ).casefold()

            if query and query not in haystack:
                continue

            filtered.append(finding)

        self.findings_table.setRowCount(len(filtered))

        for row, finding in enumerate(filtered):
            values = [
                finding.get("severity"),
                finding.get("classification")
                or finding.get("category"),
                finding.get("verification_state") or finding.get("verification", "DETECTED"),
                finding.get("title"),
                finding.get("confidence"),
                finding.get("url"),
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value or ""))
                item.setData(Qt.UserRole, finding)
                self.findings_table.setItem(row, column, item)

    def show_finding_details(self) -> None:
        rows = self.findings_table.selectionModel().selectedRows()

        if not rows:
            return

        item = self.findings_table.item(
            rows[0].row(),
            0,
        )

        finding = item.data(Qt.UserRole) or {}

        self.finding_details.setPlainText(
            "\n".join(
                [
                    f"ID: {finding.get('id', '')}",
                    f"Title: {finding.get('title', '')}",
                    f"Severity: {finding.get('severity', '')}",
                    f"Priority: {finding.get('priority', '-')}",
                    f"Priority Score: {finding.get('priority_score', '-')}",
                    f"Confidence: {finding.get('confidence', '')}",
                    f"Verification: {finding.get('verification', '')}",
                    f"Category: {finding.get('category', '')}",
                    f"URL: {finding.get('url', '')}",
                    "",
                    f"Evidence:\n{finding.get('evidence', '')}",
                    "",
                    f"Recommendation:\n{finding.get('recommendation', '')}",
                ]
            )
        )

    def populate_technologies(self) -> None:
        items = self.result.get("technologies") or []

        self.technologies_table.setRowCount(len(items))

        for row, technology in enumerate(items):
            values = [
                technology.get("name"),
                technology.get("version") or "Unknown",
                technology.get("port") or "-",
                technology.get("confidence") or "-",
                technology.get("confidence_score") or "-",
                technology.get("version_confidence") or "-",
                technology.get("source") or "-",
            ]

            for column, value in enumerate(values):
                self.technologies_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value)),
                )

    def populate_correlation(self) -> None:
        rows = self.result.get("correlation") or []
        self.correlation_table.setRowCount(len(rows))
        for row, item in enumerate(rows):
            endpoint = item.get("endpoint") or {}
            techs = ", ".join(str(x.get("name") or "") for x in item.get("technologies") or [])
            findings = ", ".join(str(x.get("title") or "") for x in item.get("findings") or [])
            cves = ", ".join(str((x.get("cve") or {}).get("id") or "") for x in item.get("vulnerabilities") or [])
            values = [endpoint.get("url", ""), techs, findings, cves]
            for col, value in enumerate(values):
                self.correlation_table.setItem(row, col, QTableWidgetItem(str(value)))

    def populate_cpe(self) -> None:
        items = self.result.get("cpe_diagnostics") or []

        self.cpe_table.setRowCount(len(items))

        for row, item in enumerate(items):
            values = [
                item.get("product"),
                item.get("version") or "Unknown",
                item.get("status"),
                item.get("confidence"),
                item.get("mode") or "-",
                item.get("reason") or "-",
            ]

            for column, value in enumerate(values):
                self.cpe_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value)),
                )

    def populate_cves(self) -> None:
        items = self.result.get("vulnerabilities") or []

        self.cve_table.setRowCount(len(items))

        for row, item in enumerate(items):
            cve = item.get("cve") or {}

            values = [
                cve.get("id"),
                item.get("technology"),
                item.get("version"),
                cve.get("severity"),
                cve.get("cvss"),
                item.get("port"),
                item.get("match_mode"),
            ]

            for column, value in enumerate(values):
                self.cve_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value or "-")),
                )

    def populate_diff(self) -> None:
        diff = self.scan_diff or {}

        if not diff.get("available"):
            self.diff_summary.setText(
                "No previous scan of this target is available."
            )
            self.diff_table.setRowCount(0)
            return

        rows = []

        for item in diff.get("new_findings") or []:
            rows.append(
                (
                    "NEW",
                    "Finding",
                    item.get("title", ""),
                    item.get("url", ""),
                )
            )

        for item in diff.get("resolved_findings") or []:
            rows.append(
                (
                    "RESOLVED",
                    "Finding",
                    item.get("title", ""),
                    item.get("url", ""),
                )
            )

        for item in diff.get("new_ports") or []:
            rows.append(
                (
                    "NEW",
                    "Port",
                    item.get("port", ""),
                    item.get("product", "") or item.get("service", ""),
                )
            )

        for item in diff.get("closed_ports") or []:
            rows.append(
                (
                    "CLOSED",
                    "Port",
                    item.get("port", ""),
                    item.get("product", "") or item.get("service", ""),
                )
            )

        for item in diff.get("new_technologies") or []:
            rows.append(
                (
                    "NEW",
                    "Technology",
                    item.get("name", ""),
                    item.get("version", "Unknown"),
                )
            )

        for item in diff.get("removed_technologies") or []:
            rows.append(
                (
                    "REMOVED",
                    "Technology",
                    item.get("name", ""),
                    item.get("version", "Unknown"),
                )
            )

        self.diff_summary.setText(
            f"{len(rows)} change(s) detected compared with the previous scan."
        )

        self.diff_table.setRowCount(len(rows))

        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                self.diff_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value)),
                )

    # ------------------------------------------------------------------
    # Project helpers
    # ------------------------------------------------------------------

    def populate_queue(self) -> None:
        if not hasattr(self, "queue_table"):
            return

        self.queue_table.setRowCount(len(self.scan_queue))

        for row, item in enumerate(self.scan_queue):
            summary = ""

            if item.result_summary:
                summary = (
                    f"Findings={item.result_summary.get('findings', 0)} | "
                    f"CVEs={item.result_summary.get('cves', 0)} | "
                    f"Risk={item.result_summary.get('risk', '-')}"
                )

            values = [
                item.id,
                item.target,
                item.profile,
                item.status,
                summary,
            ]

            for column, value in enumerate(values):
                self.queue_table.setItem(
                    row,
                    column,
                    QTableWidgetItem(str(value)),
                )

    def add_queue_item(self) -> None:
        target = self.queue_target_input.text().strip()

        if not target:
            return

        item = QueueItem.create(
            target,
            self.queue_profile_combo.currentText(),
        )

        self.scan_queue.append(item)
        save_queue(self.scan_queue)
        self.queue_target_input.clear()
        self.populate_queue()

    def run_next_queue_item(self) -> None:
        if self.thread is not None:
            return

        pending = next(
            (
                item
                for item in self.scan_queue
                if item.status == "PENDING"
            ),
            None,
        )

        if pending is None:
            QMessageBox.information(
                self,
                "Queue",
                "No pending scan.",
            )
            return

        pending.status = "RUNNING"
        save_queue(self.scan_queue)

        self.current_queue_item_id = pending.id
        self.target_input.setText(pending.target)
        self.profile_combo.setCurrentText(pending.profile)

        self.populate_queue()
        self.start_scan()

    def clear_completed_queue(self) -> None:
        self.scan_queue = [
            item
            for item in self.scan_queue
            if item.status
            not in {"DONE", "FAILED", "CANCELLED"}
        ]

        save_queue(self.scan_queue)
        self.populate_queue()

    def populate_saved_targets(self) -> None:
        if not hasattr(self, "saved_targets_table"):
            return

        items = load_targets()

        self.saved_targets_table.setRowCount(len(items))

        for row, item in enumerate(items):
            values = [
                item.get("label", ""),
                item.get("target", ""),
                item.get("profile", "NORMAL"),
            ]

            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setData(Qt.UserRole, item)
                self.saved_targets_table.setItem(row, column, cell)

    def save_current_target(self) -> None:
        target = (
            self.saved_target_input.text().strip()
            or self.target_input.text().strip()
        )

        if not target:
            return

        add_target(
            target,
            self.saved_target_label.text().strip(),
            self.saved_target_profile.currentText(),
        )

        self.saved_target_input.clear()
        self.saved_target_label.clear()

        self.populate_saved_targets()

    def scan_selected_saved_target(self) -> None:
        rows = self.saved_targets_table.selectionModel().selectedRows()

        if not rows:
            return

        item = self.saved_targets_table.item(
            rows[0].row(),
            0,
        ).data(Qt.UserRole) or {}

        self.target_input.setText(
            str(item.get("target") or "")
        )
        self.profile_combo.setCurrentText(
            str(item.get("profile") or "NORMAL")
        )

        self.start_scan()

    def remove_selected_saved_target(self) -> None:
        rows = self.saved_targets_table.selectionModel().selectedRows()

        if not rows:
            return

        item = self.saved_targets_table.item(
            rows[0].row(),
            0,
        ).data(Qt.UserRole) or {}

        remove_target(
            str(item.get("target") or "")
        )
        self.populate_saved_targets()

    def load_workspace_ui(self) -> None:
        target = (
            self.workspace_target.text().strip()
            or self.target_input.text().strip()
            or (self.result.get("target") or {}).get("original", "")
        )

        if not target:
            return

        workspace = load_workspace(target)

        self.workspace_target.setText(target)
        self.workspace_scope.setPlainText(
            "\n".join(workspace.get("scope", []))
        )
        self.workspace_notes.setPlainText(
            str(workspace.get("notes", ""))
        )

        self.workspace_last_scan.setPlainText(
            json.dumps(
                workspace.get("last_scan"),
                indent=2,
                ensure_ascii=False,
            )
            if workspace.get("last_scan")
            else "No scan stored in this workspace."
        )

    def save_workspace_ui(self) -> None:
        target = self.workspace_target.text().strip()

        if not target:
            return

        workspace = load_workspace(target)
        workspace["scope"] = [
            line.strip()
            for line in self.workspace_scope.toPlainText().splitlines()
            if line.strip()
        ]
        workspace["notes"] = self.workspace_notes.toPlainText()

        save_workspace(target, workspace)

        QMessageBox.information(
            self,
            "Workspace",
            "Workspace saved.",
        )

    def populate_history(self) -> None:
        if not hasattr(self, "history_table"):
            return

        items = load_history()

        self.history_table.setRowCount(len(items))

        for row, item in enumerate(items):
            timestamp = str(item.get("timestamp", ""))

            try:
                date_text = datetime.fromisoformat(timestamp).strftime(
                    "%Y-%m-%d %H:%M"
                )
            except Exception:
                date_text = timestamp

            risk = item.get("risk_score")

            values = [
                date_text,
                item.get("target", ""),
                item.get("profile", ""),
                item.get("quality", ""),
                (
                    f"{item.get('coverage')}%"
                    if item.get("coverage") is not None
                    else "-"
                ),
                "N/A" if risk is None else f"{risk}/100",
                item.get("findings", 0),
                item.get("cves", 0),
                (
                    f"{item.get('duration')}s"
                    if item.get("duration") is not None
                    else "-"
                ),
            ]

            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setData(Qt.UserRole, item)
                self.history_table.setItem(row, column, cell)

    def open_history_report(self) -> None:
        rows = self.history_table.selectionModel().selectedRows()

        if not rows:
            return

        item = self.history_table.item(
            rows[0].row(),
            0,
        ).data(Qt.UserRole) or {}

        path = item.get("html_report")

        if not path or not Path(path).exists():
            QMessageBox.information(
                self,
                "History",
                "HTML report not available.",
            )
            return

        QDesktopServices.openUrl(
            QUrl.fromLocalFile(
                str(Path(path).resolve())
            )
        )

    def clear_scan_history(self) -> None:
        response = QMessageBox.question(
            self,
            "Clear history",
            "Delete all local scan history?",
        )

        if response != QMessageBox.Yes:
            return

        clear_history()
        self.populate_history()

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------

    def populate_templates(self) -> None:
        if not hasattr(self, "templates_table"):
            return

        items = list_templates(
            self.settings.get("templates_dir", "")
        )

        self.templates_table.setRowCount(len(items))

        for row, item in enumerate(items):
            values = [
                "YES" if item.get("enabled") else "NO",
                item.get("id", ""),
                item.get("name", ""),
                item.get("severity", ""),
                ", ".join(item.get("tags") or []),
                Path(item.get("path", "")).name,
            ]

            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setData(Qt.UserRole, item)
                self.templates_table.setItem(row, column, cell)

    def toggle_selected_template(self) -> None:
        rows = self.templates_table.selectionModel().selectedRows()

        if not rows:
            return

        item = self.templates_table.item(
            rows[0].row(),
            0,
        ).data(Qt.UserRole) or {}

        try:
            toggle_template(
                item.get("path", ""),
                not bool(item.get("enabled", True)),
            )
        except Exception as exc:
            QMessageBox.warning(
                self,
                "Template",
                str(exc),
            )
            return

        self.populate_templates()

    # ------------------------------------------------------------------
    # Reports / export
    # ------------------------------------------------------------------

    def export_findings_csv(self) -> None:
        findings = self.result.get("findings") or []

        if not findings:
            QMessageBox.information(
                self,
                "Export",
                "No findings available.",
            )
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export findings",
            "acr_vuln_findings.csv",
            "CSV files (*.csv)",
        )

        if not path:
            return

        export_findings_csv(findings, path)

        QMessageBox.information(
            self,
            "Export",
            f"Findings exported to:\n{path}",
        )

    def open_report(self, kind: str) -> None:
        path = (self.result.get("reports") or {}).get(kind)

        if not path or not Path(path).exists():
            QMessageBox.information(
                self,
                "Reports",
                "This report is not available yet.",
            )
            return

        QDesktopServices.openUrl(
            QUrl.fromLocalFile(
                str(Path(path).resolve())
            )
        )

    def open_reports_folder(self) -> None:
        path = Path(
            str(self.settings.get("reports_dir", ""))
        )

        path.mkdir(
            parents=True,
            exist_ok=True,
        )

        QDesktopServices.openUrl(
            QUrl.fromLocalFile(
                str(path.resolve())
            )
        )

    def closeEvent(self, event) -> None:
        if self.worker is not None:
            self.worker.cancel()

        event.accept()


def run_app() -> int:
    app = QApplication([])
    app.setApplicationName("A.C.R Vuln")
    app.setStyleSheet(APP_STYLESHEET)

    window = MainWindow()
    window.show()

    return app.exec()
