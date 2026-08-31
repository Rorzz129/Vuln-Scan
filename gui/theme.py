APP_STYLESHEET = r"""
* {
    font-family: "Segoe UI";
    font-size: 10pt;
}

QMainWindow,
QWidget {
    background-color: #07080a;
    color: #d2d6dc;
}

QLabel {
    background-color: transparent;
    color: #d2d6dc;
}

QFrame#Sidebar {
    background-color: #090b0e;
    border-right: 1px solid #181b20;
}

QLabel#Brand {
    color: #e9ebee;
    font-size: 19pt;
    font-weight: 800;
}

QLabel#BrandAccent {
    color: #aeb4bd;
    font-size: 19pt;
    font-weight: 800;
}

QLabel#Subtitle,
QLabel#SectionDescription {
    color: #777e88;
    background-color: transparent;
}

QLabel#SectionTitle {
    color: #ededee;
    font-size: 22pt;
    font-weight: 800;
    background-color: transparent;
}

QPushButton#NavButton {
    background-color: transparent;
    color: #8d949e;
    border: 1px solid transparent;
    border-radius: 7px;
    padding: 10px 12px;
    text-align: left;
    min-height: 24px;
}

QPushButton#NavButton:hover {
    background-color: #0f1115;
    color: #d8dbe0;
}

QPushButton#NavButton[active="true"] {
    background-color: #121419;
    color: #eceef1;
    border: 1px solid #1d2026;
    border-left: 2px solid #8f96a0;
}

QFrame#Card {
    background-color: #0c0e12;
    border: 1px solid #1a1d23;
    border-radius: 10px;
}

QFrame#Card QLabel {
    background-color: transparent;
}

QLabel#CardTitle {
    color: #707782;
    font-size: 9pt;
    font-weight: 600;
}

QLabel#CardValue {
    color: #e7e9ec;
    font-size: 19pt;
    font-weight: 800;
}

QLineEdit,
QComboBox,
QSpinBox {
    background-color: #0c0e12;
    color: #d5d9df;
    border: 1px solid #1e2229;
    border-radius: 7px;
    padding: 8px 10px;
    selection-background-color: #2a2e35;
    min-height: 22px;
}

QLineEdit:hover,
QComboBox:hover,
QSpinBox:hover {
    border-color: #2d323b;
}

QLineEdit:focus,
QComboBox:focus,
QSpinBox:focus {
    border-color: #575e68;
}

QComboBox::drop-down {
    border: none;
    width: 28px;
}

QComboBox QAbstractItemView {
    background-color: #0c0e12;
    color: #d5d9df;
    border: 1px solid #242831;
    selection-background-color: #1d2026;
    outline: none;
}

QPushButton#Primary,
QPushButton#Secondary,
QPushButton#Danger {
    border-radius: 7px;
    padding: 9px 15px;
    font-weight: 600;
}

QPushButton#Primary {
    background-color: #e6e8eb;
    color: #0b0c0e;
    border: 1px solid #e6e8eb;
}

QPushButton#Primary:hover {
    background-color: #f2f3f5;
    border-color: #f2f3f5;
}

QPushButton#Primary:pressed {
    background-color: #cfd3d8;
}

QPushButton#Secondary {
    background-color: #101216;
    color: #c7cbd1;
    border: 1px solid #22262d;
}

QPushButton#Secondary:hover {
    background-color: #15181d;
    color: #ebedef;
    border-color: #30353e;
}

QPushButton#Danger {
    background-color: #111216;
    color: #a8adb5;
    border: 1px solid #292d34;
}

QPushButton#Danger:hover {
    background-color: #17191e;
    color: #dedfe2;
    border-color: #3a3f48;
}

QPushButton:disabled {
    background-color: #0b0d10;
    color: #4c5159;
    border-color: #171a20;
}

QProgressBar {
    background-color: #0b0d10;
    color: #aeb4bd;
    border: 1px solid #1d2026;
    border-radius: 5px;
    text-align: center;
    min-height: 14px;
}

QProgressBar::chunk {
    background-color: #b7bcc4;
    border-radius: 4px;
}

QTableWidget {
    background-color: #090b0e;
    alternate-background-color: #0b0d10;
    color: #d0d4da;
    border: 1px solid #1a1d23;
    border-radius: 8px;
    gridline-color: #171a20;
    selection-background-color: #1b1e24;
    selection-color: #f0f1f2;
}

QHeaderView::section {
    background-color: #0d0f13;
    color: #858c96;
    border: none;
    border-right: 1px solid #1b1e24;
    border-bottom: 1px solid #1e2228;
    padding: 8px;
    font-weight: 700;
}

QTableWidget::item {
    background-color: transparent;
    padding: 7px;
    border: none;
}

QPlainTextEdit {
    background-color: #090b0e;
    color: #c9cdd3;
    border: 1px solid #1a1d23;
    border-radius: 8px;
    padding: 8px;
    font-family: "Cascadia Mono", "Consolas";
    selection-background-color: #24282f;
}

QTabWidget::pane {
    background-color: #090b0e;
    border: 1px solid #1a1d23;
    border-radius: 8px;
    top: -1px;
}

QTabBar::tab {
    background-color: transparent;
    color: #767d87;
    padding: 9px 14px;
    border: none;
    border-bottom: 2px solid transparent;
}

QTabBar::tab:hover {
    color: #b7bcc4;
}

QTabBar::tab:selected {
    color: #e4e6e9;
    border-bottom: 2px solid #8f96a0;
}

QCheckBox {
    color: #c6cad0;
    spacing: 8px;
    background-color: transparent;
}

QCheckBox::indicator {
    width: 15px;
    height: 15px;
    border-radius: 3px;
    border: 1px solid #333841;
    background-color: #0c0e12;
}

QCheckBox::indicator:checked {
    background-color: #aeb4bd;
    border-color: #aeb4bd;
}

QScrollBar:vertical {
    background-color: #08090b;
    width: 9px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background-color: #262a31;
    min-height: 28px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #343942;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0;
}

QLabel#MutedStatus {
    color: #777e88;
    background-color: transparent;
}

QToolTip {
    background-color: #111318;
    color: #d9dce1;
    border: 1px solid #2b3038;
    padding: 5px;
}
"""
