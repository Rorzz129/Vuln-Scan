from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from core.scanner import Scanner, ScanCancelled


class ScanWorker(QObject):
    progress = Signal(int, str)
    log = Signal(str)
    completed = Signal(dict)
    failed = Signal(str)
    cancelled_signal = Signal()

    def __init__(self, target: str, profile: str, options: dict):
        super().__init__()
        self.target = target
        self.profile = profile
        self.options = options
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @Slot()
    def run(self) -> None:
        try:
            scanner = Scanner(
                self.target,
                self.profile,
                reports_dir=self.options.get("reports_dir"),
                templates_dir=self.options.get("templates_dir"),
                save_json=self.options.get("save_json", True),
                save_html=self.options.get("save_html", True),
                max_cves_per_technology=self.options.get("max_cves", 500),
                allow_subdomains=self.options.get("allow_subdomains", True),
                scope_exclusions=self.options.get("scope_exclusions", []),
                resume_enabled=self.options.get("resume_enabled", True),
                progress=lambda value, message: self.progress.emit(value, message),
                log=lambda message: self.log.emit(message),
                cancelled=lambda: self._cancelled,
            )

            result = scanner.run()

            if self._cancelled:
                self.cancelled_signal.emit()
            else:
                self.completed.emit(result)

        except ScanCancelled:
            self.cancelled_signal.emit()
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
