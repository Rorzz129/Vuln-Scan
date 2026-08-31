from __future__ import annotations

import os
import sys


def hide_console() -> None:
    if os.name != "nt":
        return

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32

        hwnd = kernel32.GetConsoleWindow()

        if hwnd:
            user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


hide_console()

from gui.main_window import run_app


if __name__ == "__main__":
    raise SystemExit(run_app())
