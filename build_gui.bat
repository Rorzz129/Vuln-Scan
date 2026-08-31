@echo off
setlocal
cd /d "%~dp0"

py -m pip install -U pyinstaller
py -m PyInstaller --clean --noconfirm acr_vuln.spec

echo.
echo Build complete: dist\ACR-Vuln.exe
pause
