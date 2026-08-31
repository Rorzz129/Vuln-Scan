from pathlib import Path

project = Path(SPECPATH)

datas = []

for folder in (
    "templates",
    "gui/icons",
):
    path = project / folder

    if path.exists():
        datas.append(
            (str(path), folder)
        )

a = Analysis(
    ["main.pyw"],
    pathex=[str(project)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ACR-Vuln",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
)
