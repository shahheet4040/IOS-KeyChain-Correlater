# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Specification File for iOS Keychain Correlator
==========================================================
Produces a standalone single-file or directory executable with
all web assets, templates, and cryptographic profiles bundled.
"""

from pathlib import Path
import sys

block_cipher = None

BASE_DIR = Path(__file__).resolve().parent

# Collect static assets
datas = [
    (str(BASE_DIR / 'src' / 'correlator' / 'web' / 'static'), 'correlator/web/static'),
    (str(BASE_DIR / 'src' / 'correlator' / 'data'), 'correlator/data'),
]

# Hidden imports needed by FastAPI, Uvicorn, SQLCipher, ReportLab
hiddenimports = [
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'sqlcipher3',
    'sqlcipher3.dbapi2',
    'reportlab',
    'reportlab.platypus',
    'reportlab.lib',
    'openpyxl',
    'pymobiledevice3',
]

a = Analysis(
    ['src/correlator/__main__.py'],
    pathex=[str(BASE_DIR / 'src')],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter.test', 'pytest'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='IOSKeychainCorrelator',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
