# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Hidden imports to ensure all dynamic modules and database drivers are packaged
hidden_imports = [
    "correlator",
    "correlator.acquisition",
    "correlator.advanced_decryptor",
    "correlator.case_compare",
    "correlator.case_manager",
    "correlator.cli",
    "correlator.consolidated_db",
    "correlator.correlate",
    "correlator.diagnostics",
    "correlator.dump_ingest",
    "correlator.engine",
    "correlator.entity_recognition",
    "correlator.evaluate",
    "correlator.export_formats",
    "correlator.geospatial",
    "correlator.gui",
    "correlator.importer",
    "correlator.inventory",
    "correlator.keychain",
    "correlator.media_gallery",
    "correlator.network_graph",
    "correlator.pairing",
    "correlator.pdf_report",
    "correlator.pipeline",
    "correlator.provenance",
    "correlator.report",
    "correlator.scanner",
    "correlator.search_engine",
    "correlator.sha256_custom",
    "correlator.sqlcipher_util",
    "correlator.timeline",
    "correlator.triage",
    "correlator.wal",
    "correlator.watchlists",
    "correlator.whatsapp_crypt",
    # External libraries
    "sqlcipher3",
    "sqlcipher3.dbapi2",
    "sqlite3",
    "cryptography",
    "cryptography.hazmat.backends.openssl",
    "cryptography.hazmat.primitives.ciphers",
    "cryptography.hazmat.primitives.ciphers.algorithms",
    "cryptography.hazmat.primitives.ciphers.modes",
    "reportlab",
    "reportlab.lib",
    "reportlab.platypus",
    "reportlab.pdfgen",
    "tkinter",
    "tkinter.ttk",
    "tkinter.filedialog",
    "tkinter.messagebox",
    "pydantic",
    "fastapi",
    "uvicorn",
    "openpyxl",
    "PIL",
]

# Collect any additional submodules
hidden_imports += collect_submodules("correlator")
hidden_imports += collect_submodules("sqlcipher3")

datas = []
# Include harness generators for demo data generation
datas += [
    ("harness/make_fake_extraction.py", "harness"),
    ("harness/make_fragmented_enclave.py", "harness"),
]

a = Analysis(
    ["entrypoint.py"],
    pathex=["src", "."],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "matplotlib",
        "numpy",
        "scipy",
        "pandas",
        "IPython",
        "jupyter",
        "torch",
        "tensorflow",
    ],
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
    name="IOSCorrelator",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # Disabled UPX to avoid AV false positives in enterprise forensic environments
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # False so GUI opens clean without terminal popup; CLI attaches via AttachConsole
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
