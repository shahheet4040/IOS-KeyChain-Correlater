"""
Graphical User Interface (GUI) for iOS Keychain Correlator.
A modern, professional digital forensics workstation interface designed for
clarity, ease-of-use, and court-ready evidence examination.
"""

import csv
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional, Set, Tuple

# Optional high-DPI awareness on Windows
try:
    import ctypes
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        ctypes.windll.user32.SetProcessDPIAware()
except Exception:
    pass

from correlator.diagnostics import diagnose_exception, format_diagnostic_box, run_system_doctor
from correlator.pdf_report import generate_case_pdf
from correlator.pipeline import execute_pipeline


# ── Color Palettes & Modern Themes ────────────────────────────────────

THEMES = {
    "dark": {
        "bg_root": "#0b0f19",
        "bg_card": "#151d2f",
        "bg_surface": "#1e293b",
        "bg_input": "#0f172a",
        "border": "#2d3748",
        "border_focus": "#38bdf8",
        "text_primary": "#f8fafc",
        "text_secondary": "#94a3b8",
        "text_muted": "#64748b",
        "accent_primary": "#2563eb",
        "accent_hover": "#1d4ed8",
        "accent_cyan": "#06b6d4",
        "badge_success_bg": "#064e3b",
        "badge_success_fg": "#34d399",
        "badge_plain_bg": "#1e3a8a",
        "badge_plain_fg": "#60a5fa",
        "badge_locked_bg": "#7f1d1d",
        "badge_locked_fg": "#f87171",
        "badge_warn_bg": "#78350f",
        "badge_warn_fg": "#fbbf24",
        "log_bg": "#080c14",
        "log_fg": "#e2e8f0",
        "tree_bg": "#151d2f",
        "tree_fg": "#f8fafc",
        "tree_heading_bg": "#1e293b",
        "tree_heading_fg": "#94a3b8",
        "tree_select_bg": "#2563eb",
        "tree_select_fg": "#ffffff",
    },
    "light": {
        "bg_root": "#f1f5f9",
        "bg_card": "#ffffff",
        "bg_surface": "#f8fafc",
        "bg_input": "#ffffff",
        "border": "#cbd5e1",
        "border_focus": "#2563eb",
        "text_primary": "#0f172a",
        "text_secondary": "#475569",
        "text_muted": "#64748b",
        "accent_primary": "#2563eb",
        "accent_hover": "#1d4ed8",
        "accent_cyan": "#0891b2",
        "badge_success_bg": "#d1fae5",
        "badge_success_fg": "#065f46",
        "badge_plain_bg": "#dbeafe",
        "badge_plain_fg": "#1e40af",
        "badge_locked_bg": "#fee2e2",
        "badge_locked_fg": "#991b1b",
        "badge_warn_bg": "#fef3c7",
        "badge_warn_fg": "#92400e",
        "log_bg": "#0f172a",
        "log_fg": "#f8fafc",
        "tree_bg": "#ffffff",
        "tree_fg": "#0f172a",
        "tree_heading_bg": "#e2e8f0",
        "tree_heading_fg": "#334155",
        "tree_select_bg": "#2563eb",
        "tree_select_fg": "#ffffff",
    }
}


class ForensicCorrelatorGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("iOS Keychain Correlator — Digital Forensic Toolkit v2.4")
        self.root.geometry("1120x800")
        self.root.minsize(920, 640)

        # Active Theme: 'dark' by default for forensic labs
        self.current_theme = "dark"
        self.palette = THEMES[self.current_theme]

        # Core State
        self.pipeline_result: Optional[Dict[str, Any]] = None
        self.accessible_databases: Dict[str, Path] = {}
        self.all_results_cache: List[Any] = []
        self.current_table_rows: List[List[Any]] = []
        self.current_table_cols: List[str] = []
        self.current_search_hits: List[Any] = []

        # Variables for test compatibility & UI binding
        self.extraction_var = tk.StringVar()
        self.keychain_var = tk.StringVar()
        self.out_dir_var = tk.StringVar(value=str(Path.cwd() / "out" / "gui_run"))
        self.export_var = tk.BooleanVar(value=True)
        self.intake_mode_var = tk.StringVar(value="folder")  # 'folder', 'dump', 'usb'

        # Configure style engine
        self._configure_styles()

        # Build UI Architecture
        self._build_menu()
        self._create_header()
        self._create_intake_section()
        self._create_kpi_dashboard()
        self._create_action_bar()
        self._create_main_tabs()
        self._create_status_bar()

        # Initialize background color
        self.root.configure(bg=self.palette["bg_root"])

    # ── Theme & Styling ──────────────────────────────────────────────

    def _configure_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        p = self.palette
        font_family = "Segoe UI" if sys.platform == "win32" else "Helvetica"

        style.configure(".", font=(font_family, 9), background=p["bg_card"], foreground=p["text_primary"])
        style.configure("TFrame", background=p["bg_card"])
        style.configure("TLabelframe", background=p["bg_card"], foreground=p["text_primary"], bordercolor=p["border"])
        style.configure("TLabelframe.Label", font=(font_family, 9, "bold"), foreground=p["text_secondary"], background=p["bg_card"])

        style.configure("Header.TFrame", background=p["bg_surface"])
        style.configure("Title.TLabel", font=(font_family, 14, "bold"), foreground=p["text_primary"], background=p["bg_surface"])
        style.configure("Subtitle.TLabel", font=(font_family, 9), foreground=p["text_muted"], background=p["bg_surface"])
        style.configure("Badge.TLabel", font=(font_family, 9, "bold"), foreground=p["text_secondary"], background=p["bg_surface"])

        style.configure("Primary.TButton", font=(font_family, 10, "bold"), foreground="#ffffff", background=p["accent_primary"], borderwidth=0)
        style.map("Primary.TButton", background=[("active", p["accent_hover"]), ("disabled", p["border"])])

        style.configure("Secondary.TButton", font=(font_family, 9), foreground=p["text_primary"], background=p["bg_surface"])
        style.map("Secondary.TButton", background=[("active", p["border"])])

        style.configure("Accent.TButton", font=(font_family, 9, "bold"), foreground="#ffffff", background=p["accent_cyan"])

        # Notebook tabs
        style.configure("TNotebook", background=p["bg_root"], borderwidth=0)
        style.configure("TNotebook.Tab", font=(font_family, 9, "bold"), padding=(12, 6), background=p["bg_card"], foreground=p["text_secondary"])
        style.map("TNotebook.Tab",
                  background=[("selected", p["accent_primary"]), ("active", p["bg_surface"])],
                  foreground=[("selected", "#ffffff"), ("active", p["text_primary"])])

        # Treeview
        style.configure("Treeview", background=p["tree_bg"], foreground=p["tree_fg"], fieldbackground=p["tree_bg"],
                        rowheight=26, bordercolor=p["border"])
        style.configure("Treeview.Heading", font=(font_family, 9, "bold"), background=p["tree_heading_bg"],
                        foreground=p["tree_heading_fg"], relief="flat")
        style.map("Treeview", background=[("selected", p["tree_select_bg"])], foreground=[("selected", p["tree_select_fg"])])

        # Progressbar
        style.configure("Horizontal.TProgressbar", troughcolor=p["bg_surface"], background=p["accent_cyan"], thickness=6)

    def _toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.palette = THEMES[self.current_theme]
        self.root.configure(bg=self.palette["bg_root"])
        self._configure_styles()
        self._apply_theme_to_widgets()

    def _apply_theme_to_widgets(self):
        p = self.palette
        # Update log and text views
        if hasattr(self, "log_text"):
            self.log_text.config(bg=p["log_bg"], fg=p["log_fg"], insertbackground=p["text_primary"])
        if hasattr(self, "acq_log_text"):
            self.acq_log_text.config(bg=p["log_bg"], fg=p["log_fg"], insertbackground=p["text_primary"])
        if hasattr(self, "ingest_log"):
            self.ingest_log.config(bg=p["log_bg"], fg=p["log_fg"], insertbackground=p["text_primary"])

        # Update Treeview tags
        if hasattr(self, "results_tree"):
            self.results_tree.tag_configure("decrypted", background=p["badge_success_bg"], foreground=p["badge_success_fg"])
            self.results_tree.tag_configure("plain", background=p["badge_plain_bg"], foreground=p["badge_plain_fg"])
            self.results_tree.tag_configure("locked", background=p["badge_locked_bg"], foreground=p["badge_locked_fg"])

        # Update KPI card backgrounds
        if hasattr(self, "kpi_cards"):
            for card in self.kpi_cards:
                card.config(bg=p["bg_card"], highlightbackground=p["border"])
            for lbl in self.kpi_labels:
                lbl.config(bg=p["bg_card"], fg=p["text_secondary"])
            for val in self.kpi_values:
                val.config(bg=p["bg_card"])

    # ── Top Native Menu Bar ──────────────────────────────────────────

    def _build_menu(self):
        menubar = tk.Menu(self.root)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="✨ Load Demo Enclave", accelerator="Ctrl+D", command=self._load_demo_data)
        file_menu.add_separator()
        file_menu.add_command(label="📁 Browse iOS Extraction...", command=self._browse_extraction)
        file_menu.add_command(label="🔑 Browse Keychain JSON...", command=self._browse_keychain)
        file_menu.add_command(label="📂 Set Output Folder...", command=self._browse_out_dir)
        file_menu.add_separator()
        file_menu.add_command(label="📑 Export Case PDF Report...", accelerator="Ctrl+P", command=self._export_case_pdf)
        file_menu.add_command(label="🌐 View Interactive HTML Report", accelerator="Ctrl+H", command=self._open_html_report)
        file_menu.add_command(label="📂 Open Output Folder", command=self._open_output_folder)
        file_menu.add_separator()
        file_menu.add_command(label="❌ Exit", accelerator="Alt+F4", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Triage & Live USB Menu
        triage_menu = tk.Menu(menubar, tearoff=0)
        triage_menu.add_command(label="🔄 Scan Connected USB Devices", accelerator="F5", command=self._refresh_usb_devices)
        triage_menu.add_command(label="⚡ 1-Click Live USB Acquisition", command=self._start_usb_acquisition_flow)
        triage_menu.add_command(label="📷 AFC Camera Roll Fallback (No Passcode)", command=self._pull_afc_photos)
        triage_menu.add_command(label="🔑 Recover Backup Password (Dictionary)", command=self._crack_backup_password)
        triage_menu.add_command(label="📋 Extract Hardware Device Profile", command=self._extract_device_profile)
        triage_menu.add_command(label="🔍 Scan Host Pairing Records", command=self._show_pairing_records)
        menubar.add_cascade(label="Triage & USB", menu=triage_menu)

        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="🏥 Run System Doctor & Auto-Heal", command=self._run_doctor_action)
        tools_menu.add_command(label="🔎 Deep Multi-Database Search", command=lambda: self.notebook.select(self.tab_search))
        tools_menu.add_separator()
        tools_menu.add_command(label="🌓 Toggle Dark / Light Theme", command=self._toggle_theme)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="📖 Forensic Methodology & Chain of Custody", command=self._show_methodology)
        help_menu.add_command(label="ℹ️ About iOS Keychain Correlator", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

        # Bind keyboard shortcuts
        self.root.bind("<Control-d>", lambda e: self._load_demo_data())
        self.root.bind("<Control-p>", lambda e: self._export_case_pdf())
        self.root.bind("<Control-h>", lambda e: self._open_html_report())
        self.root.bind("<F5>", lambda e: self._refresh_usb_devices())

    # ── App Header ───────────────────────────────────────────────────

    def _create_header(self):
        p = self.palette
        self.header_frame = tk.Frame(self.root, bg=p["bg_surface"], padx=18, pady=12)
        self.header_frame.pack(fill=tk.X)

        left_box = tk.Frame(self.header_frame, bg=p["bg_surface"])
        left_box.pack(side=tk.LEFT)

        title_lbl = tk.Label(
            left_box,
            text="🛡️ iOS KEYCHAIN CORRELATOR",
            font=("Segoe UI", 13, "bold"),
            fg=p["text_primary"],
            bg=p["bg_surface"],
        )
        title_lbl.pack(anchor=tk.W)

        subtitle_lbl = tk.Label(
            left_box,
            text="Automated SQLCipher decryption, forensic triage, and unified social intelligence",
            font=("Segoe UI", 8),
            fg=p["text_muted"],
            bg=p["bg_surface"],
        )
        subtitle_lbl.pack(anchor=tk.W)

        right_box = tk.Frame(self.header_frame, bg=p["bg_surface"])
        right_box.pack(side=tk.RIGHT)

        # Demo Button
        btn_demo = tk.Button(
            right_box,
            text="✨ Load Demo Enclave",
            font=("Segoe UI", 8, "bold"),
            bg="#2563eb",
            fg="#ffffff",
            activebackground="#1d4ed8",
            activeforeground="#ffffff",
            relief="flat",
            padx=10,
            pady=3,
            cursor="hand2",
            command=self._load_demo_data,
        )
        btn_demo.pack(side=tk.LEFT, padx=4)

        # Doctor Button
        btn_doc = tk.Button(
            right_box,
            text="🏥 System Doctor",
            font=("Segoe UI", 8),
            bg=p["bg_card"],
            fg=p["text_secondary"],
            activebackground=p["border"],
            relief="flat",
            padx=8,
            pady=3,
            cursor="hand2",
            command=self._run_doctor_action,
        )
        btn_doc.pack(side=tk.LEFT, padx=4)

        # Theme Switcher
        self.btn_theme = tk.Button(
            right_box,
            text="🌓 Theme",
            font=("Segoe UI", 8),
            bg=p["bg_card"],
            fg=p["text_secondary"],
            activebackground=p["border"],
            relief="flat",
            padx=8,
            pady=3,
            cursor="hand2",
            command=self._toggle_theme,
        )
        self.btn_theme.pack(side=tk.LEFT, padx=4)

    # ── Smart Intake Section (Mode-Switching Cards) ──────────────────

    def _create_intake_section(self):
        p = self.palette
        self.intake_frame = ttk.LabelFrame(self.root, text=" 1. Evidence Intake & Source Configuration ", padding=10)
        self.intake_frame.pack(fill=tk.X, padx=16, pady=(8, 4))

        # Segmented Mode Tabs: Folder vs Dump vs USB
        mode_bar = ttk.Frame(self.intake_frame)
        mode_bar.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(mode_bar, text="Intake Mode:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 8))

        modes = [
            ("📁 Local Extraction Folder", "folder"),
            ("📦 Forensic Dump (Cellebrite/GrayKey/iTunes)", "dump"),
            ("📱 Live Connected USB iPhone", "usb"),
        ]
        for label, val in modes:
            ttk.Radiobutton(
                mode_bar,
                text=label,
                value=val,
                variable=self.intake_mode_var,
                command=self._on_intake_mode_changed,
            ).pack(side=tk.LEFT, padx=6)

        # ── Mode Container Frames ──
        self.container_cards = ttk.Frame(self.intake_frame)
        self.container_cards.pack(fill=tk.X)

        # Frame A: Folder Extraction
        self.card_folder = ttk.Frame(self.container_cards)
        self.card_folder.pack(fill=tk.X)

        # Row 1: Extraction
        ttk.Label(self.card_folder, text="iOS Extraction Root:").grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Entry(self.card_folder, textvariable=self.extraction_var, width=68).grid(row=0, column=1, sticky=tk.EW, padx=8, pady=3)
        ttk.Button(self.card_folder, text="Browse...", command=self._browse_extraction).grid(row=0, column=2, pady=3)

        # Row 2: Keychain
        ttk.Label(self.card_folder, text="Keychain JSON File:").grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Entry(self.card_folder, textvariable=self.keychain_var, width=68).grid(row=1, column=1, sticky=tk.EW, padx=8, pady=3)
        kc_btn_frame = ttk.Frame(self.card_folder)
        kc_btn_frame.grid(row=1, column=2, pady=3)
        ttk.Button(kc_btn_frame, text="Browse...", command=self._browse_keychain).pack(side=tk.LEFT)
        ttk.Button(kc_btn_frame, text="⚡ Auto-Find", command=self._autofind_keychain).pack(side=tk.LEFT, padx=(4, 0))

        self.card_folder.columnconfigure(1, weight=1)

        # Frame B: Forensic Dump
        self.card_dump = ttk.Frame(self.container_cards)
        ttk.Label(self.card_dump, text="Forensic Dump Folder:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.dump_path_var = tk.StringVar()
        ttk.Entry(self.card_dump, textvariable=self.dump_path_var, width=68).grid(row=0, column=1, sticky=tk.EW, padx=8, pady=3)
        ttk.Button(self.card_dump, text="Browse...", command=self._browse_dump_dir).grid(row=0, column=2, pady=3)
        
        dump_sub = ttk.Frame(self.card_dump)
        dump_sub.grid(row=1, column=1, sticky=tk.W, pady=2)
        self.lbl_dump_format = ttk.Label(dump_sub, text="Format: Not detected", font=("Segoe UI", 9, "bold"), foreground=p["text_muted"])
        self.lbl_dump_format.pack(side=tk.LEFT)
        ttk.Button(dump_sub, text="🔍 Detect Format", command=self._detect_dump).pack(side=tk.LEFT, padx=12)
        self.card_dump.columnconfigure(1, weight=1)

        # Frame C: Live USB
        self.card_usb = ttk.Frame(self.container_cards)
        usb_row = ttk.Frame(self.card_usb)
        usb_row.pack(fill=tk.X, pady=2)
        self.lbl_usb_quick = ttk.Label(usb_row, text="📱 Plug iPhone via USB, unlock screen, and tap 'Trust'.", font=("Segoe UI", 9, "bold"), foreground=p["text_secondary"])
        self.lbl_usb_quick.pack(side=tk.LEFT)
        ttk.Button(usb_row, text="🔄 Refresh USB", command=self._refresh_usb_devices).pack(side=tk.RIGHT)
        ttk.Button(usb_row, text="⚡ 1-Click USB Acquire", style="Primary.TButton", command=self._start_usb_acquisition_flow).pack(side=tk.RIGHT, padx=6)

        # Common Output Row
        common_box = ttk.Frame(self.intake_frame)
        common_box.pack(fill=tk.X, pady=(6, 0))

        ttk.Label(common_box, text="Case Output Folder:").grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Entry(common_box, textvariable=self.out_dir_var, width=68).grid(row=0, column=1, sticky=tk.EW, padx=8, pady=3)
        ttk.Button(common_box, text="Browse...", command=self._browse_out_dir).grid(row=0, column=2, pady=3)

        opts_sub = ttk.Frame(common_box)
        opts_sub.grid(row=1, column=1, sticky=tk.W, pady=(2, 0))
        ttk.Checkbutton(
            opts_sub,
            text="Export decrypted SQLite databases (enables browsing messages, chats & tables)",
            variable=self.export_var,
        ).pack(side=tk.LEFT)

        common_box.columnconfigure(1, weight=1)

    def _on_intake_mode_changed(self):
        mode = self.intake_mode_var.get()
        self.card_folder.pack_forget()
        self.card_dump.pack_forget()
        self.card_usb.pack_forget()

        if mode == "folder":
            self.card_folder.pack(fill=tk.X)
        elif mode == "dump":
            self.card_dump.pack(fill=tk.X)
        elif mode == "usb":
            self.card_usb.pack(fill=tk.X)

    def _autofind_keychain(self):
        ext = self.extraction_var.get().strip()
        if not ext or not Path(ext).is_dir():
            messagebox.showinfo("Auto-Find", "Please select an iOS Extraction folder first.")
            return

        p = Path(ext)
        candidates = list(p.rglob("*keychain*.json")) + list(p.parent.glob("*keychain*.json"))
        if candidates:
            found = str(candidates[0])
            self.keychain_var.set(found)
            messagebox.showinfo("Keychain Located", f"Found keychain file:\n{found}")
        else:
            messagebox.showwarning("Not Found", "No keychain.json found in the extraction folder.\nPlease browse manually.")

    # ── Executive KPI Dashboard Strip ────────────────────────────────

    def _create_kpi_dashboard(self):
        p = self.palette
        self.kpi_frame = tk.Frame(self.root, bg=p["bg_root"], padx=16, pady=4)
        self.kpi_frame.pack(fill=tk.X)

        self.kpi_cards = []
        self.kpi_labels = []
        self.kpi_values = []

        metrics = [
            ("TOTAL DATABASES", "0", "#3b82f6"),
            ("DECRYPTED EVIDENCE", "0", "#10b981"),
            ("KEYCHAIN HITS", "0", "#06b6d4"),
            ("EXTRACTED ENTITIES", "0", "#f59e0b"),
        ]

        for i, (title, default_val, color) in enumerate(metrics):
            card = tk.Frame(self.kpi_frame, bg=p["bg_card"], bd=1, relief="solid", highlightthickness=1, highlightbackground=p["border"], padx=14, pady=8)
            card.grid(row=0, column=i, sticky="nsew", padx=4)
            self.kpi_frame.columnconfigure(i, weight=1)

            lbl = tk.Label(card, text=title, font=("Segoe UI", 8, "bold"), fg=p["text_secondary"], bg=p["bg_card"])
            lbl.pack(anchor=tk.W)

            val = tk.Label(card, text=default_val, font=("Segoe UI", 16, "bold"), fg=color, bg=p["bg_card"])
            val.pack(anchor=tk.W, pady=(2, 0))

            self.kpi_cards.append(card)
            self.kpi_labels.append(lbl)
            self.kpi_values.append(val)

    def _update_kpi(self, total: int, decrypted: int, keys: int, entities: int = 0):
        rate = f"{(decrypted/total*100):.1f}%" if total > 0 else "0%"
        self.kpi_values[0].config(text=f"{total} Databases")
        self.kpi_values[1].config(text=f"{decrypted} ({rate})")
        self.kpi_values[2].config(text=f"{keys} Keys")
        self.kpi_values[3].config(text=f"{entities} Extracted")

    # ── Command & Action Bar ─────────────────────────────────────────

    def _create_action_bar(self):
        p = self.palette
        bar = ttk.Frame(self.root, padding=(16, 6))
        bar.pack(fill=tk.X)

        self.run_button = ttk.Button(
            bar,
            text="🚀 Start Forensic Analysis & Decryption",
            style="Primary.TButton",
            command=self._start_analysis,
        )
        self.run_button.pack(side=tk.LEFT, ipadx=10, ipady=4)

        self.progress_bar = ttk.Progressbar(bar, mode="indeterminate", length=220)

        # Quick Report Actions (right-aligned)
        self.btn_open_html = ttk.Button(
            bar,
            text="🌐 Open HTML Dashboard",
            state=tk.DISABLED,
            command=self._open_html_report,
        )
        self.btn_open_html.pack(side=tk.RIGHT, padx=4)

        self.btn_export_pdf = ttk.Button(
            bar,
            text="📑 Export PDF Report",
            command=self._export_case_pdf,
        )
        self.btn_export_pdf.pack(side=tk.RIGHT, padx=4)

        self.btn_open_folder = ttk.Button(
            bar,
            text="📂 Output Folder",
            state=tk.DISABLED,
            command=self._open_output_folder,
        )
        self.btn_open_folder.pack(side=tk.RIGHT, padx=4)

    # ── Forensic Tabbed Workspace ────────────────────────────────────

    def _create_main_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(4, 6))

        # Tab 1: Correlation Summary Table
        self.tab_results = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_results, text=" 📊 Correlation Results ")
        self._setup_results_table(self.tab_results)

        # Tab 2: Decrypted Database Data Viewer
        self.tab_viewer = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_viewer, text=" 🔍 Decrypted Data Explorer ")
        self._setup_data_viewer(self.tab_viewer)

        # Tab 3: Social & Contact Network Graph
        self.tab_network = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_network, text=" 🕸️ Network Graph ")
        self._setup_network_tab(self.tab_network)

        # Tab 4: Named Entity Intelligence
        self.tab_entities = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_entities, text=" 🧠 Entity Intelligence ")
        self._setup_entities_tab(self.tab_entities)

        # Tab 5: Deep Keyword Search
        self.tab_search = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_search, text=" 🔎 Deep Evidence Search ")
        self._setup_search_tab(self.tab_search)

        # Tab 6: Live USB Device Acquisition
        self.tab_acquisition = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_acquisition, text=" 📱 Live USB Acquisition ")
        self._setup_acquisition_tab(self.tab_acquisition)

        # Tab 7: Forensic Process Map & Provenance Timeline
        self.tab_provenance = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_provenance, text=" 🗺️ Process Map ")
        self._setup_provenance_tab(self.tab_provenance)

        # Tab 8: Execution Logs
        self.tab_logs = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_logs, text=" 📜 Execution Logs ")
        self._setup_logs_view(self.tab_logs)

    # ── Tab 1: Correlation Results Table ─────────────────────────────

    def _setup_results_table(self, parent):
        # Top toolbar with live filter
        bar = ttk.Frame(parent)
        bar.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(bar, text="Filter:").pack(side=tk.LEFT, padx=(0, 4))
        self.results_filter_var = tk.StringVar()
        filter_entry = ttk.Entry(bar, textvariable=self.results_filter_var, width=28)
        filter_entry.pack(side=tk.LEFT, padx=4)
        filter_entry.bind("<KeyRelease>", lambda e: self._filter_results_table())

        self.lbl_results_count = ttk.Label(bar, text="0 databases loaded", font=("Segoe UI", 9, "bold"))
        self.lbl_results_count.pack(side=tk.LEFT, padx=12)

        ttk.Button(bar, text="📊 Export Results CSV", command=self._export_results_csv).pack(side=tk.RIGHT)

        # Treeview
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("status", "database", "bundle", "fingerprint", "profile", "wal")
        self.results_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")

        self.results_tree.heading("status", text="Status")
        self.results_tree.heading("database", text="Database Name / Relative Path")
        self.results_tree.heading("bundle", text="Application Bundle ID")
        self.results_tree.heading("fingerprint", text="Key Fingerprint")
        self.results_tree.heading("profile", text="Profile")
        self.results_tree.heading("wal", text="WAL Active")

        self.results_tree.column("status", width=120, anchor=tk.CENTER)
        self.results_tree.column("database", width=360, anchor=tk.W)
        self.results_tree.column("bundle", width=180, anchor=tk.W)
        self.results_tree.column("fingerprint", width=110, anchor=tk.CENTER)
        self.results_tree.column("profile", width=90, anchor=tk.CENTER)
        self.results_tree.column("wal", width=80, anchor=tk.CENTER)

        # Apply Tag colors
        p = self.palette
        self.results_tree.tag_configure("decrypted", background=p["badge_success_bg"], foreground=p["badge_success_fg"])
        self.results_tree.tag_configure("plain", background=p["badge_plain_bg"], foreground=p["badge_plain_fg"])
        self.results_tree.tag_configure("locked", background=p["badge_locked_bg"], foreground=p["badge_locked_fg"])

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.results_tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)

        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

    def _filter_results_table(self):
        query = self.results_filter_var.get().strip().lower()
        self.results_tree.delete(*self.results_tree.get_children())
        shown = 0
        for r in self.all_results_cache:
            text_block = f"{r.status} {r.relpath} {r.bundle_id or ''} {r.key_fingerprint or ''} {r.profile or ''}".lower()
            if query and query not in text_block:
                continue
            tag = "decrypted" if r.status == "decrypted" else ("plain" if r.status == "plain" else "locked")
            status_label = {
                "decrypted": "✔ DECRYPTED",
                "plain": "ℹ PLAIN",
                "not_decrypted": "✖ LOCKED",
            }.get(r.status, r.status)

            self.results_tree.insert(
                "",
                tk.END,
                values=(
                    status_label,
                    r.relpath,
                    r.bundle_id or "-",
                    r.key_fingerprint or "-",
                    r.profile or "-",
                    "Yes" if r.has_wal else "No",
                ),
                tags=(tag,),
            )
            shown += 1
        self.lbl_results_count.config(text=f"Showing {shown} of {len(self.all_results_cache)} databases")

    def _export_results_csv(self):
        if not self.all_results_cache:
            messagebox.showinfo("Export", "No results to export.")
            return
        dest = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if dest:
            with open(dest, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Status", "Relative Path", "Bundle ID", "Key Fingerprint", "Profile", "WAL"])
                for r in self.all_results_cache:
                    writer.writerow([r.status, r.relpath, r.bundle_id, r.key_fingerprint, r.profile, r.has_wal])
            messagebox.showinfo("Export Complete", f"Saved {len(self.all_results_cache)} records to:\n{dest}")

    # ── Tab 2: Decrypted Database Data Explorer ──────────────────────

    def _setup_data_viewer(self, parent):
        controls = ttk.Frame(parent)
        controls.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(controls, text="Database:").pack(side=tk.LEFT, padx=(0, 4))
        self.db_selector = ttk.Combobox(controls, state="readonly", width=34)
        self.db_selector.pack(side=tk.LEFT, padx=4)
        self.db_selector.bind("<<ComboboxSelected>>", self._on_db_selected)

        ttk.Label(controls, text="Table:").pack(side=tk.LEFT, padx=(12, 4))
        self.table_selector = ttk.Combobox(controls, state="readonly", width=24)
        self.table_selector.pack(side=tk.LEFT, padx=4)
        self.table_selector.bind("<<ComboboxSelected>>", self._on_table_selected)

        ttk.Label(controls, text="Filter Rows:").pack(side=tk.LEFT, padx=(12, 4))
        self.data_filter_var = tk.StringVar()
        df_entry = ttk.Entry(controls, textvariable=self.data_filter_var, width=18)
        df_entry.pack(side=tk.LEFT, padx=4)
        df_entry.bind("<KeyRelease>", lambda e: self._filter_data_rows())

        self.table_count_label = ttk.Label(controls, text="", font=("Segoe UI", 9, "bold"))
        self.table_count_label.pack(side=tk.RIGHT, padx=4)

        ttk.Button(controls, text="💾 Export CSV", command=self._export_current_table_csv).pack(side=tk.RIGHT, padx=6)

        # Viewer Treeview for generic tabular display
        table_container = ttk.Frame(parent)
        table_container.pack(fill=tk.BOTH, expand=True)

        self.data_tree = ttk.Treeview(table_container, show="headings", selectmode="browse")
        data_vsb = ttk.Scrollbar(table_container, orient=tk.VERTICAL, command=self.data_tree.yview)
        data_hsb = ttk.Scrollbar(table_container, orient=tk.HORIZONTAL, command=self.data_tree.xview)
        self.data_tree.configure(yscrollcommand=data_vsb.set, xscrollcommand=data_hsb.set)

        self.data_tree.grid(row=0, column=0, sticky=tk.NSEW)
        data_vsb.grid(row=0, column=1, sticky=tk.NS)
        data_hsb.grid(row=1, column=0, sticky=tk.EW)

        table_container.columnconfigure(0, weight=1)
        table_container.rowconfigure(0, weight=1)

        # Double click to inspect full row details in modal
        self.data_tree.bind("<Double-1>", self._inspect_selected_row)

    def _filter_data_rows(self):
        query = self.data_filter_var.get().strip().lower()
        self.data_tree.delete(*self.data_tree.get_children())
        count = 0
        for row in self.current_table_rows:
            if query and not any(query in str(v).lower() for v in row):
                continue
            self.data_tree.insert("", tk.END, values=[str(v) if v is not None else "<NULL>" for v in row])
            count += 1
        self.table_count_label.config(text=f"{count} / {len(self.current_table_rows)} rows")

    def _inspect_selected_row(self, event):
        sel = self.data_tree.selection()
        if not sel:
            return
        vals = self.data_tree.item(sel[0], "values")
        if not vals or not self.current_table_cols:
            return

        win = tk.Toplevel(self.root)
        win.title("Record Detail Inspector")
        win.geometry("640x500")

        txt = tk.Text(win, wrap=tk.WORD, font=("Consolas", 10), padx=10, pady=10)
        txt.pack(fill=tk.BOTH, expand=True)
        for col, val in zip(self.current_table_cols, vals):
            txt.insert(tk.END, f"── {col} ──\n{val}\n\n")
        txt.config(state=tk.DISABLED)

    def _export_current_table_csv(self):
        if not self.current_table_rows or not self.current_table_cols:
            messagebox.showinfo("Export", "No active table data loaded to export.")
            return
        dest = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if dest:
            with open(dest, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(self.current_table_cols)
                writer.writerows(self.current_table_rows)
            messagebox.showinfo("Export Complete", f"Exported {len(self.current_table_rows)} rows to:\n{dest}")

    # ── Tab 3: Social & Contact Network Graph ────────────────────────

    def _setup_network_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(top, text="Communication Roles & Interaction Frequencies", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)

        btn_open_d3 = ttk.Button(
            top,
            text="🌐 Open Interactive Graph in Browser (D3.js)",
            style="Primary.TButton",
            command=self._launch_network_graph_browser,
        )
        btn_open_d3.pack(side=tk.RIGHT)

        # Graph node table
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("node", "role", "app", "count", "degree", "first_seen", "last_seen")
        self.network_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        self.network_tree.heading("node", text="Contact Handle / Phone / Alias")
        self.network_tree.heading("role", text="Forensic Role")
        self.network_tree.heading("app", text="Applications")
        self.network_tree.heading("count", text="Message Count")
        self.network_tree.heading("degree", text="Connections (Degree)")
        self.network_tree.heading("first_seen", text="First Activity")
        self.network_tree.heading("last_seen", text="Last Activity")

        self.network_tree.column("node", width=180, anchor=tk.W)
        self.network_tree.column("role", width=150, anchor=tk.CENTER)
        self.network_tree.column("app", width=110, anchor=tk.CENTER)
        self.network_tree.column("count", width=90, anchor=tk.CENTER)
        self.network_tree.column("degree", width=100, anchor=tk.CENTER)
        self.network_tree.column("first_seen", width=130, anchor=tk.CENTER)
        self.network_tree.column("last_seen", width=130, anchor=tk.CENTER)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.network_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.network_tree.xview)
        self.network_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.network_tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)

        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

    def _launch_network_graph_browser(self):
        html_p = None
        if self.pipeline_result:
            html_p = self.pipeline_result.get("report_html_path")
        if not html_p:
            out_p = Path(self.out_dir_var.get())
            cand = out_p / "report.html"
            if cand.exists():
                html_p = cand

        if html_p and Path(html_p).exists():
            uri = f"{Path(html_p).resolve().as_uri()}#network"
            if sys.platform == "win32":
                os.startfile(str(html_p))
            else:
                subprocess.Popen(["xdg-open", str(html_p)])
        else:
            messagebox.showinfo("Network Graph", "Please run analysis first to generate the interactive network graph.")

    def _populate_network_table(self):
        self.network_tree.delete(*self.network_tree.get_children())
        out_root = Path(self.out_dir_var.get())
        exports_root = out_root / "exports"
        if not exports_root.exists():
            return

        try:
            from correlator.timeline import extract_unified_timeline
            from correlator.network_graph import generate_network_graph
            events = extract_unified_timeline(exports_root)
            graph = generate_network_graph(events)
            for n in graph.get("nodes", []):
                self.network_tree.insert(
                    "",
                    tk.END,
                    values=(
                        n.get("label"),
                        n.get("role"),
                        n.get("app"),
                        n.get("message_count"),
                        n.get("degree"),
                        n.get("first_seen")[:19] if n.get("first_seen") else "-",
                        n.get("last_seen")[:19] if n.get("last_seen") else "-",
                    )
                )
        except Exception as e:
            self._log(f"[!] Network graph extraction note: {e}")

    # ── Tab 4: Named Entity Intelligence ─────────────────────────────

    def _setup_entities_tab(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(top, text="Extracted Crypto, Financial, Flight, Phone & Alias Intelligence", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)

        self.lbl_entity_count = ttk.Label(top, text="", font=("Segoe UI", 9, "bold"))
        self.lbl_entity_count.pack(side=tk.RIGHT, padx=8)

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("type", "value", "count", "sources", "context")
        self.entity_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        self.entity_tree.heading("type", text="Entity Type")
        self.entity_tree.heading("value", text="Extracted Value")
        self.entity_tree.heading("count", text="Occurrences")
        self.entity_tree.heading("sources", text="Source Applications")
        self.entity_tree.heading("context", text="Context Snippet")

        self.entity_tree.column("type", width=120, anchor=tk.CENTER)
        self.entity_tree.column("value", width=220, anchor=tk.W)
        self.entity_tree.column("count", width=80, anchor=tk.CENTER)
        self.entity_tree.column("sources", width=140, anchor=tk.W)
        self.entity_tree.column("context", width=380, anchor=tk.W)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.entity_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.entity_tree.xview)
        self.entity_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.entity_tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)

        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

    def _populate_entities_table(self):
        self.entity_tree.delete(*self.entity_tree.get_children())
        out_root = Path(self.out_dir_var.get())
        exports_root = out_root / "exports"
        if not exports_root.exists():
            return

        try:
            from correlator.timeline import extract_unified_timeline
            from correlator.entity_recognition import extract_entities_from_events
            events = extract_unified_timeline(exports_root)
            entities = extract_entities_from_events(events)
            for ent in entities:
                ctx = ent.sample_contexts[0] if ent.sample_contexts else "-"
                self.entity_tree.insert(
                    "",
                    tk.END,
                    values=(
                        ent.entity_type,
                        ent.value,
                        ent.occurrence_count,
                        ", ".join(ent.source_apps),
                        ctx[:80],
                    )
                )
            self.lbl_entity_count.config(text=f"{len(entities)} intelligence entities detected")
            if hasattr(self, "kpi_values") and len(self.kpi_values) >= 4:
                self.kpi_values[3].config(text=f"{len(entities)} Detected")
        except Exception as e:
            self._log(f"[!] Entity intelligence extraction note: {e}")

    # ── Tab 5: Deep Evidence Search ──────────────────────────────────

    def _setup_search_tab(self, parent):
        controls = ttk.LabelFrame(parent, text=" Search Target & Parameters ", padding=10)
        controls.pack(fill=tk.X, pady=(0, 6))

        row1 = ttk.Frame(controls)
        row1.pack(fill=tk.X, pady=2)

        ttk.Label(row1, text="Keyword / Phone / Suspect Name / Regex:").pack(side=tk.LEFT, padx=(0, 6))
        self.search_keyword_var = tk.StringVar()
        entry_kw = ttk.Entry(row1, textvariable=self.search_keyword_var, width=38)
        entry_kw.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        entry_kw.bind("<Return>", lambda e: self._execute_evidence_search())

        btn_search = ttk.Button(row1, text="🔍 Search All Evidence", style="Primary.TButton", command=self._execute_evidence_search)
        btn_search.pack(side=tk.RIGHT)

        row2 = ttk.Frame(controls)
        row2.pack(fill=tk.X, pady=(6, 0))

        self.lbl_search_summary = ttk.Label(row2, text="Ready. Enter a keyword to search across all decrypted databases.", foreground=self.palette["text_muted"])
        self.lbl_search_summary.pack(side=tk.LEFT)

        btn_exp_html = ttk.Button(row2, text="📄 Export HTML Report", command=self._export_search_html)
        btn_exp_html.pack(side=tk.RIGHT, padx=4)

        btn_exp_csv = ttk.Button(row2, text="📊 Export CSV", command=self._export_search_csv)
        btn_exp_csv.pack(side=tk.RIGHT, padx=4)

        # Search Results Table
        table_frame = ttk.Frame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=6)

        cols = ("db", "table", "col", "context")
        self.search_tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.search_tree.heading("db", text="Database")
        self.search_tree.heading("table", text="Table")
        self.search_tree.heading("col", text="Column")
        self.search_tree.heading("context", text="Matched Value & Snippet Context")

        self.search_tree.column("db", width=140, anchor=tk.W)
        self.search_tree.column("table", width=140, anchor=tk.W)
        self.search_tree.column("col", width=120, anchor=tk.W)
        self.search_tree.column("context", width=480, anchor=tk.W)

        s_vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.search_tree.yview)
        s_hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.search_tree.xview)
        self.search_tree.configure(yscrollcommand=s_vsb.set, xscrollcommand=s_hsb.set)

        self.search_tree.grid(row=0, column=0, sticky=tk.NSEW)
        s_vsb.grid(row=0, column=1, sticky=tk.NS)
        s_hsb.grid(row=1, column=0, sticky=tk.EW)

        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

    def _execute_evidence_search(self):
        kw = self.search_keyword_var.get().strip()
        if not kw:
            messagebox.showwarning("Empty Search", "Please enter a keyword, name, or phone number to search.")
            return

        out_root = Path(self.out_dir_var.get())
        exports_root = out_root / "exports"
        if not exports_root.exists():
            exports_root = out_root / "decrypted_export"
        if not exports_root.exists():
            exports_root = out_root

        self.lbl_search_summary.config(text=f"Searching for '{kw}'...", foreground=self.palette["accent_primary"])
        self.search_tree.delete(*self.search_tree.get_children())

        def _worker():
            from correlator.search_engine import search_sqlite_files
            hits = search_sqlite_files(exports_root, kw)
            self.current_search_hits = hits

            def _update():
                for h in hits:
                    self.search_tree.insert("", tk.END, values=(h.db_name, h.table_name, h.column_name, h.match_context))
                self.lbl_search_summary.config(
                    text=f"Found {len(hits)} matching records across decrypted databases.",
                    foreground="#10b981" if hits else "#f43f5e",
                )

            self.root.after(0, _update)

        threading.Thread(target=_worker, daemon=True).start()

    def _export_search_csv(self):
        if not self.current_search_hits:
            messagebox.showinfo("Export", "No search hits to export.")
            return
        dest = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if dest:
            from correlator.search_engine import export_search_results
            export_search_results(self.current_search_hits, dest, fmt="csv")
            messagebox.showinfo("Export Complete", f"Search hits saved to {dest}")

    def _export_search_html(self):
        if not self.current_search_hits:
            messagebox.showinfo("Export", "No search hits to export.")
            return
        dest = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML Files", "*.html")])
        if dest:
            from correlator.search_engine import generate_search_report_html
            generate_search_report_html(self.current_search_hits, self.search_keyword_var.get(), dest)
            messagebox.showinfo("Export Complete", f"HTML Search report saved to {dest}")
            if sys.platform == "win32":
                os.startfile(dest)

    # ── Tab 6: Live USB Acquisition ──────────────────────────────────

    def _setup_acquisition_tab(self, parent):
        top_frame = ttk.Frame(parent)
        top_frame.pack(fill=tk.X, pady=(0, 8))

        lbl_info = ttk.Label(
            top_frame,
            text="Connect an iPhone via USB, ensure screen is unlocked, and tap 'Trust'. Click Refresh to detect device.",
            style="Subtitle.TLabel",
        )
        lbl_info.pack(side=tk.LEFT)

        btn_refresh = ttk.Button(top_frame, text="🔄 Refresh Devices", command=self._refresh_usb_devices)
        btn_refresh.pack(side=tk.RIGHT, padx=4)

        # Device selection & details
        mid_frame = ttk.LabelFrame(parent, text=" Connected iOS Device Status ", padding=10)
        mid_frame.pack(fill=tk.X, pady=6)

        self.lbl_device_status = ttk.Label(
            mid_frame,
            text="No USB device scan performed yet. Click 'Refresh Devices'.",
            font=("Segoe UI", 10, "bold"),
            foreground=self.palette["text_secondary"],
        )
        self.lbl_device_status.pack(anchor=tk.W, pady=2)

        self.lbl_device_details = ttk.Label(
            mid_frame,
            text="Model: - | iOS: - | UDID: - | Pairing: -",
            foreground=self.palette["text_muted"],
        )
        self.lbl_device_details.pack(anchor=tk.W, pady=2)

        # Action Buttons
        btn_box = ttk.Frame(parent, padding=(0, 6))
        btn_box.pack(fill=tk.X)

        self.btn_1click_acquire = ttk.Button(
            btn_box,
            text="⚡ 1-Click Acquire & Decrypt All Evidence",
            style="Primary.TButton",
            command=self._start_usb_acquisition_flow,
        )
        self.btn_1click_acquire.pack(side=tk.LEFT, ipadx=10, ipady=4)

        self.btn_dump_profile = ttk.Button(
            btn_box,
            text="📋 Extract Hardware Profile Only",
            command=self._extract_device_profile,
        )
        self.btn_dump_profile.pack(side=tk.LEFT, padx=6)

        self.btn_afc_fallback = ttk.Button(
            btn_box,
            text="📷 AFC Photo Fallback (No Passcode)",
            command=self._pull_afc_photos,
        )
        self.btn_afc_fallback.pack(side=tk.LEFT, padx=6)

        self.btn_crack_backup_pwd = ttk.Button(
            btn_box,
            text="🔑 Recover Backup Password",
            command=self._crack_backup_password,
        )
        self.btn_crack_backup_pwd.pack(side=tk.LEFT, padx=6)

        # Acquisition Progress & Live Log
        log_frame = ttk.LabelFrame(parent, text=" Live Acquisition Activity ", padding=8)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=6)

        self.acq_progress = ttk.Progressbar(log_frame, mode="determinate", maximum=100)
        self.acq_progress.pack(fill=tk.X, pady=(0, 6))

        p = self.palette
        self.acq_log_text = tk.Text(log_frame, wrap=tk.WORD, font=("Consolas", 9), height=10, bg=p["log_bg"], fg=p["log_fg"])
        self.acq_log_text.pack(fill=tk.BOTH, expand=True)

    def _append_acq_log(self, text: str):
        self.acq_log_text.insert(tk.END, text + "\n")
        self.acq_log_text.see(tk.END)

    def _refresh_usb_devices(self):
        try:
            from correlator.acquisition import is_acquisition_available, is_usbmuxd_running, list_connected_devices
            if not is_acquisition_available():
                self.lbl_device_status.config(text="⚠️ pymobiledevice3 library is missing.", foreground="#dc2626")
                return

            if not is_usbmuxd_running():
                self.lbl_device_status.config(
                    text="⚠️ Apple Mobile Device Service (usbmuxd) is not active on port 27015.",
                    foreground="#dc2626"
                )
                self.lbl_device_details.config(text="Please start Apple Devices service or iTunes, connect iPhone via USB, and tap 'Trust'.")
                return

            devs = list_connected_devices()
            if not devs:
                self.lbl_device_status.config(text="⚠️ No iOS devices detected over USB.", foreground="#d97706")
                self.lbl_device_details.config(text="Unlock iPhone screen, tap 'Trust', and check cable connection.")
            else:
                d = devs[0]
                status_str = "✅ Paired" if d.get("paired") else "⚠️ Unpaired"
                tier = d.get("access_tier", "unpaired").upper()
                lock_s = d.get("lock_state", "UNKNOWN")
                pwd_s = "Pwd: SET" if d.get("password_set") else "Pwd: None"

                self.lbl_device_status.config(
                    text=f"📱 {d.get('device_name')} ({d.get('product_type')}) — [Tier: {tier}]",
                    foreground="#16a34a" if tier == "FULL_BACKUP" else "#d97706"
                )
                self.lbl_device_details.config(
                    text=f"iOS {d.get('product_version')} | UDID: {d.get('udid')} | State: {lock_s} | {pwd_s} | {status_str}"
                )
                self._append_acq_log(f"[+] Found device: {d.get('device_name')} (UDID: {d.get('udid')}, Tier: {tier}, State: {lock_s})")
        except Exception as e:
            self.lbl_device_status.config(text=f"Error checking USB: {e}", foreground="#dc2626")

    def _pull_afc_photos(self):
        def _worker():
            try:
                from correlator.acquisition import PasswordFreeBackup, _get_lockdown_client, list_connected_devices
                devs = list_connected_devices()
                if not devs:
                    messagebox.showerror("No Device", "No iOS device connected over USB.")
                    return
                udid = devs[0]["udid"]
                out_dir = Path(self.out_dir_var.get()) / "afc_photos" / udid
                out_dir.mkdir(parents=True, exist_ok=True)

                self._append_acq_log(f"[+] Starting AFC photo pull for {udid}...")
                client = _get_lockdown_client(udid)
                agent = PasswordFreeBackup(client, udid)

                def _cb(msg, pct):
                    self.root.after(0, lambda: self.acq_progress.config(value=int(pct * 100)))
                    self.root.after(0, lambda: self._append_acq_log(f"[AFC] {msg}"))

                pulled = agent.partial_afc_pull(out_dir, progress_callback=_cb)
                self._append_acq_log(f"[+] Extracted {len(pulled)} photos/files to: {out_dir}")
                messagebox.showinfo("AFC Extraction Finished", f"Extracted {len(pulled)} photos/media files to:\n{out_dir}")
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda msg=err_msg: self._append_acq_log(f"[-] AFC error: {msg}"))
                self.root.after(0, lambda msg=err_msg: messagebox.showerror("AFC Error", f"AFC photo extraction failed: {msg}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _crack_backup_password(self):
        manifest_path = filedialog.askopenfilename(
            title="Select Manifest.plist from Encrypted iOS Backup",
            filetypes=[("Property List", "*.plist"), ("All Files", "*.*")],
        )
        if not manifest_path:
            return

        def _worker():
            try:
                from correlator.acquisition import BackupPasswordCracker
                cracker = BackupPasswordCracker(manifest_path)
                if not cracker.salt or not cracker.expected_hash:
                    messagebox.showwarning("Notice", "Manifest.plist does not appear to contain an encrypted backup password hash.")
                    return

                self._append_acq_log(f"[+] Loaded Manifest.plist ({cracker.rounds} PBKDF2 rounds). Testing top candidates...")
                common_passwords = [
                    "1234", "0000", "123456", "password", "apple", "iphone",
                    "1111", "1212", "qwerty", "12345678", "admin", "12345",
                ]
                found = None
                for cand in common_passwords:
                    if cracker.try_password(cand):
                        found = cand
                        break

                if found:
                    self._append_acq_log(f"[+] 🎉 SUCCESS! Backup password recovered: '{found}'")
                    messagebox.showinfo("Password Cracked", f"🎉 Backup Password Recovered!\n\nPassword: {found}\nPBKDF2 Rounds: {cracker.rounds}")
                else:
                    self._append_acq_log("[-] Top candidates exhausted without match. You may supply a custom wordlist file.")
                    messagebox.showinfo("Not Found", "Standard candidate passwords exhausted.\nUse custom wordlist for deeper dictionary attack.")
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda msg=err_msg: self._append_acq_log(f"[-] Cracker error: {msg}"))
                self.root.after(0, lambda msg=err_msg: messagebox.showerror("Error", f"Password cracker failed: {msg}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _extract_device_profile(self):
        def _worker():
            try:
                from correlator.acquisition import dump_device_profile
                out_dir = Path(self.out_dir_var.get())
                out_dir.mkdir(parents=True, exist_ok=True)
                prof = dump_device_profile(out_file=out_dir / "device_profile.json")
                self._append_acq_log(f"[+] Device profile saved to: {out_dir / 'device_profile.json'}")
                messagebox.showinfo("Profile Extracted", f"Device profile saved successfully:\n{out_dir / 'device_profile.json'}")
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda msg=err_msg: self._append_acq_log(f"[-] Profile extraction error: {msg}"))
                self.root.after(0, lambda msg=err_msg: messagebox.showerror("Error", f"Could not dump device profile: {msg}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _start_usb_acquisition_flow(self):
        def _worker():
            self.btn_1click_acquire.config(state=tk.DISABLED)
            out_dir = Path(self.out_dir_var.get()) / "usb_extraction"
            out_dir.mkdir(parents=True, exist_ok=True)

            def progress_cb(msg, pct):
                self.root.after(0, lambda: self.acq_progress.configure(value=int(pct * 100)))
                self.root.after(0, lambda: self._append_acq_log(f"[{int(pct*100):>3}%] {msg}"))

            try:
                from correlator.acquisition import acquire_live_pipeline
                res = acquire_live_pipeline(out_dir=out_dir, progress_callback=progress_cb)

                self.root.after(0, lambda: self.extraction_var.set(str(res["backup_folder"])))
                self.root.after(0, lambda: self.keychain_var.set(str(res["keychain_path"])))
                self.root.after(0, lambda: self._append_acq_log("🎉 Acquisition, Decryption & Report finished! Switching to results view."))
                self.root.after(0, lambda: messagebox.showinfo("Success", "USB Acquisition & Correlation finished!\nViewing results."))
                self.root.after(0, lambda: self.notebook.select(self.tab_results))
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda msg=err_msg: self._append_acq_log(f"[-] Acquisition failed: {msg}"))
                self.root.after(0, lambda msg=err_msg: messagebox.showerror("Acquisition Error", f"Live USB acquisition failed: {msg}"))
            finally:
                self.root.after(0, lambda: self.btn_1click_acquire.config(state=tk.NORMAL))

        threading.Thread(target=_worker, daemon=True).start()

    # ── Tab 7: Forensic Process Map & Provenance Timeline ────────────

    def _setup_provenance_tab(self, parent):
        top_frame = ttk.Frame(parent, padding=(0, 4))
        top_frame.pack(fill=tk.X)

        self.lbl_prov_summary = ttk.Label(
            top_frame,
            text="Chronological Forensic Execution Map (0 Steps Recorded)",
            font=("Segoe UI", 10, "bold"),
            foreground=self.palette["text_primary"],
        )
        self.lbl_prov_summary.pack(side=tk.LEFT, pady=2)

        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=6)

        cols = ("step", "phase", "target", "action", "timestamp", "status")
        self.prov_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        self.prov_tree.heading("step", text="Step #")
        self.prov_tree.heading("phase", text="Forensic Phase")
        self.prov_tree.heading("target", text="Target Object")
        self.prov_tree.heading("action", text="Action & Cryptographic Operations")
        self.prov_tree.heading("timestamp", text="Timestamp (UTC)")
        self.prov_tree.heading("status", text="Status")

        self.prov_tree.column("step", width=55, anchor=tk.CENTER)
        self.prov_tree.column("phase", width=170, anchor=tk.W)
        self.prov_tree.column("target", width=130, anchor=tk.W)
        self.prov_tree.column("action", width=380, anchor=tk.W)
        self.prov_tree.column("timestamp", width=150, anchor=tk.CENTER)
        self.prov_tree.column("status", width=80, anchor=tk.CENTER)

        p_vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.prov_tree.yview)
        p_hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.prov_tree.xview)
        self.prov_tree.configure(yscrollcommand=p_vsb.set, xscrollcommand=p_hsb.set)

        self.prov_tree.grid(row=0, column=0, sticky=tk.NSEW)
        p_vsb.grid(row=0, column=1, sticky=tk.NS)
        p_hsb.grid(row=1, column=0, sticky=tk.EW)

        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

    def _populate_provenance_table(self, steps: List[Dict[str, Any]]):
        for item in self.prov_tree.get_children():
            self.prov_tree.delete(item)

        if not steps and self.pipeline_result:
            from correlator.provenance import build_default_provenance_map
            tracker = build_default_provenance_map(
                self.pipeline_result.get("results", []),
                self.extraction_var.get() or "Extraction",
                self.keychain_var.get() or "Keychain",
            )
            steps = tracker.get_timeline()

        self.lbl_prov_summary.config(text=f"Chronological Forensic Execution Map ({len(steps)} Steps Recorded)")

        for s in steps:
            status_val = "✅ SUCCESS" if s.get("status") == "success" else "⚠️ WARNING"
            self.prov_tree.insert(
                "",
                tk.END,
                values=(
                    f"#{s.get('step_number')}",
                    s.get("phase"),
                    s.get("target"),
                    s.get("action"),
                    s.get("timestamp"),
                    status_val,
                ),
            )

    # ── Tab 8: Execution Logs ────────────────────────────────────────

    def _setup_logs_view(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(top, text="Real-time Cryptographic & Analysis Console", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        ttk.Button(top, text="📋 Copy Logs", command=self._copy_logs_to_clipboard).pack(side=tk.RIGHT)
        ttk.Button(top, text="🧹 Clear", command=lambda: self.log_text.delete("1.0", tk.END)).pack(side=tk.RIGHT, padx=4)

        p = self.palette
        self.log_text = tk.Text(parent, wrap=tk.WORD, font=("Consolas", 9), background=p["log_bg"], foreground=p["log_fg"])
        log_sb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_sb.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_sb.pack(side=tk.RIGHT, fill=tk.Y)

    def _copy_logs_to_clipboard(self):
        text = self.log_text.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Execution logs copied to clipboard.")

    # ── Status Bar ───────────────────────────────────────────────────

    def _create_status_bar(self):
        self.status_var = tk.StringVar(value="Ready. Select evidence paths or click '✨ Load Demo Enclave' to test.")
        bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, padding=(10, 4))
        bar.pack(side=tk.BOTTOM, fill=tk.X)

    # ── User Action Handlers ─────────────────────────────────────────

    def _browse_extraction(self):
        chosen = filedialog.askdirectory(title="Select iOS Extraction Root Directory")
        if chosen:
            self.extraction_var.set(chosen)

    def _browse_keychain(self):
        chosen = filedialog.askopenfilename(
            title="Select Keychain JSON File",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if chosen:
            self.keychain_var.set(chosen)

    def _browse_out_dir(self):
        chosen = filedialog.askdirectory(title="Select Output Directory for Case Reports")
        if chosen:
            self.out_dir_var.set(chosen)

    def _browse_dump_dir(self):
        chosen = filedialog.askdirectory(title="Select Forensic Dump Directory (Cellebrite, GrayKey, iTunes)")
        if chosen:
            self.dump_path_var.set(chosen)
            self._detect_dump()

    def _detect_dump(self):
        p = self.dump_path_var.get().strip()
        if not p or not Path(p).is_dir():
            return
        from correlator.dump_ingest import detect_dump_format
        fmt = detect_dump_format(p)
        names = {
            "cellebrite": "✅ Cellebrite UFED / Physical Analyzer",
            "graykey": "✅ GrayKey Full Filesystem",
            "itunes": "✅ iTunes / Finder iOS Backup",
            "generic": "ℹ️ Generic Dump (Folder with DBs)",
        }
        self.lbl_dump_format.config(text=f"Format: {names.get(fmt, fmt)}", foreground="#10b981")
        self._log(f"[+] Selected dump: {p}\n    Format: {fmt}")

    def _load_demo_data(self):
        base = Path(__file__).resolve().parent.parent.parent
        demo_dir = base / "out" / "fragmented_enclave"
        extraction = demo_dir / "extraction"
        keychain = demo_dir / "keychain.json"

        if not extraction.exists() or not keychain.exists():
            self._log("Fragmented Enclave demo fixtures not found, generating now...")
            from harness.make_fragmented_enclave import generate_fragmented_enclave
            generate_fragmented_enclave(demo_dir)

        self.extraction_var.set(str(extraction))
        self.keychain_var.set(str(keychain))
        self.out_dir_var.set(str(base / "out" / "gui_run"))
        self._log("Loaded 'Fragmented Enclave' demo dataset (Signal 48b, Legacy 32b, WhatsApp control, Orphan DB).")
        self.status_var.set("Fragmented Enclave demo loaded. Click 'Start Forensic Analysis' to inspect!")
        messagebox.showinfo("Demo Loaded", "Loaded 'Fragmented Enclave' synthetic forensic exhibit!\n\nClick 'Start Forensic Analysis' to correlate keys and decrypt databases.")

    def _log(self, message: str):
        if hasattr(self, "log_text"):
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.see(tk.END)

    def _start_analysis(self):
        # If dump mode is selected and dump path provided, run dump analysis
        if self.intake_mode_var.get() == "dump":
            dp = self.dump_path_var.get().strip()
            if dp and Path(dp).is_dir():
                self._run_dump_ingestion(analyze=True)
                return

        ext = self.extraction_var.get().strip()
        kc = self.keychain_var.get().strip()
        out = self.out_dir_var.get().strip()

        if not ext or not Path(ext).is_dir():
            messagebox.showerror("Missing Input", "Please select a valid iOS Extraction directory.")
            return
        if not kc or not Path(kc).is_file():
            messagebox.showerror("Missing Input", "Please select a valid Keychain JSON file.")
            return
        if not out:
            messagebox.showerror("Missing Input", "Please specify an Output Directory.")
            return

        self.run_button.config(state=tk.DISABLED)
        self.progress_bar.pack(side=tk.LEFT, padx=12)
        self.progress_bar.start(10)
        self.status_var.set("Running forensic correlation and decryption...")
        self._log(f"[*] Starting forensic correlation...\n  Extraction: {ext}\n  Keychain: {kc}\n  Output: {out}")

        threading.Thread(target=self._run_worker, args=(ext, kc, out), daemon=True).start()

    def _run_worker(self, ext_path: str, kc_path: str, out_dir: str):
        try:
            out_p = Path(out_dir)
            export_p = (out_p / "exports") if self.export_var.get() else None

            result = execute_pipeline(
                extraction=Path(ext_path),
                keychain=Path(kc_path),
                out_dir=out_p,
                export_dir=export_p,
            )
            self.root.after(0, self._on_analysis_finished, result, None)
        except Exception as e:
            self.root.after(0, self._on_analysis_finished, None, e)

    def _on_analysis_finished(self, result: Optional[Dict[str, Any]], error: Optional[Exception]):
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        self.run_button.config(state=tk.NORMAL)

        if error:
            diag = diagnose_exception(error, {
                "root": self.extraction_var.get(),
                "keychain": self.keychain_var.get(),
                "out": self.out_dir_var.get(),
            })
            self._log("\n" + format_diagnostic_box(diag))
            steps_txt = "\n".join([f"  {i}. {s}" for i, s in enumerate(diag.get("steps", []), 1)])
            msg = f"{diag['title']}\n\nCause: {diag['cause']}\n\nRecommended Fix:\n{steps_txt}"
            if diag.get("quick_command"):
                msg += f"\n\nQuick Command:\n{diag['quick_command']}"
            messagebox.showerror("Diagnostic Assistant", msg)
            self.status_var.set(f"Error: {diag['title']}. Check Execution Logs tab.")
            return

        if not result:
            return

        self.pipeline_result = result
        self.btn_open_html.config(state=tk.NORMAL)
        self.btn_open_folder.config(state=tk.NORMAL)

        total = result.get("total_databases", 0)
        decrypted = result.get("decrypted_count", 0)
        plain = result.get("plain_count", 0)
        locked = result.get("locked_count", 0)
        keys_matched = len(set(r.key_fingerprint for r in result.get("results", []) if r.key_fingerprint))

        # Update KPI Metric Cards
        self._update_kpi(total, decrypted, keys_matched, entities=0)

        self._log(f"[+] Finished! Total: {total} databases ({decrypted} decrypted, {plain} plain, {locked} locked).")
        self.status_var.set(f"Completed! {decrypted} decrypted, {plain} plain, {locked} locked databases.")

        # Cache results for live filtering
        self.all_results_cache = result.get("results", [])
        self._filter_results_table()

        # Populate Decrypted Data Explorer
        self._populate_accessible_databases(result)

        # Populate Forensic Process Map
        self._populate_provenance_table(result.get("provenance_map", []))

        # Populate Social Network Graph & Entity tabs
        self._populate_network_table()
        self._populate_entities_table()

        messagebox.showinfo(
            "Analysis Complete",
            f"Forensic correlation finished!\n\n"
            f"• Decrypted Databases: {decrypted}\n"
            f"• Plain Databases: {plain}\n"
            f"• Locked / Undecrypted: {locked}\n\n"
            f"Explore decrypted tables, entity intelligence, and social network graph in the tabs above!",
        )

    def _run_dump_ingestion(self, analyze: bool):
        p = self.dump_path_var.get().strip()
        if not p or not Path(p).is_dir():
            messagebox.showerror("Error", "Please select a valid dump directory.")
            return

        out_dir = Path(self.out_dir_var.get()) / "ingested_dump"

        def _worker():
            def cb(msg, pct):
                self._log(f"[{int(pct*100):>3}%] {msg}")

            try:
                from correlator.dump_ingest import ingest_and_analyze, normalize_dump_to_extraction
                if analyze:
                    res = ingest_and_analyze(p, out_dir, progress_callback=cb)
                    self.root.after(0, lambda: self.extraction_var.set(str(res["extraction_path"])))
                    if res.get("keychain_path"):
                        self.root.after(0, lambda: self.keychain_var.set(str(res["keychain_path"])))
                    if res.get("pipeline_result"):
                        self.root.after(0, self._on_analysis_finished, res["pipeline_result"], None)
                    self.root.after(0, lambda: messagebox.showinfo("Ingestion Succeeded", f"Decrypted {res['decrypted_count']} databases from {res['format']} dump!"))
                    self.root.after(0, lambda: self.notebook.select(self.tab_results))
                else:
                    res = normalize_dump_to_extraction(p, out_dir, progress_callback=cb)
                    self.root.after(0, lambda: self.extraction_var.set(str(res["extraction_path"])))
                    if res.get("keychain_path"):
                        self.root.after(0, lambda: self.keychain_var.set(str(res["keychain_path"])))
                    self.root.after(0, lambda: messagebox.showinfo("Normalized", f"Extracted {res['db_count']} databases. Ready to correlate!"))
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda msg=err_msg: messagebox.showerror("Ingestion Error", f"Failed to ingest dump: {msg}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _populate_accessible_databases(self, result: Dict[str, Any]):
        self.accessible_databases.clear()
        ext_root = Path(self.extraction_var.get())
        out_root = Path(self.out_dir_var.get())
        exports_root = out_root / "exports"

        if exports_root.exists():
            for exp_file in exports_root.rglob("*"):
                if exp_file.is_file() and exp_file.suffix in (".sqlite", ".db", ".sqlite3"):
                    rel = exp_file.relative_to(exports_root).as_posix()
                    name = f"[Decrypted] {exp_file.name} ({rel})"
                    self.accessible_databases[name] = exp_file

        for r in result.get("results", []):
            if r.status == "plain":
                plain_file = ext_root / r.relpath
                name = f"[Plain] {plain_file.name} ({r.relpath})"
                self.accessible_databases[name] = plain_file

        names = list(self.accessible_databases.keys())
        self.db_selector["values"] = names
        if names:
            self.db_selector.current(0)
            self._on_db_selected(None)
        else:
            self.db_selector.set("")
            self.table_selector["values"] = []
            self.table_selector.set("")

    def _on_db_selected(self, event):
        selected_name = self.db_selector.get()
        if not selected_name or selected_name not in self.accessible_databases:
            return

        db_path = self.accessible_databases[selected_name]
        try:
            con = sqlite3.connect(f"{Path(db_path).resolve().as_uri()}?mode=ro", uri=True)
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")
            tables = [row[0] for row in cur.fetchall()]
            con.close()

            self.table_selector["values"] = tables
            if tables:
                self.table_selector.current(0)
                self._on_table_selected(None)
            else:
                self.table_selector.set("No tables found")
                self.data_tree.delete(*self.data_tree.get_children())
                self.table_count_label.config(text="0 rows")
        except Exception as e:
            messagebox.showwarning("Database Read Error", f"Unable to read tables: {e}")

    def _on_table_selected(self, event):
        db_name = self.db_selector.get()
        table_name = self.table_selector.get()
        if not db_name or not table_name or table_name == "No tables found":
            return

        db_path = self.accessible_databases[db_name]
        try:
            con = sqlite3.connect(f"{Path(db_path).resolve().as_uri()}?mode=ro", uri=True)
            cur = con.cursor()
            cur.execute(f'SELECT * FROM "{table_name}" LIMIT 500;')
            self.current_table_cols = [d[0] for d in cur.description] if cur.description else []
            self.current_table_rows = cur.fetchall()
            con.close()

            self.data_tree["columns"] = self.current_table_cols
            for col in self.current_table_cols:
                self.data_tree.heading(col, text=col)
                self.data_tree.column(col, width=130, anchor=tk.W)

            self.data_filter_var.set("")
            self._filter_data_rows()
        except Exception as e:
            messagebox.showwarning("Table Read Error", f"Unable to read table rows: {e}")

    def _run_doctor_action(self):
        self._log("\n[*] Running System Doctor & Self-Healing Health Check...")
        res = run_system_doctor(auto_fix=True)
        summary_lines = []
        for c in res["checks"]:
            sym = "✅" if c["status"] in ("PASS", "FIXED") else ("⚠️" if c["status"] == "WARN" else "❌")
            log_line = f"  {sym} {c['name']:<25} [{c['status']}] - {c['msg']}"
            self._log(log_line)
            summary_lines.append(f"{sym} {c['name']}: {c['status']}")

        if res["healthy"]:
            self._log("🎉 All components operational and healthy!\n")
            self.status_var.set("System Doctor: Everything is operational and healthy!")
            messagebox.showinfo("System Doctor Health Check", "✅ All diagnostic tests passed!\n\n" + "\n".join(summary_lines))
        else:
            self._log("⚠️ Some checks require attention.\n")
            self.status_var.set("System Doctor: Issues detected. See Execution Logs tab.")
            messagebox.showwarning("System Doctor Health Check", "⚠️ Some diagnostic tests failed:\n\n" + "\n".join(summary_lines))

    def _show_pairing_records(self):
        from correlator.pairing import find_pairing_records, get_pairing_summary
        summary = get_pairing_summary()
        self._log("\n" + summary)
        win = tk.Toplevel(self.root)
        win.title("Discovered iOS Host Pairing Records")
        win.geometry("680x420")
        txt = tk.Text(win, wrap=tk.WORD, font=("Consolas", 9), bg=self.palette["log_bg"], fg=self.palette["log_fg"], padx=10, pady=10)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, summary)
        txt.config(state=tk.DISABLED)

    def _export_case_pdf(self):
        pdf_path = filedialog.asksaveasfilename(
            title="Export Official Forensic PDF Report",
            defaultextension=".pdf",
            filetypes=[("PDF Document", "*.pdf")],
            initialfile="Forensic_Case_Report.pdf",
        )
        if not pdf_path:
            return

        try:
            results_list = []
            if self.pipeline_result and "results" in self.pipeline_result:
                for r in self.pipeline_result["results"]:
                    results_list.append({
                        "name": r.name,
                        "bundle_id": r.bundle_id,
                        "profile": r.profile,
                        "key_fingerprint": r.key_fingerprint,
                        "status": r.status,
                    })

            case_data = {
                "case_id": "GUI-EXHIBIT",
                "case_name": "Digital Forensic Examination",
                "case_number": "FSL-2026-REPORT",
                "examiner": os.environ.get("USERNAME", "Forensic Examiner"),
                "status": "COMPLETED",
                "summary": {
                    "total_devices": 1,
                    "total_databases": len(results_list) if results_list else len(self.accessible_databases),
                    "total_decrypted": sum(1 for r in results_list if r.get("status") == "decrypted"),
                    "total_plain": sum(1 for r in results_list if r.get("status") == "plain_sqlite"),
                    "total_locked": sum(1 for r in results_list if r.get("status") == "locked"),
                },
                "devices": [{
                    "device_name": "Target iOS Device",
                    "device_model": "Apple iPhone / iPad",
                    "os_version": "Production iOS Release",
                    "serial_number": "EXHIBIT-A",
                    "access_tier": "FULL_BACKUP",
                    "total_databases": len(results_list),
                }],
                "databases": results_list,
                "evidence_samples": [],
            }

            for db_name, p in list(self.accessible_databases.items())[:3]:
                try:
                    con = sqlite3.connect(f"{Path(p).resolve().as_uri()}?mode=ro", uri=True)
                    cur = con.cursor()
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 3;")
                    tables = [row[0] for row in cur.fetchall()]
                    for tbl in tables:
                        cur.execute(f'SELECT * FROM "{tbl}" LIMIT 2;')
                        col_names = [d[0] for d in cur.description] if cur.description else []
                        for row in cur.fetchall():
                            for c_idx, cell in enumerate(row):
                                if cell and len(str(cell)) > 5:
                                    case_data["evidence_samples"].append({
                                        "database": db_name,
                                        "table": tbl,
                                        "column": col_names[c_idx] if c_idx < len(col_names) else "data",
                                        "snippet": str(cell)[:70],
                                    })
                                    break
                    con.close()
                except Exception:
                    pass

            generate_case_pdf(case_data, pdf_path)
            messagebox.showinfo("PDF Generated", f"Official Forensic PDF Report saved successfully to:\n{pdf_path}")
            try:
                os.startfile(pdf_path)
            except Exception:
                pass
        except Exception as e:
            messagebox.showerror("PDF Export Failed", f"Could not generate PDF: {e}")

    def _open_html_report(self):
        if not self.pipeline_result:
            return
        html_p = self.pipeline_result.get("report_html_path")
        if html_p and Path(html_p).exists():
            if sys.platform == "win32":
                os.startfile(str(html_p))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(html_p)])
            else:
                subprocess.Popen(["xdg-open", str(html_p)])

    def _open_output_folder(self):
        out_p = Path(self.out_dir_var.get())
        if out_p.exists():
            if sys.platform == "win32":
                os.startfile(str(out_p))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(out_p)])
            else:
                subprocess.Popen(["xdg-open", str(out_p)])

    def _show_methodology(self):
        messagebox.showinfo(
            "Forensic Methodology",
            "iOS Keychain Correlator adheres to ISO/IEC 27037 standards:\n\n"
            "1. Read-Only Evidence Isolation: Databases are queried via SQLite URI mode=ro with immutable access.\n"
            "2. Cryptographic Integrity: SHA-256 hashes recorded before and after correlation.\n"
            "3. Deterministic Decryption: Keys matched via SQLCipher raw PRAGMA key derivations.\n"
            "4. Transparent Audit Trail: Every phase produces a chronological provenance timeline.",
        )

    def _show_about(self):
        messagebox.showinfo(
            "About iOS Keychain Correlator",
            "iOS Keychain Correlator v2.4 Pro\n\n"
            "Autonomous Forensics Toolkit for iOS SQLCipher Decryption,\n"
            "Keychain Correlation, Social Network Analysis, and Entity Intelligence.\n\n"
            "Built with Python, SQLCipher, D3.js, and ReportLab.",
        )


def main():
    root = tk.Tk()
    app = ForensicCorrelatorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
