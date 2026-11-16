"""
Graphical User Interface (GUI) for iOS Keychain Correlator.
Designed for ease-of-use so non-technical users can analyze extractions,
decrypt databases, and explore recovered data visually.
"""

import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional

from correlator.diagnostics import diagnose_exception, format_diagnostic_box, run_system_doctor
from correlator.pdf_report import generate_case_pdf
from correlator.pipeline import execute_pipeline


class ForensicCorrelatorGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("iOS Keychain Correlator - Forensic Toolkit")
        self.root.geometry("980x720")
        self.root.minsize(840, 600)

        # Style configuration
        self._configure_styles()

        # State
        self.pipeline_result: Optional[Dict[str, Any]] = None
        self.accessible_databases: Dict[str, Path] = {}  # db_name -> path

        # Build UI components
        self._create_header()
        self._create_inputs_section()
        self._create_action_bar()
        self._create_main_tabs()
        self._create_status_bar()

    def _configure_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Fonts and colors
        style.configure(".", font=("Segoe UI", 9))
        style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"), foreground="#0f172a")
        style.configure("Subtitle.TLabel", font=("Segoe UI", 9), foreground="#64748b")
        style.configure("Header.TLabel", font=("Segoe UI", 10, "bold"), foreground="#1e293b")
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), foreground="#ffffff", background="#2563eb")
        style.map("Primary.TButton", background=[("active", "#1d4ed8"), ("disabled", "#94a3b8")])
        style.configure("Success.TButton", font=("Segoe UI", 9), background="#10b981", foreground="#ffffff")
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("Treeview", rowheight=24)

    def _create_header(self):
        header_frame = ttk.Frame(self.root, padding=(16, 12, 16, 8))
        header_frame.pack(fill=tk.X)

        title = ttk.Label(header_frame, text="iOS Keychain Correlator", style="Title.TLabel")
        title.pack(anchor=tk.W)

        subtitle = ttk.Label(
            header_frame,
            text="Automatically match Keychain keys with SQLCipher databases, decrypt evidence, and view recovered tables.",
            style="Subtitle.TLabel",
        )
        subtitle.pack(anchor=tk.W)

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=16, pady=4)

    def _create_inputs_section(self):
        frame = ttk.LabelFrame(self.root, text=" 1. Input & Output Paths ", padding=12)
        frame.pack(fill=tk.X, padx=16, pady=6)

        # Extraction Root
        ttk.Label(frame, text="iOS Extraction Root:").grid(row=0, column=0, sticky=tk.W, pady=4)
        self.extraction_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.extraction_var, width=65).grid(row=0, column=1, sticky=tk.EW, padx=8, pady=4)
        ttk.Button(frame, text="Browse...", command=self._browse_extraction).grid(row=0, column=2, pady=4)

        # Keychain JSON
        ttk.Label(frame, text="Keychain JSON File:").grid(row=1, column=0, sticky=tk.W, pady=4)
        self.keychain_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.keychain_var, width=65).grid(row=1, column=1, sticky=tk.EW, padx=8, pady=4)
        ttk.Button(frame, text="Browse...", command=self._browse_keychain).grid(row=1, column=2, pady=4)

        # Output Folder
        ttk.Label(frame, text="Output Directory:").grid(row=2, column=0, sticky=tk.W, pady=4)
        self.out_dir_var = tk.StringVar(value=str(Path.cwd() / "out" / "gui_run"))
        ttk.Entry(frame, textvariable=self.out_dir_var, width=65).grid(row=2, column=1, sticky=tk.EW, padx=8, pady=4)
        ttk.Button(frame, text="Browse...", command=self._browse_out_dir).grid(row=2, column=2, pady=4)

        # Options line
        opts_frame = ttk.Frame(frame)
        opts_frame.grid(row=3, column=1, sticky=tk.W, pady=(6, 0))

        self.export_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            opts_frame,
            text="Export decrypted SQLite databases (allows viewing messages & tables)",
            variable=self.export_var,
        ).pack(side=tk.LEFT)

        ttk.Button(
            frame,
            text="✨ Load Demo Data",
            command=self._load_demo_data,
        ).grid(row=3, column=2, sticky=tk.E, pady=(6, 0))

        frame.columnconfigure(1, weight=1)

    def _create_action_bar(self):
        frame = ttk.Frame(self.root, padding=(16, 6))
        frame.pack(fill=tk.X)

        self.run_button = ttk.Button(
            frame,
            text="🚀 Start Analysis & Decryption",
            style="Primary.TButton",
            command=self._start_analysis,
        )
        self.run_button.pack(side=tk.LEFT, ipadx=10, ipady=4)

        self.progress_bar = ttk.Progressbar(frame, mode="indeterminate", length=220)

        self.btn_open_html = ttk.Button(
            frame,
            text="📄 View HTML Report",
            state=tk.DISABLED,
            command=self._open_html_report,
        )
        self.btn_open_html.pack(side=tk.RIGHT, padx=4)

        self.btn_export_pdf = ttk.Button(
            frame,
            text="📑 Export Case PDF Report",
            command=self._export_case_pdf,
        )
        self.btn_export_pdf.pack(side=tk.RIGHT, padx=4)

        self.btn_open_folder = ttk.Button(
            frame,
            text="📂 Open Output Folder",
            state=tk.DISABLED,
            command=self._open_output_folder,
        )
        self.btn_open_folder.pack(side=tk.RIGHT, padx=4)

        self.btn_pairing = ttk.Button(
            frame,
            text="🔑 Scan Pairing Records",
            command=self._show_pairing_records,
        )
        self.btn_pairing.pack(side=tk.RIGHT, padx=4)

        self.btn_doctor = ttk.Button(
            frame,
            text="🏥 System Doctor & Auto-Heal",
            command=self._run_doctor_action,
        )
        self.btn_doctor.pack(side=tk.RIGHT, padx=4)

    def _create_main_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)

        # Tab 1: Live USB Device Acquisition
        self.tab_acquisition = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_acquisition, text=" 📱 Live USB Acquisition ")
        self._setup_acquisition_tab(self.tab_acquisition)

        # Tab 2: Dump Ingestion (Cellebrite / GrayKey / iTunes)
        self.tab_ingest = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_ingest, text=" 📦 Ingest Forensic Dump ")
        self._setup_ingest_tab(self.tab_ingest)

        # Tab 3: Correlation Summary Table
        self.tab_results = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_results, text=" 📊 Correlation Results ")
        self._setup_results_table(self.tab_results)

        # Tab 4: Decrypted Database Data Viewer
        self.tab_viewer = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_viewer, text=" 🔍 Browse Decrypted Data ")
        self._setup_data_viewer(self.tab_viewer)

        # Tab 5: Deep Keyword Search
        self.tab_search = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_search, text=" 🔎 Evidence Search ")
        self._setup_search_tab(self.tab_search)

        # Tab 6: Execution Logs
        self.tab_logs = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_logs, text=" 📜 Execution Logs ")
        self._setup_logs_view(self.tab_logs)

        # Tab 7: Forensic Process Map & Provenance Timeline
        self.tab_provenance = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_provenance, text=" 🗺️ Forensic Process Map ")
        self._setup_provenance_tab(self.tab_provenance)

    def _setup_results_table(self, parent):
        cols = ("status", "database", "bundle", "fingerprint", "profile", "wal")
        self.results_tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")

        self.results_tree.heading("status", text="Status")
        self.results_tree.heading("database", text="Database Name / Relative Path")
        self.results_tree.heading("bundle", text="Application Bundle ID")
        self.results_tree.heading("fingerprint", text="Key Fingerprint")
        self.results_tree.heading("profile", text="Profile")
        self.results_tree.heading("wal", text="WAL Active")

        self.results_tree.column("status", width=110, anchor=tk.CENTER)
        self.results_tree.column("database", width=340, anchor=tk.W)
        self.results_tree.column("bundle", width=180, anchor=tk.W)
        self.results_tree.column("fingerprint", width=110, anchor=tk.CENTER)
        self.results_tree.column("profile", width=90, anchor=tk.CENTER)
        self.results_tree.column("wal", width=80, anchor=tk.CENTER)

        # Color tags
        self.results_tree.tag_configure("decrypted", background="#ecfdf5", foreground="#065f46")
        self.results_tree.tag_configure("plain", background="#eff6ff", foreground="#1e40af")
        self.results_tree.tag_configure("locked", background="#fef2f2", foreground="#991b1b")

        vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.results_tree.yview)
        hsb = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.results_tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)

        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

    def _setup_data_viewer(self, parent):
        controls = ttk.Frame(parent)
        controls.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(controls, text="Select Database:").pack(side=tk.LEFT, padx=(0, 4))
        self.db_selector = ttk.Combobox(controls, state="readonly", width=32)
        self.db_selector.pack(side=tk.LEFT, padx=4)
        self.db_selector.bind("<<ComboboxSelected>>", self._on_db_selected)

        ttk.Label(controls, text="Select Table:").pack(side=tk.LEFT, padx=(12, 4))
        self.table_selector = ttk.Combobox(controls, state="readonly", width=22)
        self.table_selector.pack(side=tk.LEFT, padx=4)
        self.table_selector.bind("<<ComboboxSelected>>", self._on_table_selected)

        self.table_count_label = ttk.Label(controls, text="", foreground="#64748b")
        self.table_count_label.pack(side=tk.RIGHT, padx=4)

        # Viewer Treeview for generic tabular display
        table_container = ttk.Frame(parent)
        table_container.pack(fill=tk.BOTH, expand=True)

        self.data_tree = ttk.Treeview(table_container, show="headings")
        data_vsb = ttk.Scrollbar(table_container, orient=tk.VERTICAL, command=self.data_tree.yview)
        data_hsb = ttk.Scrollbar(table_container, orient=tk.HORIZONTAL, command=self.data_tree.xview)
        self.data_tree.configure(yscrollcommand=data_vsb.set, xscrollcommand=data_hsb.set)

        self.data_tree.grid(row=0, column=0, sticky=tk.NSEW)
        data_vsb.grid(row=0, column=1, sticky=tk.NS)
        data_hsb.grid(row=1, column=0, sticky=tk.EW)

        table_container.columnconfigure(0, weight=1)
        table_container.rowconfigure(0, weight=1)

    def _setup_logs_view(self, parent):
        self.log_text = tk.Text(parent, wrap=tk.WORD, font=("Consolas", 9), background="#0f172a", foreground="#f8fafc")
        log_sb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_sb.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_sb.pack(side=tk.RIGHT, fill=tk.Y)

    def _create_status_bar(self):
        self.status_var = tk.StringVar(value="Ready. Select paths or click 'Load Demo Data' to begin.")
        bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, padding=(8, 4))
        bar.pack(side=tk.BOTTOM, fill=tk.X)

    # ---------------- User Action Handlers ----------------

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
        chosen = filedialog.askdirectory(title="Select Output Directory for Reports")
        if chosen:
            self.out_dir_var.set(chosen)

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
        self.status_var.set("Fragmented Enclave demo loaded. Click 'Start Analysis & Decryption' to test!")

    def _log(self, message: str):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def _start_analysis(self):
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
        self._log(f"[*] Starting analysis...\n  Extraction: {ext}\n  Keychain: {kc}\n  Output: {out}")

        # Run pipeline in a background thread so UI stays responsive
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

            # Update UI on main thread
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
            
            # Format friendly message for GUI popup
            steps_txt = "\n".join([f"  {i}. {s}" for i, s in enumerate(diag.get("steps", []), 1)])
            msg = f"{diag['title']}\n\nCause: {diag['cause']}\n\nRecommended Fix:\n{steps_txt}"
            if diag.get("quick_command"):
                msg += f"\n\nQuick Command to Fix:\n{diag['quick_command']}"
            
            messagebox.showerror("Troubleshooter & Diagnosis", msg)
            self.status_var.set(f"Error: {diag['title']}. Check the Execution Logs tab for detailed steps.")
            return

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

        self.pipeline_result = result
        self.btn_open_html.config(state=tk.NORMAL)
        self.btn_open_folder.config(state=tk.NORMAL)

        total = result["total_databases"]
        decrypted = result["decrypted_count"]
        plain = result["plain_count"]
        locked = result["locked_count"]

        self._log(f"[+] Finished! Total: {total} databases ({decrypted} decrypted, {plain} plain, {locked} locked).")
        self.status_var.set(f"Completed! {decrypted} decrypted, {plain} plain, {locked} locked databases.")

        # Populate Results Treeview
        self._populate_results_table(result["results"])

        # Populate Database Viewer Dropdown
        self._populate_accessible_databases(result)

        # Populate Forensic Process Map
        self._populate_provenance_table(result.get("provenance_map", []))

        messagebox.showinfo(
            "Analysis Complete",
            f"Forensic correlation finished!\n\n"
            f"• Decrypted Databases: {decrypted}\n"
            f"• Plain Databases: {plain}\n"
            f"• Locked / Undecrypted: {locked}\n\n"
            f"Check the 'Browse Decrypted Data' tab to inspect recovered tables!",
        )

    def _populate_results_table(self, results: List[Any]):
        self.results_tree.delete(*self.results_tree.get_children())
        for r in results:
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

    def _populate_accessible_databases(self, result: Dict[str, Any]):
        self.accessible_databases.clear()
        ext_root = Path(self.extraction_var.get())
        out_root = Path(self.out_dir_var.get())
        exports_root = out_root / "exports"

        # 1. Add exported decrypted databases
        if exports_root.exists():
            for exp_file in exports_root.rglob("*"):
                if exp_file.is_file() and exp_file.suffix in (".sqlite", ".db", ".sqlite3"):
                    rel = exp_file.relative_to(exports_root).as_posix()
                    name = f"[Decrypted] {exp_file.name} ({rel})"
                    self.accessible_databases[name] = exp_file

        # 2. Add plain databases directly from extraction
        for r in result["results"]:
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
            con = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
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
            con = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
            cur = con.cursor()
            cur.execute(f'SELECT * FROM "{table_name}" LIMIT 500;')
            col_names = [d[0] for d in cur.description] if cur.description else []
            rows = cur.fetchall()
            con.close()

            # Configure Treeview columns dynamically
            self.data_tree["columns"] = col_names
            for col in col_names:
                self.data_tree.heading(col, text=col)
                self.data_tree.column(col, width=120, anchor=tk.W)

            self.data_tree.delete(*self.data_tree.get_children())
            for row in rows:
                self.data_tree.insert("", tk.END, values=[str(v) if v is not None else "<NULL>" for v in row])

            self.table_count_label.config(text=f"{len(rows)} row(s) loaded")
        except Exception as e:
            messagebox.showwarning("Table Read Error", f"Unable to read table rows: {e}")

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
        mid_frame = ttk.LabelFrame(parent, text=" Connected iOS Device ", padding=10)
        mid_frame.pack(fill=tk.X, pady=6)

        self.lbl_device_status = ttk.Label(
            mid_frame,
            text="No USB device scan performed yet. Click 'Refresh Devices'.",
            font=("Segoe UI", 10, "bold"),
            foreground="#475569",
        )
        self.lbl_device_status.pack(anchor=tk.W, pady=2)

        self.lbl_device_details = ttk.Label(
            mid_frame,
            text="Model: - | iOS: - | UDID: - | Pairing: -",
            foreground="#64748b",
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

        self.acq_log_text = tk.Text(log_frame, wrap=tk.WORD, font=("Consolas", 9), height=10, bg="#0f172a", fg="#e2e8f0")
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
        """Pulls DCIM photos over Apple File Conduit without requiring passcode."""
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
                self._append_acq_log(f"[-] AFC error: {e}")
                messagebox.showerror("AFC Error", f"AFC photo extraction failed: {e}")

        threading.Thread(target=_worker, daemon=True).start()

    def _crack_backup_password(self):
        """Attempts dictionary attack against backup Manifest.plist PBKDF2 hash."""
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

                # Test common forensic password dictionary
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
                self._append_acq_log(f"[-] Cracker error: {e}")
                messagebox.showerror("Error", f"Password cracker failed: {e}")

        threading.Thread(target=_worker, daemon=True).start()

    def _export_case_pdf(self):
        """Generates and saves a complete court-ready PDF case report."""
        pdf_path = filedialog.asksaveasfilename(
            title="Export Official Forensic PDF Report",
            defaultextension=".pdf",
            filetypes=[("PDF Document", "*.pdf")],
            initialfile="Forensic_Case_Report.pdf",
        )
        if not pdf_path:
            return

        try:
            # Gather case data from current pipeline result or state
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
                "case_id": "GUI-EXPORT",
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
                    "device_name": "Seized iOS Target Device",
                    "device_model": "iPhone / iPad",
                    "os_version": "iOS 16/17 (Production)",
                    "serial_number": "EXHIBIT-A",
                    "access_tier": "FULL_BACKUP (AFU)",
                    "total_databases": len(results_list),
                }],
                "databases": results_list,
                "evidence_samples": [],
            }

            # If accessible databases exist, sample a few message snippets
            for db_name, p in list(self.accessible_databases.items())[:3]:
                try:
                    con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
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
            # Offer to open PDF
            try:
                os.startfile(pdf_path)
            except Exception:
                pass
        except Exception as e:
            messagebox.showerror("PDF Export Failed", f"Could not generate PDF: {e}")

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
                self._append_acq_log(f"[-] Profile extraction error: {e}")
                messagebox.showerror("Error", f"Could not dump device profile: {e}")

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
                # Auto switch to Results tab
                self.root.after(0, lambda: self.notebook.select(self.tab_results))
            except Exception as e:
                self.root.after(0, lambda: self._append_acq_log(f"[-] Acquisition failed: {e}"))
                self.root.after(0, lambda: messagebox.showerror("Acquisition Error", f"Live USB acquisition failed: {e}"))
            finally:
                self.root.after(0, lambda: self.btn_1click_acquire.config(state=tk.NORMAL))

        threading.Thread(target=_worker, daemon=True).start()

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

    # ── Pairing Records Feature ──────────────────────────────────────────

    def _show_pairing_records(self):
        from correlator.pairing import find_pairing_records, get_pairing_summary
        summary = get_pairing_summary()
        self._log("\n" + summary)

        records = find_pairing_records()
        win = tk.Toplevel(self.root)
        win.title("Discovered iOS Pairing Records")
        win.geometry("640x400")

        txt = tk.Text(win, wrap=tk.WORD, font=("Consolas", 9), bg="#0f172a", fg="#f8fafc", padx=10, pady=10)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, summary)
        txt.config(state=tk.DISABLED)

    # ── Dump Ingestion Tab (Cellebrite / GrayKey / iTunes) ────────────────

    def _setup_ingest_tab(self, parent):
        top = ttk.LabelFrame(parent, text=" Forensic Dump Source ", padding=10)
        top.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(top, text="Select extraction directory exported by Cellebrite UFED, GrayKey, or iTunes:").pack(anchor=tk.W, pady=(0, 4))
        
        row1 = ttk.Frame(top)
        row1.pack(fill=tk.X, pady=2)

        self.dump_path_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self.dump_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(row1, text="Browse Folder...", command=self._browse_dump_dir).pack(side=tk.RIGHT)

        row2 = ttk.Frame(top)
        row2.pack(fill=tk.X, pady=(6, 0))

        self.lbl_dump_format = ttk.Label(row2, text="Detected Format: None selected", font=("Segoe UI", 9, "bold"), foreground="#475569")
        self.lbl_dump_format.pack(side=tk.LEFT)

        btn_detect = ttk.Button(row2, text="🔍 Auto-Detect", command=self._detect_dump)
        btn_detect.pack(side=tk.RIGHT)

        # Ingest Action Buttons
        btn_bar = ttk.Frame(parent, padding=(0, 6))
        btn_bar.pack(fill=tk.X)

        self.btn_ingest_only = ttk.Button(btn_bar, text="📁 Normalize Dump to Extraction", command=lambda: self._run_dump_ingestion(analyze=False))
        self.btn_ingest_only.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_ingest_analyze = ttk.Button(
            btn_bar,
            text="⚡ 1-Click Ingest, Correlate & Decrypt",
            style="Primary.TButton",
            command=lambda: self._run_dump_ingestion(analyze=True),
        )
        self.btn_ingest_analyze.pack(side=tk.LEFT, ipadx=8, ipady=3)

        # Progress and Log
        ingest_log_frame = ttk.LabelFrame(parent, text=" Ingestion Progress ", padding=8)
        ingest_log_frame.pack(fill=tk.BOTH, expand=True, pady=6)

        self.ingest_progress = ttk.Progressbar(ingest_log_frame, mode="determinate", maximum=100)
        self.ingest_progress.pack(fill=tk.X, pady=(0, 6))

        self.ingest_log = tk.Text(ingest_log_frame, wrap=tk.WORD, font=("Consolas", 9), bg="#0f172a", fg="#e2e8f0")
        self.ingest_log.pack(fill=tk.BOTH, expand=True)

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
        self.lbl_dump_format.config(text=f"Detected Format: {names.get(fmt, fmt)}", foreground="#16a34a")
        self.ingest_log.insert(tk.END, f"[+] Selected dump: {p}\n    Format: {fmt}\n")

    def _run_dump_ingestion(self, analyze: bool):
        p = self.dump_path_var.get().strip()
        if not p or not Path(p).is_dir():
            messagebox.showerror("Error", "Please select a valid dump directory.")
            return

        out_dir = Path(self.out_dir_var.get()) / "ingested_dump"

        def _worker():
            def cb(msg, pct):
                self.root.after(0, lambda: self.ingest_progress.configure(value=int(pct * 100)))
                self.root.after(0, lambda: self.ingest_log.insert(tk.END, f"[{int(pct*100):>3}%] {msg}\n"))
                self.root.after(0, lambda: self.ingest_log.see(tk.END))

            try:
                from correlator.dump_ingest import ingest_and_analyze, normalize_dump_to_extraction
                if analyze:
                    res = ingest_and_analyze(p, out_dir, progress_callback=cb)
                    self.root.after(0, lambda: self.extraction_var.set(str(res["extraction_path"])))
                    if res.get("keychain_path"):
                        self.root.after(0, lambda: self.keychain_var.set(str(res["keychain_path"])))
                    if res.get("pipeline_result"):
                        pipe = res["pipeline_result"]
                        self.pipeline_result = pipe
                        self.root.after(0, lambda: self._populate_results_table(pipe["results"]))
                        self.root.after(0, lambda: self._populate_accessible_databases(pipe))
                        self.root.after(0, lambda: self._populate_provenance_table(pipe.get("provenance_map", [])))
                    self.root.after(0, lambda: messagebox.showinfo("Ingestion Succeeded", f"Decrypted {res['decrypted_count']} databases from {res['format']} dump!"))
                    self.root.after(0, lambda: self.notebook.select(self.tab_results))
                else:
                    res = normalize_dump_to_extraction(p, out_dir, progress_callback=cb)
                    self.root.after(0, lambda: self.extraction_var.set(str(res["extraction_path"])))
                    if res.get("keychain_path"):
                        self.root.after(0, lambda: self.keychain_var.set(str(res["keychain_path"])))
                    self.root.after(0, lambda: messagebox.showinfo("Normalized", f"Extracted {res['db_count']} databases. Ready to correlate!"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Ingestion Error", f"Failed to ingest dump: {e}"))

        threading.Thread(target=_worker, daemon=True).start()

    # ── Deep Evidence Search Tab ─────────────────────────────────────────

    def _setup_search_tab(self, parent):
        controls = ttk.LabelFrame(parent, text=" Search Target & Parameters ", padding=10)
        controls.pack(fill=tk.X, pady=(0, 6))

        row1 = ttk.Frame(controls)
        row1.pack(fill=tk.X, pady=2)

        ttk.Label(row1, text="Keyword / Phone / Suspect Name:").pack(side=tk.LEFT, padx=(0, 6))
        self.search_keyword_var = tk.StringVar()
        entry_kw = ttk.Entry(row1, textvariable=self.search_keyword_var, width=35)
        entry_kw.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        entry_kw.bind("<Return>", lambda e: self._execute_evidence_search())

        btn_search = ttk.Button(row1, text="🔍 Search All Evidence", style="Primary.TButton", command=self._execute_evidence_search)
        btn_search.pack(side=tk.RIGHT)

        row2 = ttk.Frame(controls)
        row2.pack(fill=tk.X, pady=(6, 0))

        self.lbl_search_summary = ttk.Label(row2, text="Ready. Enter a keyword to search across all decrypted databases.", foreground="#64748b")
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
        self.search_tree.column("context", width=450, anchor=tk.W)

        s_vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.search_tree.yview)
        s_hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.search_tree.xview)
        self.search_tree.configure(yscrollcommand=s_vsb.set, xscrollcommand=s_hsb.set)

        self.search_tree.grid(row=0, column=0, sticky=tk.NSEW)
        s_vsb.grid(row=0, column=1, sticky=tk.NS)
        s_hsb.grid(row=1, column=0, sticky=tk.EW)

        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        self.current_search_hits = []

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

        self.lbl_search_summary.config(text=f"Searching for '{kw}'...", foreground="#2563eb")
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
                    foreground="#16a34a" if hits else "#dc2626",
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


    def _setup_provenance_tab(self, parent):
        top_frame = ttk.Frame(parent, padding=(0, 4))
        top_frame.pack(fill=tk.X)

        self.lbl_prov_summary = ttk.Label(
            top_frame,
            text="Chronological Forensic Execution Map (0 Steps Recorded)",
            font=("Segoe UI", 10, "bold"),
            foreground="#1e293b",
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
        self.prov_tree.column("action", width=360, anchor=tk.W)
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


def main():
    root = tk.Tk()
    app = ForensicCorrelatorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
