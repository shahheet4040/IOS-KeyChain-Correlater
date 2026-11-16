# 🛡️ iOS Keychain Correlator — Digital Forensic Suite

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688.svg)](https://fastapi.tiangolo.com/)
[![SQLCipher](https://img.shields.io/badge/SQLCipher-v1--v4-orange.svg)](https://www.zetetic.net/sqlcipher/)
[![Tests Passing](https://img.shields.io/badge/Tests-116%2F116%20Passed-brightgreen.svg)]()
[![Platform: Windows / macOS / Linux](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)]()

> **An automated digital forensics analysis engine designed for Scientific Officers, Law Enforcement, and DFIR Examiners to correlate raw iOS Keychain dumps with encrypted application databases, decrypting databases, recovering uncommitted WAL frames, and exporting court-admissible evidence.**

---

## 🔍 The Problem It Solves

In modern mobile forensics, physical or logical acquisition tools (Cellebrite UFED, GrayKey, iTunes) extract raw filesystems and keychain databases in 1–2 hours. However:
* **The Manual Bottleneck:** Raw keychains often contain thousands of generic password entries, certificates, and base64 payloads. Matching the correct 256-bit AES key to the corresponding encrypted application database (Signal, WeChat, WhatsApp, etc.) manually takes **hours to days**.
* **Cryptographic Variance:** Different iOS applications use distinct SQLCipher iterations, page sizes, and HMAC algorithms (e.g., Signal uses 4096-byte pages; WeChat/WCDB uses 64,000 PBKDF2 iterations).
* **Evidence in WAL:** Critical recent messages often reside in SQLite Write-Ahead Log (`-wal`) journals that typical parsers miss before checkpointing.

**iOS Keychain Correlator eliminates this bottleneck**, automating the correlation, decryption, and verification process into **30 seconds**.

---

## ✨ Key Features

* **📦 Forensic Dump Auto-Ingestion:** Automatically detects and ingests extraction directories from **Cellebrite UFED / Physical Analyzer**, **GrayKey**, and **iTunes / Finder** backups.
* **🔑 Universal Keychain Importer:** Seamlessly parses and normalizes dumps from **Frida scripts**, **Keychain-Dumper**, **Apple Binary/XML Plists**, **Cellebrite XML**, and **Elcomsoft CSV** exports.
* **🔐 Multi-Profile Decryption Matrix:** Pre-configured with cryptographic profiles covering:
  * Signal Messenger (SQLCipher v4, 4096-byte pages, HMAC-SHA512)
  * WeChat / WCDB (64,000 PBKDF2 iterations)
  * SQLCipher v1, v2, v3, and v4 compatibility modes
  * WhatsApp Crypt14/15 databases (AES-256-GCM / PBKDF2)
* **📝 Active WAL Journal Carver:** Inspects `-wal` files to calculate salt/checksums and recover uncommitted frames before SQLite merges or truncates them.
* **🔎 Universal Evidence Search Engine:** Deep-scans all decrypted tables across multiple databases simultaneously for phone numbers, suspect aliases, Bitcoin addresses, or keywords.
* **💻 Workstation Pairing Trust Scanner:** Discovers trusted Apple Lockdown certificates (`%ProgramData%\Apple\Lockdown\`) to identify devices paired with lab PCs.
* **🛡️ Chain of Custody & Immutability:** Never writes to pristine evidence. Performs baseline pre-run SHA-256 hashing and post-run cryptographic verification to ensure 100% evidence integrity.
* **📊 Dual Interface (Web & Desktop):**
  * **Enterprise Web Dashboard (FastAPI):** Clean, dark-themed cyber forensic interface with Swagger API docs.
  * **Interactive Self-Contained HTML Explorer:** Embedded directly into reports—browse chats, filter tables, and export CSVs without any server or internet connection.
  * **Desktop GUI & CLI:** Tkinter GUI and full command-line automation for scripting.

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────┐
│             INPUT EXTRACTIONS & ARTIFACTS              │
│  • Cellebrite UFED  • GrayKey  • iTunes  • Live USB   │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│           INGESTION & KEYCHAIN NORMALIZATION           │
│  • dump_ingest.py        • importer.py (Plist/XML/CSV) │
│  • sha256_custom.py      • pairing.py                  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│         CRYPTOGRAPHIC ENGINE & WAL INSPECTOR           │
│  • Multi-Profile Matrix  • Keychain Candidate Matcher  │
│  • SQLite/SQLCipher Triage • WAL Checkpoint Inspector  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│            DECRYPTED EVIDENCE & REPORTING              │
│  • Plain SQLite Exports  • Deep Keyword Search Engine  │
│  • Offline HTML Report   • Case Management (FSL)       │
│  • FastAPI Web App       • Desktop GUI & CLI           │
└────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/shahheet4040/IOS-KeyChain-Correlater.git
cd IOS-KeyChain-Correlater

# Create virtual environment & install dependencies
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Launch the Web Application
```bash
python run_webapp.py 8888
```
Open **[http://127.0.0.1:8888](http://127.0.0.1:8888)** to access the Forensic Dashboard and Swagger API docs at `/docs`.

### 3. Launch Desktop GUI
```bash
python -m correlator.gui
```

### 4. CLI Usage Examples

```bash
# 1-Click Ingest and Decrypt a Cellebrite / GrayKey Dump:
python -m correlator.cli ingest-dump --dump /path/to/dump --out out/case1 --analyze

# Manual Correlation (Extraction Root + Keychain Export):
python -m correlator.cli run --root /path/to/extraction --keychain /path/to/keychain.plist --out out/case1 --export-dir out/case1/decrypted

# Deep Evidence Search across decrypted databases:
python -m correlator.cli search -d out/case1/decrypted -k "suspect_name" --html out/search_report.html

# Scan Workstation for Paired Device Trust Certificates:
python -m correlator.cli pairing --scan
```

---

## 🧪 Testing & Validation

The suite includes **116 automated unit and integration tests** verifying cryptographic accuracy, format parsing, and report generation:

```bash
pytest
```

---

## ⚖️ Forensic Disclaimer

This software is developed strictly for **authorized digital forensics investigations, law enforcement, academic research, and lawful digital discovery**. It operates within lawful forensic boundaries (analyzing authorized extractions and lawfully paired devices) and does not exploit hardware security processors (SEP).
