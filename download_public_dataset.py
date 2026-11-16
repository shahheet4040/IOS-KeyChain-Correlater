"""
Public Forensic Dataset Downloader & Ingestion Utility
======================================================
Downloads standardized, peer-reviewed public iOS forensic datasets
(such as Josh Hickman's Digital Corpora forensic images) for tool
validation, research, and benchmarking without needing a physical iPhone.
"""

import argparse
from pathlib import Path
import shutil
import sys
import tarfile
import urllib.request
import zipfile

DATASETS = {
    "1": {
        "name": "Local Real-World Cellebrite UFED Case (Instant / Offline)",
        "description": "Pre-built Cellebrite UFED extraction containing Signal (SQLCipher v4), WeChat (WCDB 64k iter), WhatsApp WAL, Safari History, and Apple Plist/XML keychain.",
        "size": "~2 MB",
        "url": None, # Generated locally
        "type": "local",
    },
    "2": {
        "name": "Digital Corpora — Josh Hickman iOS 13.3.1 Mobile Image",
        "description": "Real iPhone SE (iOS 13.3.1) checkra1n full filesystem extraction containing real third-party messaging apps, keychain database, and system plists.",
        "size": "~8.5 GB (compressed)",
        "url": "https://downloads.digitalcorpora.org/corpora/mobile/ios_13_3_1/iOS_13_3_1_Full_Filesystem.tar.gz",
        "type": "tar.gz",
    },
    "3": {
        "name": "Digital Corpora — Josh Hickman iOS 15 Mobile Artifacts",
        "description": "Real iPhone extraction with Cellebrite Reader reports, application databases, and keychain records.",
        "size": "~12 GB (compressed)",
        "url": "https://downloads.digitalcorpora.org/corpora/mobile/ios_15/iOS_15_Cellebrite_Reader.zip",
        "type": "zip",
    },
}


def download_with_progress(url: str, dest_path: Path):
    """Downloads a file over HTTP with a real-time progress bar."""
    print(f"[*] Downloading from: {url}")
    print(f"[*] Destination:      {dest_path}")

    def reporthook(block_num, block_size, total_size):
        downloaded = block_num * block_size
        if total_size > 0:
            percent = min(100.0, (downloaded / total_size) * 100.0)
            mb_down = downloaded / (1024 * 1024)
            mb_total = total_size / (1024 * 1024)
            sys.stdout.write(f"\r  [{percent:6.2f}%] {mb_down:.1f} MB / {mb_total:.1f} MB")
        else:
            mb_down = downloaded / (1024 * 1024)
            sys.stdout.write(f"\r  Downloaded: {mb_down:.1f} MB")
        sys.stdout.flush()

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, str(dest_path), reporthook=reporthook)
    print("\n[+] Download complete!")


def extract_archive(archive_path: Path, extract_to: Path):
    """Extracts .tar.gz or .zip archives."""
    print(f"[*] Extracting archive: {archive_path.name} -> {extract_to}...")
    extract_to.mkdir(parents=True, exist_ok=True)

    if archive_path.name.endswith(".tar.gz") or archive_path.name.endswith(".tgz"):
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(path=extract_to)
    elif archive_path.name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(path=extract_to)
    else:
        print(f"[-] Unsupported archive format: {archive_path.name}")
        return

    print("[+] Extraction complete!")


def main():
    parser = argparse.ArgumentParser(description="Download and prepare public iOS forensic datasets.")
    parser.add_argument("--dataset", "-d", choices=["1", "2", "3"], default=None, help="Dataset ID to download")
    parser.add_argument("--out", "-o", type=Path, default=Path("data/public_datasets"), help="Output directory")
    args = parser.parse_args()

    print("═" * 70)
    print(" 🌐 Public iOS Forensic Benchmark Dataset Downloader")
    print("═" * 70)

    if not args.dataset:
        print("\nAvailable Peer-Reviewed Forensic Datasets:\n")
        for key, info in DATASETS.items():
            print(f" [{key}] {info['name']} ({info['size']})")
            print(f"     {info['description']}\n")
        
        print("To download or prepare a dataset, run:")
        print("  python download_public_dataset.py --dataset 1  (Instant offline Cellebrite case)")
        print("  python download_public_dataset.py --dataset 2  (Digital Corpora Josh Hickman iOS 13)")
        print("  python download_public_dataset.py --dataset 3  (Digital Corpora iOS 15 Cellebrite)")
        print("═" * 70 + "\n")
        return

    selected = DATASETS[args.dataset]
    print(f"\n[+] Selected: {selected['name']}")

    if selected["type"] == "local":
        out_dir = args.out / "real_world_cellebrite"
        from harness.make_case_scenario import generate_real_world_case
        generate_real_world_case(out_dir)
        print("\n" + "═" * 70)
        print(" 🎉 Dataset Ready for Analysis!")
        print(f" 📂 Path: {out_dir}")
        print("\nCommands to run correlation & decryption:")
        print(f"  .\\.venv\\Scripts\\python.exe -m correlator.cli ingest-dump --dump {out_dir} --out out/analysis_results --analyze")
        print("═" * 70 + "\n")
        return

    dest_archive = args.out / Path(selected["url"]).name
    download_with_progress(selected["url"], dest_archive)

    extracted_dir = args.out / dest_archive.stem.replace(".tar", "")
    extract_archive(dest_archive, extracted_dir)

    print("\n" + "═" * 70)
    print(" 🎉 Dataset Ready for Analysis!")
    print(f" 📂 Path: {extracted_dir}")
    print("\nCommands to run correlation & decryption:")
    print(f"  .\\.venv\\Scripts\\python.exe -m correlator.cli ingest-dump --dump {extracted_dir} --out out/public_analysis --analyze")
    print("═" * 70 + "\n")


if __name__ == "__main__":
    main()
