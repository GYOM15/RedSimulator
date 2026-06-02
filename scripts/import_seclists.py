#!/usr/bin/env python3
"""Import payloads from SecLists into the local payload database.

Downloads curated payload lists from the SecLists GitHub repository and
organizes them into data/payloads/{type}/{category}.txt format compatible
with the PayloadDatabase class.

Usage:
    python scripts/import_seclists.py

The script is idempotent -- existing files are skipped unless --force is used.
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
import urllib.error
from pathlib import Path

# Base URL for raw SecLists files on GitHub
_SECLISTS_RAW = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"

# Mapping: (local_path, remote_url, description)
# Each entry downloads a specific SecLists file into the local payload database.
_DOWNLOADS: list[tuple[str, str, str]] = [
    # SQLi payloads
    (
        "sqli/generic_sqli.txt",
        f"{_SECLISTS_RAW}/Fuzzing/SQLi/Generic-SQLi.txt",
        "Generic SQL injection payloads",
    ),
    (
        "sqli/generic_blind_sqli.txt",
        f"{_SECLISTS_RAW}/Fuzzing/SQLi/Generic-BlindSQLi.txt",
        "Generic blind SQL injection payloads",
    ),
    # XSS payloads
    (
        "xss/xss_basic.txt",
        f"{_SECLISTS_RAW}/Fuzzing/XSS/XSS-Jhaddix.txt",
        "XSS payloads from Jhaddix collection",
    ),
    (
        "xss/xss_cheat_sheet_filter_evasion.txt",
        f"{_SECLISTS_RAW}/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt",
        "XSS filter evasion from PortSwigger",
    ),
    # Command injection
    (
        "command_injection/commix.txt",
        f"{_SECLISTS_RAW}/Fuzzing/command-injection-commix.txt",
        "Command injection payloads from Commix",
    ),
    # Path traversal / LFI
    (
        "path_traversal/lfi_linux.txt",
        f"{_SECLISTS_RAW}/Fuzzing/LFI/LFI-Jhaddix.txt",
        "LFI/path traversal payloads from Jhaddix",
    ),
    # Auth bypass
    (
        "auth_bypass/default_passwords.txt",
        f"{_SECLISTS_RAW}/Passwords/Default-Credentials/default-passwords.csv",
        "Default credential pairs",
    ),
    # Open redirect
    (
        "open_redirect/open_redirects.txt",
        f"{_SECLISTS_RAW}/Fuzzing/open-redirect-payloads.txt",
        "Open redirect payloads",
    ),
]


def _download_file(url: str, dest: Path, force: bool = False) -> bool:
    """Download a file from a URL to a local path.

    Returns True if the file was downloaded, False if skipped.
    """
    if dest.exists() and not force:
        print(f"  [SKIP] {dest.relative_to(dest.parent.parent.parent)} (already exists)")
        return False

    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        print(f"  [DOWN] {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "RedSimulator/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read()

        # Write the downloaded content
        dest.write_bytes(content)

        # Count non-empty, non-comment lines
        lines = [
            line
            for line in content.decode("utf-8", errors="replace").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        print(f"  [ OK ] {dest.relative_to(dest.parent.parent.parent)} ({len(lines)} payloads)")
        return True

    except urllib.error.HTTPError as e:
        print(f"  [FAIL] HTTP {e.code} for {url}")
        return False
    except urllib.error.URLError as e:
        print(f"  [FAIL] Network error for {url}: {e.reason}")
        return False
    except OSError as e:
        print(f"  [FAIL] IO error writing {dest}: {e}")
        return False


def main() -> int:
    """Download SecLists payloads into the local database."""
    parser = argparse.ArgumentParser(
        description="Import payloads from SecLists into the local payload database."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing files instead of skipping them.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output directory (default: data/payloads/ relative to project root).",
    )
    args = parser.parse_args()

    # Determine output directory
    if args.output:
        base_dir = args.output
    else:
        # Resolve relative to this script's location (scripts/ -> project root -> data/payloads)
        project_root = Path(__file__).resolve().parent.parent
        base_dir = project_root / "data" / "payloads"

    print(f"SecLists Payload Importer")
    print(f"========================")
    print(f"Output directory: {base_dir}")
    print(f"Force overwrite: {args.force}")
    print()

    downloaded = 0
    skipped = 0
    failed = 0

    for local_path, url, description in _DOWNLOADS:
        dest = base_dir / local_path
        print(f"[{description}]")
        result = _download_file(url, dest, force=args.force)
        if result:
            downloaded += 1
        elif dest.exists():
            skipped += 1
        else:
            failed += 1
        print()

    print(f"Done: {downloaded} downloaded, {skipped} skipped, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
