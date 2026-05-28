# depaudit

**Audit Python dependencies for license compliance and known CVEs — in one command.**

Know what licenses you're shipping and whether any of your dependencies have published vulnerabilities, before your legal or security team asks.

```bash
pip install depaudit
depaudit scan                  # audit everything installed
depaudit scan requests click   # audit specific packages
```

[![CI](https://github.com/bhupendra05/depaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/bhupendra05/depaudit/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it does

1. **License compliance** — classifies each dependency's license as `allowed`, `restricted` (weak copyleft), `forbidden` (strong copyleft/GPL), or `unknown`
2. **CVE checks** — queries [OSV.dev](https://osv.dev) (the open vulnerability database) for known vulnerabilities against the exact installed version
3. **Zero config** — works with any Python project, reads from the installed environment
4. **Offline-safe** — skip CVE checks with `--no-vulns` for air-gapped or CI environments

---

## CLI

```bash
# Full audit of all installed packages
depaudit scan

# Specific packages only
depaudit scan django requests numpy

# Skip CVE queries (license-only, works offline)
depaudit scan --no-vulns

# JSON output
depaudit scan --json

# Fail CI if any issues found
depaudit scan --fail-on-issues

# Fail CI only if CVEs found
depaudit scan --fail-on-vulns

# Treat a license as allowed (e.g. LGPL for internal tool)
depaudit scan --ignore-license LGPL-3.0

# Skip specific packages
depaudit scan --ignore-pkg some-internal-package

# List just licenses (no CVE check)
depaudit licenses
depaudit licenses requests click
```

**Example output:**

```
depaudit — 142 packages scanned

  CVE FINDINGS (2 vulnerability/ies):
  📦 requests==2.28.0
     CVE-2023-32681  [MEDIUM]  Requests forwards proxy-authorization to destination servers
       Fix: upgrade to >= 2.31.0
       https://osv.dev/vulnerability/CVE-2023-32681

  LICENSE FINDINGS (3 package(s)):
  [FORBIDDEN] some-gpl-lib==1.0.0  GPL-3.0
       Forbidden license (GPL-3.0) — may require open-sourcing your code
  [RESTRICTED] chardet==5.0.0  LGPL-2.1
       Restricted license (LGPL-2.1) — copyleft, must disclose modifications
  [UNKNOWN] my-internal==0.1.0  Proprietary
       Unknown license ('Proprietary') — review manually

  Summary: 3 license issue(s), 2 CVE(s)
```

---

## Python API

```python
from depaudit import run_audit, LicenseRisk

report = run_audit(
    packages=["django", "requests", "cryptography"],
    check_vulns=True,
    ignore_licenses={"LGPL-3.0"},  # acceptable for your project
)

print(f"CVEs found: {report.total_vulns}")

for audit in report.vuln_issues:
    for v in audit.vulnerabilities:
        print(f"[{v.severity}] {audit.package.name}: {v.vuln_id} — {v.summary}")
        if v.fixed_in:
            print(f"  Fix: upgrade to >={v.fixed_in}")

for audit in report.license_issues:
    if audit.license_finding.risk == LicenseRisk.FORBIDDEN:
        print(f"BLOCKED: {audit.package.name} ({audit.package.license})")
```

---

## License risk levels

| Risk | Licenses | Meaning |
|------|----------|---------|
| `allowed` | MIT, Apache-2.0, BSD, ISC, PSF | Use freely |
| `restricted` | LGPL, MPL, EPL | Must disclose changes to the library |
| `forbidden` | GPL-2.0/3.0, AGPL, SSPL | May require open-sourcing your whole project |
| `unknown` | anything else | Review manually |

---

## CI/CD

```yaml
- name: Dependency audit
  run: |
    pip install depaudit
    depaudit scan --fail-on-vulns --fail-on-issues --ignore-license LGPL-3.0
```

---

## License

MIT © [Bhupendra Tale](https://github.com/bhupendra05)
