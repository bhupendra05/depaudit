"""High-level audit runner — combines license + CVE checks."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Set

from .resolver import PackageInfo, resolve_installed
from .licenses import classify, LicenseFinding, LicenseRisk
from .vulnerabilities import fetch_vulnerabilities, Vulnerability


@dataclass
class PackageAudit:
    package: PackageInfo
    license_finding: LicenseFinding
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return (
            self.license_finding.risk in (LicenseRisk.FORBIDDEN, LicenseRisk.RESTRICTED, LicenseRisk.UNKNOWN)
            or bool(self.vulnerabilities)
        )


@dataclass
class AuditReport:
    audits: List[PackageAudit] = field(default_factory=list)

    @property
    def license_issues(self) -> List[PackageAudit]:
        return [a for a in self.audits
                if a.license_finding.risk in (LicenseRisk.FORBIDDEN, LicenseRisk.RESTRICTED, LicenseRisk.UNKNOWN)]

    @property
    def vuln_issues(self) -> List[PackageAudit]:
        return [a for a in self.audits if a.vulnerabilities]

    @property
    def clean(self) -> List[PackageAudit]:
        return [a for a in self.audits if not a.has_issues]

    @property
    def total_vulns(self) -> int:
        return sum(len(a.vulnerabilities) for a in self.audits)


def _license_message(risk: LicenseRisk, license_str: str) -> str:
    if risk == LicenseRisk.FORBIDDEN:
        return f"Forbidden license ({license_str}) — may require open-sourcing your code"
    if risk == LicenseRisk.RESTRICTED:
        return f"Restricted license ({license_str}) — copyleft, must disclose modifications"
    if risk == LicenseRisk.UNKNOWN:
        return f"Unknown license ({license_str!r}) — review manually"
    return f"Allowed ({license_str})"


def run_audit(
    packages: Optional[List[str]] = None,
    check_vulns: bool = True,
    ignore_licenses: Optional[Set[str]] = None,
    ignore_packages: Optional[Set[str]] = None,
    timeout: int = 10,
) -> AuditReport:
    """
    Audit installed packages for license compliance and known CVEs.

    Args:
        packages: limit to these package names (None = all installed)
        check_vulns: whether to query OSV.dev for CVEs
        ignore_licenses: set of license strings to treat as allowed
        ignore_packages: package names to skip entirely
    """
    ignore_licenses = ignore_licenses or set()
    ignore_packages = {p.lower() for p in (ignore_packages or set())}

    pkg_list = resolve_installed(packages)
    report = AuditReport()

    for pkg in pkg_list:
        if pkg.name.lower() in ignore_packages:
            continue

        # License check
        risk = classify(pkg.license)
        if pkg.license in ignore_licenses:
            risk = LicenseRisk.ALLOWED

        lf = LicenseFinding(
            package=pkg.name,
            version=pkg.version,
            license=pkg.license,
            risk=risk,
            message=_license_message(risk, pkg.license),
        )

        # CVE check
        vulns: List[Vulnerability] = []
        if check_vulns:
            vulns = fetch_vulnerabilities(pkg.name, pkg.version, timeout=timeout)

        report.audits.append(PackageAudit(package=pkg, license_finding=lf, vulnerabilities=vulns))

    return report
