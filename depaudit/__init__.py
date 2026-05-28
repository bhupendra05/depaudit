"""depaudit — dependency license and CVE compliance scanner."""
from .resolver import PackageInfo, resolve_installed
from .licenses import classify, LicenseFinding, LicenseRisk
from .vulnerabilities import fetch_vulnerabilities, Vulnerability
from .audit import run_audit, AuditReport, PackageAudit

__all__ = [
    "PackageInfo",
    "resolve_installed",
    "classify",
    "LicenseFinding",
    "LicenseRisk",
    "fetch_vulnerabilities",
    "Vulnerability",
    "run_audit",
    "AuditReport",
    "PackageAudit",
]
__version__ = "0.1.0"
