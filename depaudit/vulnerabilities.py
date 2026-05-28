"""
CVE vulnerability lookup via PyPI's JSON API + OSV.dev.

Uses only stdlib (urllib) — no external dependencies.
"""
from __future__ import annotations
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Vulnerability:
    vuln_id: str        # CVE-xxxx or GHSA-xxxx
    summary: str
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    fixed_in: Optional[str] = None
    reference: str = ""


OSV_URL = "https://api.osv.dev/v1/query"


def _severity_from_osv(vuln: dict) -> str:
    sev = vuln.get("database_specific", {}).get("severity", "")
    if not sev:
        # Try CVSS
        for aff in vuln.get("affected", []):
            sev = aff.get("database_specific", {}).get("severity", "")
            if sev:
                break
    return sev.upper() if sev else "UNKNOWN"


def _fixed_in(vuln: dict, package_name: str) -> Optional[str]:
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    return ev["fixed"]
    return None


def fetch_vulnerabilities(
    package: str,
    version: str,
    timeout: int = 10,
) -> List[Vulnerability]:
    """
    Query OSV.dev for known vulnerabilities for *package*==*version*.
    Returns empty list on network error (offline-safe).
    """
    payload = json.dumps({
        "version": version,
        "package": {"name": package, "ecosystem": "PyPI"},
    }).encode()

    req = urllib.request.Request(
        OSV_URL,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "depaudit/0.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except Exception:
        return []

    results: List[Vulnerability] = []
    for vuln in data.get("vulns", []):
        vid = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary", vuln.get("details", "")[:120])
        sev = _severity_from_osv(vuln)
        fixed = _fixed_in(vuln, package)
        ref = next(
            (r["url"] for r in vuln.get("references", []) if "url" in r),
            f"https://osv.dev/vulnerability/{vid}",
        )
        results.append(Vulnerability(
            vuln_id=vid,
            summary=summary,
            severity=sev,
            fixed_in=fixed,
            reference=ref,
        ))
    return results
