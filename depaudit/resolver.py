"""Resolve installed Python packages and their metadata."""
from __future__ import annotations
import importlib.metadata as meta
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class PackageInfo:
    name: str
    version: str
    license: str            # SPDX identifier or raw classifier text
    summary: str
    home_page: str
    requires: List[str] = field(default_factory=list)


_LICENSE_FROM_CLASSIFIER = re.compile(
    r"License\s*::\s*OSI Approved\s*::\s*(.+)", re.IGNORECASE
)
_SPDX_MAP = {
    "MIT License": "MIT",
    "Apache Software License": "Apache-2.0",
    "Apache 2.0": "Apache-2.0",
    "BSD License": "BSD",
    "BSD 2-Clause": "BSD-2-Clause",
    "BSD 3-Clause": "BSD-3-Clause",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "ISC License (ISCL)": "ISC",
    "Python Software Foundation License": "PSF-2.0",
}


def _extract_license(dist: meta.Distribution) -> str:
    """Extract license from metadata classifiers or License field."""
    # Prefer classifier (more reliable)
    classifiers = (dist.metadata.get_all("Classifier") or [])
    for clf in classifiers:
        m = _LICENSE_FROM_CLASSIFIER.match(clf)
        if m:
            raw = m.group(1).strip()
            return _SPDX_MAP.get(raw, raw)

    # Fall back to License header
    lic = dist.metadata.get("License") or ""
    lic = lic.strip()
    if lic and lic.upper() not in ("UNKNOWN", ""):
        return _SPDX_MAP.get(lic, lic)

    return "UNKNOWN"


def resolve_installed(packages: Optional[List[str]] = None) -> List[PackageInfo]:
    """
    Return metadata for all installed packages (or a specific subset).

    If *packages* is None, returns every installed distribution.
    """
    if packages is not None:
        dists = []
        for name in packages:
            try:
                dists.append(meta.distribution(name))
            except meta.PackageNotFoundError:
                pass
    else:
        dists = list(meta.distributions())

    seen: Set[str] = set()
    result: List[PackageInfo] = []
    for dist in dists:
        name = dist.metadata.get("Name") or ""
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        result.append(PackageInfo(
            name=name,
            version=dist.metadata.get("Version") or "UNKNOWN",
            license=_extract_license(dist),
            summary=dist.metadata.get("Summary") or "",
            home_page=dist.metadata.get("Home-page") or dist.metadata.get("Project-URL") or "",
            requires=dist.metadata.get_all("Requires-Dist") or [],
        ))

    return sorted(result, key=lambda p: p.name.lower())
