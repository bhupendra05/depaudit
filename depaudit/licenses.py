"""License policy engine — classify licenses as allowed, restricted, or forbidden."""
from __future__ import annotations
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class LicenseRisk(str, Enum):
    ALLOWED = "allowed"
    RESTRICTED = "restricted"   # copyleft — may require source disclosure
    FORBIDDEN = "forbidden"     # incompatible / proprietary
    UNKNOWN = "unknown"


# SPDX tokens → risk
_LICENSE_RISK: dict[str, LicenseRisk] = {
    # Permissive — safe for most projects
    "MIT": LicenseRisk.ALLOWED,
    "Apache-2.0": LicenseRisk.ALLOWED,
    "BSD": LicenseRisk.ALLOWED,
    "BSD-2-Clause": LicenseRisk.ALLOWED,
    "BSD-3-Clause": LicenseRisk.ALLOWED,
    "ISC": LicenseRisk.ALLOWED,
    "PSF-2.0": LicenseRisk.ALLOWED,
    "Unlicense": LicenseRisk.ALLOWED,
    "CC0-1.0": LicenseRisk.ALLOWED,
    "Artistic-2.0": LicenseRisk.ALLOWED,
    "WTFPL": LicenseRisk.ALLOWED,
    "Zlib": LicenseRisk.ALLOWED,
    # Weak copyleft — must disclose modifications to the library
    "LGPL-2.0": LicenseRisk.RESTRICTED,
    "LGPL-2.1": LicenseRisk.RESTRICTED,
    "LGPL-3.0": LicenseRisk.RESTRICTED,
    "MPL-2.0": LicenseRisk.RESTRICTED,
    "EPL-1.0": LicenseRisk.RESTRICTED,
    "EPL-2.0": LicenseRisk.RESTRICTED,
    "CDDL-1.0": LicenseRisk.RESTRICTED,
    # Strong copyleft — whole project may need to be open-sourced
    "GPL-2.0": LicenseRisk.FORBIDDEN,
    "GPL-2.0-only": LicenseRisk.FORBIDDEN,
    "GPL-2.0-or-later": LicenseRisk.FORBIDDEN,
    "GPL-3.0": LicenseRisk.FORBIDDEN,
    "GPL-3.0-only": LicenseRisk.FORBIDDEN,
    "GPL-3.0-or-later": LicenseRisk.FORBIDDEN,
    "AGPL-3.0": LicenseRisk.FORBIDDEN,
    "SSPL-1.0": LicenseRisk.FORBIDDEN,
    "EUPL-1.2": LicenseRisk.FORBIDDEN,
}

_ALIAS = {
    "Apache 2.0": "Apache-2.0",
    "Apache-2": "Apache-2.0",
    "MIT License": "MIT",
    "BSD License": "BSD",
    "BSD-3-Clause License": "BSD-3-Clause",
    "PSF": "PSF-2.0",
    "Python Software Foundation": "PSF-2.0",
    "GPLv2": "GPL-2.0",
    "GPLv3": "GPL-3.0",
    "LGPLv2": "LGPL-2.0",
    "LGPLv3": "LGPL-3.0",
    "AGPLv3": "AGPL-3.0",
}


def classify(license_str: str) -> LicenseRisk:
    """Return the risk level for a license string."""
    if not license_str or license_str.upper() in ("UNKNOWN", ""):
        return LicenseRisk.UNKNOWN

    # Normalise via alias table
    normalised = _ALIAS.get(license_str, license_str)

    # Direct match
    if normalised in _LICENSE_RISK:
        return _LICENSE_RISK[normalised]

    # Try token-by-token (handles "MIT AND Apache-2.0" etc.)
    tokens = re.split(r"[\s,;/]+", normalised)
    risks = [_LICENSE_RISK[t] for t in tokens if t in _LICENSE_RISK]
    if risks:
        # Return the worst risk found
        for worst in (LicenseRisk.FORBIDDEN, LicenseRisk.RESTRICTED, LicenseRisk.ALLOWED):
            if worst in risks:
                return worst

    return LicenseRisk.UNKNOWN


@dataclass
class LicenseFinding:
    package: str
    version: str
    license: str
    risk: LicenseRisk
    message: str
