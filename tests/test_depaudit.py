"""Tests for depaudit — license classifier + audit runner."""
import pytest
from depaudit.licenses import classify, LicenseRisk, LicenseFinding
from depaudit.resolver import PackageInfo, _extract_license
from depaudit.vulnerabilities import Vulnerability
from depaudit.audit import run_audit, AuditReport, PackageAudit, _license_message


# ---------------------------------------------------------------------------
# classify()
# ---------------------------------------------------------------------------

class TestClassify:
    def test_mit_is_allowed(self):
        assert classify("MIT") == LicenseRisk.ALLOWED

    def test_apache_is_allowed(self):
        assert classify("Apache-2.0") == LicenseRisk.ALLOWED

    def test_bsd_is_allowed(self):
        assert classify("BSD") == LicenseRisk.ALLOWED

    def test_bsd3_is_allowed(self):
        assert classify("BSD-3-Clause") == LicenseRisk.ALLOWED

    def test_isc_is_allowed(self):
        assert classify("ISC") == LicenseRisk.ALLOWED

    def test_psf_is_allowed(self):
        assert classify("PSF-2.0") == LicenseRisk.ALLOWED

    def test_lgpl_is_restricted(self):
        assert classify("LGPL-3.0") == LicenseRisk.RESTRICTED

    def test_mpl_is_restricted(self):
        assert classify("MPL-2.0") == LicenseRisk.RESTRICTED

    def test_gpl2_is_forbidden(self):
        assert classify("GPL-2.0") == LicenseRisk.FORBIDDEN

    def test_gpl3_is_forbidden(self):
        assert classify("GPL-3.0") == LicenseRisk.FORBIDDEN

    def test_agpl_is_forbidden(self):
        assert classify("AGPL-3.0") == LicenseRisk.FORBIDDEN

    def test_unknown_string_returns_unknown(self):
        assert classify("UNKNOWN") == LicenseRisk.UNKNOWN

    def test_empty_string_returns_unknown(self):
        assert classify("") == LicenseRisk.UNKNOWN

    def test_alias_apache2(self):
        assert classify("Apache 2.0") == LicenseRisk.ALLOWED

    def test_alias_mit_license(self):
        assert classify("MIT License") == LicenseRisk.ALLOWED

    def test_alias_gpLv3(self):
        assert classify("GPLv3") == LicenseRisk.FORBIDDEN

    def test_alias_lgplv2(self):
        assert classify("LGPLv2") == LicenseRisk.RESTRICTED

    def test_combined_spdx_worst_wins(self):
        # "MIT AND GPL-3.0" should be FORBIDDEN (worst)
        assert classify("MIT AND GPL-3.0") == LicenseRisk.FORBIDDEN

    def test_unlicense_is_allowed(self):
        assert classify("Unlicense") == LicenseRisk.ALLOWED

    def test_custom_unknown_license(self):
        assert classify("Proprietary-Corp-License-1.0") == LicenseRisk.UNKNOWN


# ---------------------------------------------------------------------------
# LicenseRisk enum
# ---------------------------------------------------------------------------

class TestLicenseRisk:
    def test_string_values(self):
        assert LicenseRisk.ALLOWED.value == "allowed"
        assert LicenseRisk.RESTRICTED.value == "restricted"
        assert LicenseRisk.FORBIDDEN.value == "forbidden"
        assert LicenseRisk.UNKNOWN.value == "unknown"


# ---------------------------------------------------------------------------
# _license_message
# ---------------------------------------------------------------------------

class TestLicenseMessage:
    def test_forbidden_message_mentions_open_sourcing(self):
        msg = _license_message(LicenseRisk.FORBIDDEN, "GPL-3.0")
        assert "GPL-3.0" in msg
        assert "open-sourc" in msg.lower()

    def test_restricted_message_mentions_copyleft(self):
        msg = _license_message(LicenseRisk.RESTRICTED, "LGPL-3.0")
        assert "copyleft" in msg.lower()

    def test_unknown_message_mentions_review(self):
        msg = _license_message(LicenseRisk.UNKNOWN, "WeirdLicense")
        assert "manually" in msg.lower()

    def test_allowed_message_positive(self):
        msg = _license_message(LicenseRisk.ALLOWED, "MIT")
        assert "Allowed" in msg or "MIT" in msg


# ---------------------------------------------------------------------------
# PackageInfo
# ---------------------------------------------------------------------------

class TestPackageInfo:
    def test_fields(self):
        p = PackageInfo(name="mylib", version="1.0.0", license="MIT",
                        summary="A lib", home_page="https://example.com")
        assert p.name == "mylib"
        assert p.version == "1.0.0"
        assert p.license == "MIT"


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------

class TestVulnerability:
    def test_fields(self):
        v = Vulnerability(vuln_id="CVE-2024-1234", summary="RCE bug", severity="CRITICAL",
                          fixed_in="2.0.0", reference="https://osv.dev")
        assert v.vuln_id == "CVE-2024-1234"
        assert v.severity == "CRITICAL"
        assert v.fixed_in == "2.0.0"


# ---------------------------------------------------------------------------
# AuditReport
# ---------------------------------------------------------------------------

def _make_audit(name, license_str, risk, vulns=None):
    pkg = PackageInfo(name=name, version="1.0.0", license=license_str, summary="", home_page="")
    lf = LicenseFinding(package=name, version="1.0.0", license=license_str, risk=risk,
                        message=_license_message(risk, license_str))
    return PackageAudit(package=pkg, license_finding=lf, vulnerabilities=vulns or [])


class TestAuditReport:
    def test_empty_report(self):
        report = AuditReport()
        assert report.license_issues == []
        assert report.vuln_issues == []
        assert report.total_vulns == 0

    def test_license_issues_filters_correctly(self):
        report = AuditReport(audits=[
            _make_audit("safe", "MIT", LicenseRisk.ALLOWED),
            _make_audit("risky", "GPL-3.0", LicenseRisk.FORBIDDEN),
        ])
        assert len(report.license_issues) == 1
        assert report.license_issues[0].package.name == "risky"

    def test_clean_packages(self):
        report = AuditReport(audits=[
            _make_audit("safe", "MIT", LicenseRisk.ALLOWED),
            _make_audit("risky", "GPL-3.0", LicenseRisk.FORBIDDEN),
        ])
        assert len(report.clean) == 1
        assert report.clean[0].package.name == "safe"

    def test_vuln_issues(self):
        vuln = Vulnerability("CVE-2024-1", "Bug", "HIGH")
        report = AuditReport(audits=[
            _make_audit("safe", "MIT", LicenseRisk.ALLOWED),
            _make_audit("vuln-pkg", "MIT", LicenseRisk.ALLOWED, [vuln]),
        ])
        assert len(report.vuln_issues) == 1

    def test_total_vulns(self):
        v1 = Vulnerability("CVE-1", "B1", "HIGH")
        v2 = Vulnerability("CVE-2", "B2", "MEDIUM")
        report = AuditReport(audits=[
            _make_audit("pkg", "MIT", LicenseRisk.ALLOWED, [v1, v2]),
        ])
        assert report.total_vulns == 2

    def test_has_issues_when_forbidden(self):
        a = _make_audit("pkg", "GPL-3.0", LicenseRisk.FORBIDDEN)
        assert a.has_issues

    def test_has_issues_when_vuln(self):
        v = Vulnerability("CVE-1", "B", "HIGH")
        a = _make_audit("pkg", "MIT", LicenseRisk.ALLOWED, [v])
        assert a.has_issues

    def test_no_issues_when_clean(self):
        a = _make_audit("pkg", "MIT", LicenseRisk.ALLOWED)
        assert not a.has_issues

    def test_restricted_is_issue(self):
        a = _make_audit("pkg", "LGPL-3.0", LicenseRisk.RESTRICTED)
        assert a.has_issues

    def test_unknown_is_issue(self):
        a = _make_audit("pkg", "WeirdLicense", LicenseRisk.UNKNOWN)
        assert a.has_issues


# ---------------------------------------------------------------------------
# run_audit (no-network, no-vulns mode)
# ---------------------------------------------------------------------------

class TestRunAudit:
    def test_runs_without_error(self):
        # limit to a single well-known package that's always installed
        report = run_audit(packages=["pip"], check_vulns=False)
        assert isinstance(report, AuditReport)

    def test_ignore_package_skips_it(self):
        report = run_audit(packages=["pip"], check_vulns=False, ignore_packages={"pip"})
        assert all(a.package.name.lower() != "pip" for a in report.audits)

    def test_ignore_license_makes_allowed(self):
        # Use the resolver to find the actual extracted license for pytest,
        # then pass that exact string to ignore_licenses so the test is reliable.
        from depaudit.resolver import resolve_installed
        pkgs = resolve_installed(["pytest"])
        if not pkgs:
            pytest.skip("pytest package not found in installed packages")
        actual_license = pkgs[0].license

        report = run_audit(packages=["pytest"], check_vulns=False, ignore_licenses={actual_license})
        if report.audits:
            assert report.audits[0].license_finding.risk == LicenseRisk.ALLOWED

    def test_returns_audit_for_each_package(self):
        report = run_audit(packages=["pip", "setuptools"], check_vulns=False)
        names = {a.package.name.lower() for a in report.audits}
        # At least one of these should be present in any Python env
        assert names & {"pip", "setuptools"}
