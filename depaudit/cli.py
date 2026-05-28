"""CLI for depaudit."""
from __future__ import annotations
import json
import sys
import click
from .audit import run_audit
from .licenses import LicenseRisk

_RISK_COLOUR = {
    LicenseRisk.ALLOWED:     "green",
    LicenseRisk.RESTRICTED:  "yellow",
    LicenseRisk.FORBIDDEN:   "red",
    LicenseRisk.UNKNOWN:     "cyan",
}
_SEV_COLOUR = {
    "CRITICAL": "red",
    "HIGH":     "yellow",
    "MEDIUM":   "cyan",
    "LOW":      "white",
    "UNKNOWN":  "white",
}


@click.group()
def cli() -> None:
    """depaudit — audit Python dependency licenses and CVEs."""


@cli.command("scan")
@click.argument("packages", nargs=-1)
@click.option("--no-vulns", is_flag=True, help="Skip CVE checks (offline mode).")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@click.option("--ignore-license", multiple=True, metavar="LICENSE",
              help="Treat this license as allowed (repeatable).")
@click.option("--ignore-pkg", multiple=True, metavar="PACKAGE",
              help="Skip this package entirely (repeatable).")
@click.option("--fail-on-issues", is_flag=True,
              help="Exit 1 if any license or CVE issues found.")
@click.option("--fail-on-vulns", is_flag=True,
              help="Exit 1 if any CVEs found.")
@click.option("--timeout", default=10, show_default=True,
              help="HTTP timeout for OSV.dev queries.")
def scan(
    packages, no_vulns, as_json, ignore_license, ignore_pkg,
    fail_on_issues, fail_on_vulns, timeout,
):
    """
    Audit installed packages for license and CVE issues.

    Pass package names to limit the scan, or omit to scan everything installed.
    """
    pkg_list = list(packages) or None
    report = run_audit(
        packages=pkg_list,
        check_vulns=not no_vulns,
        ignore_licenses=set(ignore_license),
        ignore_packages=set(ignore_pkg),
        timeout=timeout,
    )

    if as_json:
        click.echo(json.dumps({
            "total_packages": len(report.audits),
            "license_issues": len(report.license_issues),
            "cve_issues": len(report.vuln_issues),
            "total_vulns": report.total_vulns,
            "packages": [
                {
                    "name": a.package.name,
                    "version": a.package.version,
                    "license": a.package.license,
                    "license_risk": a.license_finding.risk.value,
                    "vulnerabilities": [
                        {
                            "id": v.vuln_id,
                            "severity": v.severity,
                            "summary": v.summary,
                            "fixed_in": v.fixed_in,
                            "reference": v.reference,
                        }
                        for v in a.vulnerabilities
                    ],
                }
                for a in report.audits
            ],
        }, indent=2))
    else:
        click.echo(f"\ndepaudit — {len(report.audits)} packages scanned\n")

        if report.vuln_issues:
            click.echo(click.style(f"  CVE FINDINGS ({report.total_vulns} vulnerability/ies):", fg="red", bold=True))
            for a in report.vuln_issues:
                click.echo(f"  📦 {a.package.name}=={a.package.version}")
                for v in a.vulnerabilities:
                    sev_col = _SEV_COLOUR.get(v.severity, "white")
                    click.echo(f"     {click.style(v.vuln_id, fg=sev_col)}  [{v.severity}]  {v.summary[:80]}")
                    if v.fixed_in:
                        click.echo(f"       Fix: upgrade to >= {v.fixed_in}")
                    click.echo(f"       {v.reference}")
            click.echo()

        if report.license_issues:
            click.echo(click.style(f"  LICENSE FINDINGS ({len(report.license_issues)} package(s)):", fg="yellow", bold=True))
            for a in report.license_issues:
                col = _RISK_COLOUR[a.license_finding.risk]
                risk = click.style(f"[{a.license_finding.risk.value.upper()}]", fg=col)
                click.echo(f"  {risk} {a.package.name}=={a.package.version}  {a.license_finding.license}")
                click.echo(f"       {a.license_finding.message}")
            click.echo()

        if not report.license_issues and not report.vuln_issues:
            click.echo(click.style("  ✔ No issues found — all clear!", fg="green"))
        else:
            click.echo(f"  Summary: {len(report.license_issues)} license issue(s), {report.total_vulns} CVE(s)")
        click.echo()

    if fail_on_issues and (report.license_issues or report.vuln_issues):
        sys.exit(1)
    if fail_on_vulns and report.vuln_issues:
        sys.exit(1)


@cli.command("licenses")
@click.argument("packages", nargs=-1)
@click.option("--json", "as_json", is_flag=True)
def licenses(packages, as_json):
    """List licenses for installed packages."""
    pkg_list = list(packages) or None
    from .resolver import resolve_installed
    from .licenses import classify
    pkgs = resolve_installed(pkg_list)

    if as_json:
        click.echo(json.dumps([
            {"name": p.name, "version": p.version, "license": p.license,
             "risk": classify(p.license).value}
            for p in pkgs
        ], indent=2))
    else:
        click.echo(f"\n{'PACKAGE':<40} {'VERSION':<15} {'LICENSE':<30} RISK")
        click.echo("-" * 95)
        for p in pkgs:
            risk = classify(p.license)
            col = _RISK_COLOUR[risk]
            click.echo(
                f"{p.name:<40} {p.version:<15} {p.license:<30} "
                + click.style(risk.value, fg=col)
            )
        click.echo()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
