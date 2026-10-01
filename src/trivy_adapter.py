import json
from pathlib import Path
from typing import Any

from models import Finding


def load_trivy_report(path: str) -> dict[str, Any]:
    report_path = Path(path)

    if not report_path.exists():
        raise FileNotFoundError(
            f"Trivy report not found: {path}"
        )

    return json.loads(
        report_path.read_text(encoding="utf-8")
    )


def convert_trivy_vulnerability(
    target: str,
    vulnerability: dict[str, Any]
) -> Finding:

    vulnerability_id = vulnerability.get(
        "VulnerabilityID",
        "UNKNOWN"
    )

    package_name = vulnerability.get(
        "PkgName",
        "unknown"
    )

    installed_version = vulnerability.get(
        "InstalledVersion"
    )

    fixed_version = vulnerability.get(
        "FixedVersion"
    )

    title = vulnerability.get("Title")

    if not title:
        title = f"{vulnerability_id} in {package_name}"

    return Finding(
        scanner="trivy",

        finding_id=vulnerability_id,

        title=title,

        resource=package_name,

        file=target,

        severity=vulnerability.get(
            "Severity"
        ),

        description=vulnerability.get(
            "Description"
        ),

        component=package_name,

        installed_version=installed_version,

        fixed_version=fixed_version,

        reference=vulnerability.get(
            "PrimaryURL"
        ),
    )


def load_findings(path: str) -> list[Finding]:

    report = load_trivy_report(path)

    findings: list[Finding] = []

    results = report.get(
        "Results",
        []
    )

    for result in results:

        target = result.get(
            "Target",
            "unknown"
        )

        vulnerabilities = result.get(
            "Vulnerabilities"
        ) or []

        for vulnerability in vulnerabilities:

            findings.append(
                convert_trivy_vulnerability(
                    target,
                    vulnerability
                )
            )

    return findings


if __name__ == "__main__":

    findings = load_findings(
        "findings/trivy.json"
    )

    print(
        f"Found {len(findings)} Trivy findings\n"
    )

    for finding in findings:

        print(
            finding.model_dump_json(
                indent=2
            )
        )

        print()