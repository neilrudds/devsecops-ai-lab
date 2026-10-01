import json
from pathlib import Path
from typing import Any

from models import Finding

def load_checkov_report(path: str) -> dict[str, Any]:
    report_path = Path(path)

    if not report_path.exists():
        raise FileNotFoundError(f"Checkov report not found: {path}")

    return json.loads(report_path.read_text(encoding="utf-8"))


def extract_failed_checks(report: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Checkov normally returns one report object for our Terraform scan.

    This also tolerates a list because Checkov can generate multiple
    framework reports when scanning more than one framework.
    """

    if isinstance(report, list):
        failed_checks = []

        for scanner_report in report:
            failed_checks.extend(
                scanner_report.get("results", {}).get("failed_checks", [])
            )

        return failed_checks

    return report.get("results", {}).get("failed_checks", [])


def convert_checkov_finding(check: dict[str, Any]) -> Finding:
    line_range = check.get("file_line_range") or []

    line_start = line_range[0] if len(line_range) >= 1 else None
    line_end = line_range[1] if len(line_range) >= 2 else None

    return Finding(
        scanner="checkov",
        finding_id=check.get("check_id", "UNKNOWN"),
        title=check.get("check_name", "Unknown Checkov finding"),
        resource=check.get("resource", "unknown"),
        file=check.get("file_path", "unknown"),
        line_start=line_start,
        line_end=line_end,
        severity=check.get("severity"),
        description=check.get("description"),
        guideline=check.get("guideline"),
    )


def load_findings(path: str) -> list[Finding]:
    report = load_checkov_report(path)
    failed_checks = extract_failed_checks(report)

    return [
        convert_checkov_finding(check)
        for check in failed_checks
    ]


if __name__ == "__main__":
    findings = load_findings("findings/checkov.json")

    print(f"Found {len(findings)} failed Checkov checks\n")

    for finding in findings:
        print(finding.model_dump_json(indent=2))
        print()