import json
from pathlib import Path
from typing import Any

from models import Finding


def load_gitleaks_report(
    path: str
) -> list[dict[str, Any]]:

    report_path = Path(path)

    if not report_path.exists():
        raise FileNotFoundError(
            f"Gitleaks report not found: {path}"
        )

    return json.loads(
        report_path.read_text(
            encoding="utf-8"
        )
    )


def convert_gitleaks_finding(
    result: dict[str, Any]
) -> Finding:

    rule_id = result.get(
        "RuleID",
        "UNKNOWN"
    )

    description = result.get(
        "Description",
        "Potential secret detected"
    )

    file = result.get(
        "File",
        "unknown"
    )

    tags = result.get(
        "Tags",
        []
    )

    if isinstance(tags, list):
        guideline = ", ".join(tags)
    else:
        guideline = None

    return Finding(
        scanner="gitleaks",

        finding_id=rule_id,

        title=description,

        resource=file,

        file=file,

        line_start=result.get(
            "StartLine"
        ),

        line_end=result.get(
            "EndLine"
        ),

        severity=None,

        description=(
            "Potential credential or secret "
            "detected in source code. "
            "The secret value has intentionally "
            "been removed before AI processing."
        ),

        guideline=guideline,
    )


def load_findings(
    path: str
) -> list[Finding]:

    report = load_gitleaks_report(
        path
    )

    return [
        convert_gitleaks_finding(result)
        for result in report
    ]


if __name__ == "__main__":

    findings = load_findings(
        "findings/gitleaks.json"
    )

    print(
        f"Found {len(findings)} "
        f"Gitleaks findings\n"
    )

    for finding in findings:

        print(
            finding.model_dump_json(
                indent=2
            )
        )

        print()