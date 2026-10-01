import json
from pathlib import Path
from typing import Any

from models import Finding


def load_semgrep_report(path: str) -> dict[str, Any]:
    report_path = Path(path)

    if not report_path.exists():
        raise FileNotFoundError(
            f"Semgrep report not found: {path}"
        )

    return json.loads(
        report_path.read_text(encoding="utf-8")
    )


def convert_semgrep_finding(
    result: dict[str, Any]
) -> Finding:

    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})

    start = result.get("start", {})
    end = result.get("end", {})

    cwe = metadata.get("cwe")

    if isinstance(cwe, list):
        guideline = ", ".join(cwe)
    else:
        guideline = cwe

    return Finding(
        scanner="semgrep",

        finding_id=result.get(
            "check_id",
            "UNKNOWN"
        ),

        title=result.get(
            "check_id",
            "Unknown Semgrep finding"
        ),

        resource=result.get(
            "path",
            "unknown"
        ),

        file=result.get(
            "path",
            "unknown"
        ),

        line_start=start.get("line"),

        line_end=end.get("line"),

        severity=extra.get("severity"),

        description=extra.get("message"),

        guideline=guideline,
    )


def load_findings(path: str) -> list[Finding]:

    report = load_semgrep_report(path)

    results = report.get(
        "results",
        []
    )

    return [
        convert_semgrep_finding(result)
        for result in results
    ]


if __name__ == "__main__":

    findings = load_findings(
        "findings/semgrep.json"
    )

    print(
        f"Found {len(findings)} "
        f"Semgrep findings\n"
    )

    for finding in findings:

        print(
            finding.model_dump_json(
                indent=2
            )
        )

        print()