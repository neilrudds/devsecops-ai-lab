import json
from enum import Enum

from openai import OpenAI
from pydantic import BaseModel

from models import Finding
from findings import load_all_findings


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityAssessment(BaseModel):
    risk: RiskLevel
    summary: str
    exploit_scenario: str
    business_impact: str
    remediation: str
    requires_human_review: bool


def analyse_finding(finding: Finding) -> SecurityAssessment:
    client = OpenAI()

    response = client.responses.parse(
        model="gpt-5.6",
        input=[
            {
                "role": "system",
                "content": (
                    "You are a senior cloud security engineer reviewing "
                    "automated Infrastructure-as-Code security findings. "
                    "Assess the actual risk of the finding rather than blindly "
                    "accepting the scanner result. Explain a plausible exploit "
                    "scenario, business impact, and specific remediation. "
                    "Be concise and technically precise."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    finding.model_dump(),
                    indent=2
                ),
            },
        ],
        text_format=SecurityAssessment,
    )

    return response.output_parsed


def main() -> None:
    findings = load_all_findings()

    for finding in findings:
        print(finding.scanner, finding.finding_id, finding.resource)

    print(
        f"Loaded {len(findings)} security findings.\n"
    )

    if not findings:
        print("No failed security findings found.")
        return

    checkov_findings = [
    finding
    for finding in findings
    if finding.scanner == "checkov"
]

    semgrep_findings = [
        finding
        for finding in findings
        if finding.scanner == "semgrep"
    ]

    trivy_findings = [
        finding
        for finding in findings
        if finding.scanner == "trivy"
    ]

    gitleaks_findings = [
        finding
        for finding in findings
        if finding.scanner == "gitleaks"
    ]

    findings_to_analyse = (
        checkov_findings[:1]
        + semgrep_findings[:1]
        + trivy_findings[:1]
        + gitleaks_findings[:1]
    )

    for index, finding in enumerate(findings_to_analyse, start=1):

        print("=" * 80)
        print(
            f"Finding {index}/{len(findings_to_analyse)}"
        )
        print("=" * 80)

        assessment = analyse_finding(finding)

        print(assessment.model_dump_json(indent=2))
        print()


if __name__ == "__main__":
    main()