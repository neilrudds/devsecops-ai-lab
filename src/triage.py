import json
from enum import Enum

from openai import OpenAI
from pydantic import BaseModel

from checkov_adapter import Finding, load_findings


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
    findings = load_findings("findings/checkov.json")

    print(f"Loaded {len(findings)} Checkov findings.\n")

    if not findings:
        print("No failed Checkov findings found.")
        return

    findings_to_analyse = findings[:3]

    for index, finding in enumerate(findings_to_analyse, start=1):

        print("=" * 80)
        print(
            f"Finding {index}/{len(findings)}: "
            f"{index}/{len(findings_to_analyse)}"
        )
        print("=" * 80)

        assessment = analyse_finding(finding)

        print(assessment.model_dump_json(indent=2))
        print()


if __name__ == "__main__":
    main()