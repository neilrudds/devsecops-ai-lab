import json
from enum import Enum
from pathlib import Path

from openai import OpenAI
from pydantic import BaseModel


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


def load_finding(path: str) -> dict:
    return json.loads(Path(path).read_text())


def analyse_finding(finding: dict) -> SecurityAssessment:
    client = OpenAI()

    response = client.responses.parse(
        model="gpt-5.6",
        input=[
            {
                "role": "system",
                "content": (
                    "You are a cloud security engineer reviewing automated "
                    "DevSecOps scanner findings. Analyse the finding, explain "
                    "the actual security risk, and recommend remediation. "
                    "Do not assume the scanner severity is correct."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(finding),
            },
        ],
        text_format=SecurityAssessment,
    )

    return response.output_parsed


if __name__ == "__main__":
    finding = load_finding("findings/sample_finding.json")
    assessment = analyse_finding(finding)

    print(assessment.model_dump_json(indent=2))