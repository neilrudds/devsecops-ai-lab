from models import Finding

import checkov_adapter
import semgrep_adapter
import trivy_adapter
import gitleaks_adapter


def load_all_findings() -> list[Finding]:

    findings: list[Finding] = []

    findings.extend(
        checkov_adapter.load_findings(
            "findings/checkov.json"
        )
    )

    findings.extend(
        semgrep_adapter.load_findings(
            "findings/semgrep.json"
        )
    )

    findings.extend(
        trivy_adapter.load_findings(
            "findings/trivy.json"
        )
    )

    findings.extend(
        gitleaks_adapter.load_findings(
            "findings/gitleaks.json"
        )
    )
    return findings