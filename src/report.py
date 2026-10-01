from collections import Counter

from findings import load_all_findings


def main() -> None:
    findings = load_all_findings()

    counts = Counter(
        finding.scanner
        for finding in findings
    )

    print()
    print("Security scan summary")
    print("=" * 40)

    for scanner, count in sorted(counts.items()):
        print(f"{scanner}: {count}")

    print("-" * 40)
    print(f"Total findings: {len(findings)}")
    print()

    for finding in findings:
        print(
            f"[{finding.scanner}] "
            f"{finding.finding_id} | "
            f"{finding.resource}"
        )


if __name__ == "__main__":
    main()