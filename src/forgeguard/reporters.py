from forgeguard.models import Finding, Status, summarize


STATUS_LABELS = {
    Status.PASS: "PASS",
    Status.WARN: "WARN",
    Status.FAIL: "FAIL",
}


def render_text(findings: list[Finding]) -> str:
    lines = [
        "FORGEGUARD AUDIT",
        "================",
        "",
    ]

    for finding in findings:
        label = STATUS_LABELS[finding.status]
        container = f" [{finding.container}]" if finding.container else ""

        lines.append(f"[{label}]{container} {finding.title}")
        lines.append(f"  {finding.message}")

        if finding.remediation:
            lines.append(f"  Remediation: {finding.remediation}")

        lines.append("")

    summary = summarize(findings)

    lines.append(
        "Result: "
        f"{summary.passed} passed, "
        f"{summary.warned} warned, "
        f"{summary.failed} failed"
    )

    return "\n".join(lines)