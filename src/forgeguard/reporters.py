import json
from dataclasses import asdict

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


def render_json(findings: list[Finding]) -> str:
    summary = summarize(findings)

    report = {
        "summary": asdict(summary),
        "findings": [asdict(finding) for finding in findings],
    }

    return json.dumps(report, indent=2)


def test_render_json_returns_structured_report() -> None:
    findings = [
        Finding(
            check_id="security.no-new-privileges",
            status=Status.WARN,
            title="No-new-privileges",
            message="The protection is not enabled.",
            container="example-web",
            remediation="Enable no-new-privileges.",
        )
    ]

    output = render_json(findings)
    report = json.loads(output)

    assert report["summary"]["passed"] == 0
    assert report["summary"]["warned"] == 1
    assert report["summary"]["failed"] == 0

    assert len(report["findings"]) == 1
    assert report["findings"][0]["check_id"] == "security.no-new-privileges"
    assert report["findings"][0]["status"] == "warn"
    assert report["findings"][0]["container"] == "example-web"