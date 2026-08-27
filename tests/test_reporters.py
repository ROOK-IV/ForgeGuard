import json

from forgeguard.models import Finding, Status
from forgeguard.reporters import render_json, render_text


def test_render_text_includes_findings_and_summary() -> None:
    findings = [
        Finding(
            check_id="container.privileged",
            status=Status.FAIL,
            title="Privileged container",
            message="Container runs with privileged mode enabled.",
            container="example-web",
            remediation="Disable privileged mode.",
        ),
        Finding(
            check_id="network.host-mode",
            status=Status.PASS,
            title="Host network mode",
            message="Container uses a bridge network.",
            container="example-web",
        ),
    ]

    output = render_text(findings)

    assert "[FAIL] [example-web] Privileged container" in output
    assert "Remediation: Disable privileged mode." in output
    assert "[PASS] [example-web] Host network mode" in output
    assert "Result: 1 passed, 0 warned, 1 failed" in output

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