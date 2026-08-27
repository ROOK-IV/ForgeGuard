from forgeguard.models import Finding, Status
from forgeguard.reporters import render_text


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