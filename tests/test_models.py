from forgeguard.models import Finding, Status, summarize


def test_summarize_counts_each_status() -> None:
    findings = [
        Finding(
            check_id="ports.loopback",
            status=Status.PASS,
            title="Loopback binding",
            message="Published port uses 127.0.0.1.",
        ),
        Finding(
            check_id="image.pin",
            status=Status.WARN,
            title="Image pinning",
            message="Image uses a mutable tag.",
        ),
        Finding(
            check_id="container.privileged",
            status=Status.FAIL,
            title="Privileged container",
            message="Container runs in privileged mode.",
        ),
    ]

    summary = summarize(findings)

    assert summary.passed == 1
    assert summary.warned == 1
    assert summary.failed == 1
    assert summary.total == 3


def test_finding_accepts_container_and_evidence() -> None:
    finding = Finding(
        check_id="ports.loopback",
        status=Status.FAIL,
        title="Unsafe published port",
        message="Port is published on all interfaces.",
        container="example-web",
        remediation="Bind the port to 127.0.0.1.",
        evidence={"host_ip": "0.0.0.0", "host_port": "8080"},
    )

    assert finding.container == "example-web"
    assert finding.evidence["host_ip"] == "0.0.0.0"