from forgeguard.checks import (
    check_host_network,
    check_port_bindings,
    check_privileged,
)
from forgeguard.models import ContainerSnapshot, PortBinding, Status


def make_container(*, privileged: bool) -> ContainerSnapshot:
    return ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:1.0",
        privileged=privileged,
    )


def test_privileged_container_fails() -> None:
    finding = check_privileged(make_container(privileged=True))

    assert finding.status is Status.FAIL
    assert finding.container == "example-web"
    assert finding.evidence == {"privileged": True}
    assert finding.remediation is not None


def test_unprivileged_container_passes() -> None:
    finding = check_privileged(make_container(privileged=False))

    assert finding.status is Status.PASS
    assert finding.container == "example-web"
    assert finding.evidence == {"privileged": False}


def test_all_interface_binding_fails() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:1.0",
        port_bindings=(
            PortBinding(
                container_port="8080/tcp",
                host_ip="0.0.0.0",
                host_port="8080",
            ),
        ),
    )

    finding = check_port_bindings(container)

    assert finding.status is Status.FAIL
    assert finding.evidence["unsafe_bindings"][0]["host_ip"] == "0.0.0.0"


def test_loopback_bindings_pass() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:1.0",
        port_bindings=(
            PortBinding(
                container_port="8080/tcp",
                host_ip="127.0.0.1",
                host_port="8080",
            ),
            PortBinding(
                container_port="9090/tcp",
                host_ip="::1",
                host_port="9090",
            ),
        ),
    )

    finding = check_port_bindings(container)

    assert finding.status is Status.PASS
    assert finding.evidence == {"binding_count": 2}


def test_host_network_mode_fails() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:1.0",
        network_mode="host",
    )

    finding = check_host_network(container)

    assert finding.status is Status.FAIL


def test_bridge_network_mode_passes() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:1.0",
        network_mode="forgeguard-lab",
    )

    finding = check_host_network(container)

    assert finding.status is Status.PASS