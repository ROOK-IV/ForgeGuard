from forgeguard.checks import (
    check_added_capabilities,
    check_docker_socket,
    check_host_network,
    check_image_pinning,
    check_no_new_privileges,
    check_port_bindings,
    check_privileged,
    check_sensitive_host_mounts,
)


from forgeguard.models import ContainerSnapshot, Mount, PortBinding, Status


def make_container(*, privileged: bool, image: str = "example/web:1.0") -> ContainerSnapshot:
    return ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image=image,
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

    assert check_host_network(container).status is Status.FAIL


def test_bridge_network_mode_passes() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:1.0",
        network_mode="forgeguard-lab",
    )

    assert check_host_network(container).status is Status.PASS


def test_docker_socket_mount_fails() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="socket-reader",
        image="example/socket-reader:1.0",
        mounts=(
            Mount(
                mount_type="bind",
                source="/var/run/docker.sock",
                destination="/var/run/docker.sock",
                read_only=True,
            ),
        ),
    )

    assert check_docker_socket(container).status is Status.FAIL


def test_container_without_docker_socket_passes() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:1.0",
    )

    assert check_docker_socket(container).status is Status.PASS


def test_added_capabilities_warn() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:1.0",
        added_capabilities=("NET_ADMIN",),
    )

    finding = check_added_capabilities(container)

    assert finding.status is Status.WARN
    assert finding.evidence["added_capabilities"] == ["NET_ADMIN"]


def test_no_added_capabilities_passes() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:1.0",
    )

    assert check_added_capabilities(container).status is Status.PASS


def test_missing_no_new_privileges_warns() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:1.0",
    )

    assert check_no_new_privileges(container).status is Status.WARN


def test_no_new_privileges_enabled_passes() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:1.0",
        security_options=("no-new-privileges:true",),
    )

    assert check_no_new_privileges(container).status is Status.PASS


def test_digest_pinned_image_passes() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web@sha256:" + ("a" * 64),
    )

    finding = check_image_pinning(container)

    assert finding.status is Status.PASS
    assert finding.evidence["image"] == container.image


def test_mutable_image_tag_warns() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:latest",
    )

    finding = check_image_pinning(container)

    assert finding.status is Status.WARN
    assert finding.remediation is not None
    assert finding.evidence["image"] == "example/web:latest"


def test_sensitive_host_bind_mount_fails() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:latest",
        mounts=(
            Mount(
                mount_type="bind",
                source="/etc/example",
                destination="/host-config",
                read_only=True,
            ),
        ),
    )

    finding = check_sensitive_host_mounts(container)

    assert finding.status is Status.FAIL
    assert finding.evidence["sources"] == ["/etc/example"]


def test_ordinary_host_bind_mount_passes() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:latest",
        mounts=(
            Mount(
                mount_type="bind",
                source="/srv/example-data",
                destination="/app/data",
                read_only=False,
            ),
        ),
    )

    finding = check_sensitive_host_mounts(container)

    assert finding.status is Status.PASS


def test_docker_socket_is_not_reported_twice() -> None:
    container = ContainerSnapshot(
        container_id="abc123",
        name="example-web",
        image="example/web:latest",
        mounts=(
            Mount(
                mount_type="bind",
                source="/var/run/docker.sock",
                destination="/var/run/docker.sock",
                read_only=False,
            ),
        ),
    )

    finding = check_sensitive_host_mounts(container)

    assert finding.status is Status.PASS