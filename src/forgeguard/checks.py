from ipaddress import ip_address

from forgeguard.models import ContainerSnapshot, Finding, Status


DOCKER_SOCKET_PATHS = {
    "/var/run/docker.sock",
    "/run/docker.sock",
}


def check_privileged(container: ContainerSnapshot) -> Finding:
    if container.privileged:
        return Finding(
            check_id="container.privileged",
            status=Status.FAIL,
            title="Privileged container",
            message="Container runs with privileged mode enabled.",
            container=container.name,
            remediation="Remove privileged: true and grant only required access.",
            evidence={"privileged": True},
        )

    return Finding(
        check_id="container.privileged",
        status=Status.PASS,
        title="Privileged container",
        message="Container does not run in privileged mode.",
        container=container.name,
        evidence={"privileged": False},
    )


def check_port_bindings(container: ContainerSnapshot) -> Finding:
    unsafe_bindings = []

    for binding in container.port_bindings:
        try:
            is_loopback = ip_address(binding.host_ip).is_loopback
        except ValueError:
            is_loopback = False

        if not is_loopback:
            unsafe_bindings.append(
                {
                    "container_port": binding.container_port,
                    "host_ip": binding.host_ip,
                    "host_port": binding.host_port,
                }
            )

    if unsafe_bindings:
        return Finding(
            check_id="network.loopback-bindings",
            status=Status.FAIL,
            title="Published-port bindings",
            message="One or more ports are published beyond the loopback interface.",
            container=container.name,
            remediation="Bind published ports explicitly to 127.0.0.1 or ::1.",
            evidence={"unsafe_bindings": unsafe_bindings},
        )

    if not container.port_bindings:
        message = "Container does not publish host ports."
    else:
        message = "All published ports use loopback addresses."

    return Finding(
        check_id="network.loopback-bindings",
        status=Status.PASS,
        title="Published-port bindings",
        message=message,
        container=container.name,
        evidence={"binding_count": len(container.port_bindings)},
    )


def check_host_network(container: ContainerSnapshot) -> Finding:
    if container.network_mode == "host":
        return Finding(
            check_id="network.host-mode",
            status=Status.FAIL,
            title="Host network mode",
            message="Container shares the host network namespace.",
            container=container.name,
            remediation="Use a dedicated bridge network instead of host mode.",
            evidence={"network_mode": container.network_mode},
        )

    return Finding(
        check_id="network.host-mode",
        status=Status.PASS,
        title="Host network mode",
        message="Container does not use host network mode.",
        container=container.name,
        evidence={"network_mode": container.network_mode},
    )


def check_docker_socket(container: ContainerSnapshot) -> Finding:
    socket_mounts = [
        {
            "source": mount.source,
            "destination": mount.destination,
            "read_only": mount.read_only,
        }
        for mount in container.mounts
        if (
            mount.source in DOCKER_SOCKET_PATHS
            or mount.destination in DOCKER_SOCKET_PATHS
        )
    ]

    if socket_mounts:
        return Finding(
            check_id="mounts.docker-socket",
            status=Status.FAIL,
            title="Docker socket mount",
            message="Container has access to the Docker control socket.",
            container=container.name,
            remediation="Remove the Docker socket mount.",
            evidence={"socket_mounts": socket_mounts},
        )

    return Finding(
        check_id="mounts.docker-socket",
        status=Status.PASS,
        title="Docker socket mount",
        message="Container does not mount the Docker control socket.",
        container=container.name,
        evidence={"socket_mounts": []},
    )


def check_added_capabilities(container: ContainerSnapshot) -> Finding:
    if container.added_capabilities:
        return Finding(
            check_id="container.capabilities",
            status=Status.WARN,
            title="Added Linux capabilities",
            message="Container has additional Linux capabilities.",
            container=container.name,
            remediation="Remove capabilities that are not strictly required.",
            evidence={
                "added_capabilities": list(container.added_capabilities),
            },
        )

    return Finding(
        check_id="container.capabilities",
        status=Status.PASS,
        title="Added Linux capabilities",
        message="Container does not add Linux capabilities.",
        container=container.name,
        evidence={"added_capabilities": []},
    )


def check_no_new_privileges(container: ContainerSnapshot) -> Finding:
    enabled = any(
        option.startswith("no-new-privileges")
        for option in container.security_options
    )

    if not enabled:
        return Finding(
            check_id="container.no-new-privileges",
            status=Status.WARN,
            title="No-new-privileges",
            message="Container does not enable no-new-privileges.",
            container=container.name,
            remediation=(
                "Set security_opt to no-new-privileges:true "
                "when the workload supports it."
            ),
            evidence={
                "security_options": list(container.security_options),
            },
        )

    return Finding(
        check_id="container.no-new-privileges",
        status=Status.PASS,
        title="No-new-privileges",
        message="Container enables no-new-privileges.",
        container=container.name,
        evidence={
            "security_options": list(container.security_options),
        },
    )


def audit_container(container: ContainerSnapshot) -> list[Finding]:
    return [
        check_privileged(container),
        check_port_bindings(container),
        check_host_network(container),
        check_docker_socket(container),
        check_added_capabilities(container),
        check_no_new_privileges(container),
    ]


def audit_containers(
    containers: list[ContainerSnapshot],
) -> list[Finding]:
    findings: list[Finding] = []

    for container in containers:
        findings.extend(audit_container(container))

    return findings