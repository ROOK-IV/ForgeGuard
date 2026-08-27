from forgeguard.models import ContainerSnapshot, Finding, Status


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

from ipaddress import ip_address


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


def audit_container(container: ContainerSnapshot) -> list[Finding]:
    return [
        check_privileged(container),
        check_port_bindings(container),
        check_host_network(container),
    ]


def audit_containers(
    containers: list[ContainerSnapshot],
) -> list[Finding]:
    findings: list[Finding] = []

    for container in containers:
        findings.extend(audit_container(container))

    return findings