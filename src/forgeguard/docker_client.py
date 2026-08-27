from __future__ import annotations

import json
import subprocess
from typing import Any

from forgeguard.models import ContainerSnapshot, Mount, PortBinding


class DockerClientError(RuntimeError):
    """Raised when Docker inspection cannot be completed safely."""


def parse_container(raw: dict[str, Any]) -> ContainerSnapshot:
    config = raw.get("Config") or {}
    host_config = raw.get("HostConfig") or {}
    network_settings = raw.get("NetworkSettings") or {}
    restart_policy = host_config.get("RestartPolicy") or {}

    port_bindings: list[PortBinding] = []

    for container_port, bindings in (network_settings.get("Ports") or {}).items():
        if not bindings:
            continue

        for binding in bindings:
            port_bindings.append(
                PortBinding(
                    container_port=container_port,
                    host_ip=str(binding.get("HostIp") or ""),
                    host_port=str(binding.get("HostPort") or ""),
                )
            )

    mounts = tuple(
        Mount(
            mount_type=str(item.get("Type") or ""),
            source=str(item.get("Source") or ""),
            destination=str(item.get("Destination") or ""),
            read_only=not bool(item.get("RW", False)),
        )
        for item in (raw.get("Mounts") or [])
    )

    return ContainerSnapshot(
        container_id=str(raw.get("Id") or ""),
        name=str(raw.get("Name") or "").removeprefix("/"),
        image=str(config.get("Image") or ""),
        user=str(config.get("User") or ""),
        privileged=bool(host_config.get("Privileged", False)),
        network_mode=str(host_config.get("NetworkMode") or "default"),
        restart_policy=str(restart_policy.get("Name") or "no"),
        port_bindings=tuple(port_bindings),
        mounts=mounts,
        added_capabilities=tuple(host_config.get("CapAdd") or ()),
        security_options=tuple(host_config.get("SecurityOpt") or ()),
        read_only_rootfs=bool(host_config.get("ReadonlyRootfs", False))
    )


def inspect_running_containers() -> list[ContainerSnapshot]:
    try:
        listing = subprocess.run(
            ["docker", "container", "ls", "--quiet"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DockerClientError(
            "Docker CLI is not installed or is not available in PATH."
        ) from exc

    if listing.returncode != 0:
        message = listing.stderr.strip() or "Docker container listing failed."
        raise DockerClientError(message)

    container_ids = listing.stdout.split()

    if not container_ids:
        return []

    inspection = subprocess.run(
        ["docker", "inspect", *container_ids],
        capture_output=True,
        text=True,
        check=False,
    )

    if inspection.returncode != 0:
        message = inspection.stderr.strip() or "Docker inspection failed."
        raise DockerClientError(message)

    try:
        raw_containers = json.loads(inspection.stdout)
    except json.JSONDecodeError as exc:
        raise DockerClientError("Docker returned invalid inspection JSON.") from exc

    if not isinstance(raw_containers, list):
        raise DockerClientError("Docker inspection output was not a list.")

    return [parse_container(item) for item in raw_containers]