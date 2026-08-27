from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class Finding:
    check_id: str
    status: Status
    title: str
    message: str
    container: str | None = None
    remediation: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class PortBinding:
    container_port: str
    host_ip: str
    host_port: str


@dataclass(frozen=True, slots=True)
class Mount:
    mount_type: str
    source: str
    destination: str
    read_only: bool


@dataclass(frozen=True, slots=True)
class ContainerSnapshot:
    container_id: str
    name: str
    image: str
    privileged: bool = False
    network_mode: str = "default"
    restart_policy: str = "no"
    port_bindings: tuple[PortBinding, ...] = ()
    mounts: tuple[Mount, ...] = ()
    added_capabilities: tuple[str, ...] = ()
    security_options: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AuditSummary:
    passed: int
    warned: int
    failed: int

    @property
    def total(self) -> int:
        return self.passed + self.warned + self.failed


def summarize(findings: list[Finding]) -> AuditSummary:
    return AuditSummary(
        passed=sum(item.status is Status.PASS for item in findings),
        warned=sum(item.status is Status.WARN for item in findings),
        failed=sum(item.status is Status.FAIL for item in findings),
    )