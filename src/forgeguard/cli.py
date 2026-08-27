from __future__ import annotations

import argparse

from forgeguard.checks import audit_containers
from forgeguard.docker_client import DockerClientError, inspect_running_containers
from forgeguard.models import Finding, Status, summarize
from forgeguard.reporters import render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forgeguard",
        description="Audit the security posture of running Docker containers.",
    )

    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Select the report format. Default: text.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        containers = inspect_running_containers()
    except DockerClientError as exc:
        parser.exit(status=2, message=f"forgeguard: error: {exc}\n")

    if containers:
        findings = audit_containers(containers)
    else:
        findings = [
            Finding(
                check_id="docker.running-containers",
                status=Status.WARN,
                title="Running containers",
                message="No running Docker containers were found.",
            )
        ]

    if args.format == "json":
        print(render_json(findings))
    else:
        print(render_text(findings))

    summary = summarize(findings)
    return 1 if summary.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())