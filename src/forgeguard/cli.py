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

    parser.add_argument(
        "--fail-on",
        choices=("fail", "warn"),
        default="fail",
        help="set the lowest severity level that produces exit code 1. Default: fail.",
    )

    parser.add_argument(
        "--container",
        metavar="NAME",
        help="Audit only the running container with this exact name.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        containers = inspect_running_containers()
    except DockerClientError as exc:
        parser.exit(status=2, message=f"forgeguard: error: {exc}\n")

    if args.container:
        containers = [
            container
            for container in containers
            if container.name == args.container
        ]

        if containers:
            findings = audit_containers(containers)
        else:
            findings = [
                Finding(
                    check_id="docker.container-filter",
                    status=Status.WARN,
                    title="Container filter",
                    message=(
                        f'No running container named "{args.container}" was found.'
                    ),
                    container=args.container,
                )
            ]
    elif containers:
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

    if summary.failed:
        return 1

    if args.fail_on == "warn" and summary.warned:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())