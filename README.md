# ForgeGuard
[![Validate](https://github.com/ROOK-XI/ForgeGuard/actions/workflows/validate.yml/badge.svg)](https://github.com/ROOK-XI/ForgeGuard/actions/workflows/validate.yml)

A read-only Docker security posture auditor.

ForgeGuard inspects running Docker containers, normalizes their runtime metadata,
applies focused security checks, and produces clear pass, warning, and failure
results.

> [!NOTE]
> ForgeGuard audits configuration. It does not modify, stop, restart, or remove
> containers.

## Security checks

ForgeGuard v0.1 audits each running container for:

| Check | Severity when detected |
| --- | --- |
| Privileged mode | Fail |
| Published ports bound beyond loopback | Fail |
| Host-network mode | Fail |
| Docker socket mounts | Fail |
| Sensitive host filesystem mounts | Fail |
| Added Linux capabilities | Warn |
| Missing `no-new-privileges` | Warn |
| Image not pinned to a SHA-256 digest | Warn |
| Root container user | Warn |
| Writable root filesystem | Warn |

A passing result means the inspected configuration did not trigger that specific
rule. It does not guarantee that the container image or application is free of
vulnerabilities.

## Requirements

- Python 3.11 or newer
- Docker Engine
- Docker CLI
- Permission to inspect Docker containers

Access to the Docker daemon is security-sensitive and often equivalent to
root-level host access. Run ForgeGuard only on systems you administer.

## Development setup

Clone the repository and create a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Run the tests:

```powershell
python -m pytest
```

## Usage

Audit all running containers and print a terminal report:

```text
forgeguard
```

Produce machine-readable JSON:

```text
forgeguard --format json
```

Audit one running container by exact name:

```text
forgeguard --container rangeforge-dvwa
```

Treat warnings as an unsuccessful audit for CI or automation:

```text
forgeguard --fail-on warn
```

Options can be combined:

```text
forgeguard --container rangeforge-dvwa --format json --fail-on warn
```

On Linux systems where Docker requires elevated access:

```bash
sudo forgeguard
```

ForgeGuard performs read-only Docker operations equivalent to:

```bash
docker container ls --quiet
docker inspect CONTAINER_ID
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Audit completed with no failures |
| `1` | One or more security checks failed |
| `2` | Docker inspection or command usage failed |

Warnings produce exit code `0` by default. When `--fail-on warn` is used,
warnings produce exit code `1`.

## Example

```text
FORGEGUARD AUDIT
================

[PASS] [rangeforge-dvwa] Privileged container
  Container does not run in privileged mode.

[FAIL] [rangeforge-dvwa] Docker socket mount
  The container mounts the Docker socket.

  Remediation: Remove the Docker socket mount unless it is strictly required.

[WARN] [rangeforge-dvwa] Container user
  The container is configured to run as root.

  Remediation: Configure the image or container to use a dedicated non-root user.

Result: 8 passed, 1 warned, 1 failed
```

This abbreviated example demonstrates all three statuses. Actual totals depend on
the number and configuration of the containers inspected.

## Project structure

```text
ForgeGuard/
|-- src/
|   `-- forgeguard/
|       |-- __init__.py
|       |-- checks.py
|       |-- cli.py
|       |-- docker_client.py
|       |-- models.py
|       `-- reporters.py
|-- tests/
|   |-- test_checks.py
|   |-- test_cli.py
|   |-- test_docker_client.py
|   |-- test_models.py
|   `-- test_reporters.py
|-- LICENSE
|-- README.md
`-- pyproject.toml
```

## Scope

ForgeGuard is a configuration-auditing tool. It is not:

- A vulnerability scanner
- An exploit framework
- A container runtime protection system
- A replacement for host hardening or network controls

## Security

See [SECURITY.md](SECURITY.md) for supported versions, reporting scope, and
private vulnerability-reporting instructions.

## License

Released under the [MIT License](LICENSE).

---

Built by **ROOK IV**.
