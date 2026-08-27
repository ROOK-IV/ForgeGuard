# ForgeGuard

A read-only Docker security posture auditor.

ForgeGuard inspects running Docker containers, normalizes their runtime metadata,
applies focused security checks, and produces clear pass, warning, and failure
results.

> [!NOTE]
> ForgeGuard audits configuration. It does not modify, stop, restart, or remove
> containers.

## Current checks

ForgeGuard v0.1 currently detects:

- Privileged containers
- Published ports bound beyond loopback
- Host-network mode

Additional checks will be added before the first public release.

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

Audit all running containers:

```text
forgeguard
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

Warnings do not currently produce a nonzero exit code.

## Example

```text
FORGEGUARD AUDIT
================

[PASS] [rangeforge-dvwa] Privileged container
  Container does not run in privileged mode.

[PASS] [rangeforge-dvwa] Published-port bindings
  All published ports use loopback addresses.

[PASS] [rangeforge-dvwa] Host network mode
  Container does not use host network mode.

Result: 3 passed, 0 warned, 0 failed
```

## Project structure

```text
ForgeGuard/
├── docs/
├── src/
│   └── forgeguard/
│       ├── checks.py
│       ├── cli.py
│       ├── docker_client.py
│       ├── models.py
│       └── reporters.py
├── tests/
├── LICENSE
├── README.md
└── pyproject.toml
```

## Scope

ForgeGuard is a configuration-auditing tool. It is not:

- A vulnerability scanner
- An exploit framework
- A container runtime protection system
- A replacement for host hardening or network controls

## License

Released under the [MIT License](LICENSE).

---

Built by **ROOK XI**.