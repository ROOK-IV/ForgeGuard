# Changelog

All notable changes to ForgeGuard are documented in this file.

## [0.1.0] - 2026-08-26

### Added

- Read-only inspection of running Docker containers
- Terminal and JSON report formats
- Filtering by exact container name
- Configurable warning exit policy for CI
- Checks for privileged mode and host networking
- Checks for unsafe published-port bindings
- Checks for Docker socket and sensitive host mounts
- Checks for added Linux capabilities
- Check for missing `no-new-privileges`
- Check for mutable image references
- Checks for root users and writable root filesystems
- Automated tests across Python 3.11 through 3.14