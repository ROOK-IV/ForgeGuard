# Security Policy

## Supported versions

ForgeGuard currently supports the latest published release.

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |
| Earlier versions | No |

## Reporting a vulnerability

Please do not open a public issue for an undisclosed security vulnerability.

Use GitHub's private vulnerability-reporting feature when available:

https://github.com/ROOK-IV/ForgeGuard/security/advisories/new

If private reporting is unavailable, contact:

`rookiv@proton.me`

Include, when possible:

- The affected ForgeGuard version
- A clear description of the issue
- Minimal reproduction steps
- The potential security impact
- Any suggested mitigation

Do not include passwords, tokens, private keys, personal data, or unrelated
system information.

## Scope

Examples of issues within scope include:

- Behavior that unexpectedly modifies Docker state
- Unsafe command construction or command execution
- Incorrect handling of untrusted Docker inspection data
- Security checks that materially misrepresent an unsafe configuration as safe
- Package, build, or release-integrity problems

The following are generally outside ForgeGuard's security scope:

- Vulnerabilities in Docker Engine or the Docker CLI
- Vulnerabilities inside audited container images or applications
- Expected warnings or failures produced by documented checks
- Issues that require testing systems without authorization

## Safe research

Test only against systems and containers you own or are explicitly authorized
to assess. Avoid disrupting services, accessing unrelated data, or exposing
sensitive information.

## Response process

Reports will be reviewed on a best-effort basis. Valid issues will be assessed,
tracked privately when appropriate, and addressed before public disclosure.
Credit will be provided when requested and appropriate.
