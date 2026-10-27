# Security policy

## Supported versions

The current public release line is supported for security fixes. Development
snapshots are not supported releases.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting:
https://github.com/ArchLinuxAddict/dex2c-recovery-toolkit/security/advisories/new

Do not open a public issue for a vulnerability, and do not include target APKs,
proprietary code, credentials, or personal device data. Describe the affected
version/commit, the input conditions, and a minimal reproduction that does not
contain restricted material.

## Scope

Examples include unsafe archive extraction, path traversal, denial of service
on malformed DEX/ELF input, unintended execution of input files, and exposure
of secrets. The toolkit analyzes untrusted binaries; treat all input as
untrusted and run it in an isolated environment.

## No guarantee

This project is provided under the MIT License without warranty. No response
time or security guarantee is promised.
