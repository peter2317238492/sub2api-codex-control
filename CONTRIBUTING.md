# Contributing

## Development

Start from the installation guide in `docs/installation.md`, keep changes
focused, and add tests for behavior changes. Run the relevant package tests and
the repository checks before opening a pull request.

Do not commit generated dependencies, build output, acceptance reports,
backups, database dumps, logs, credentials, authentication exports, signing
material, or production configuration. Use `control.example.com` and other
reserved example values in documentation and fixtures.

## Pull requests

Explain the behavior and security impact, list the verification commands that
were run, and call out any tests that could not be run. Keep release, protocol,
database, authentication, and proxy changes independently reviewable when
possible.

By submitting a contribution, you agree that it is licensed under the Apache
License 2.0 in `LICENSE` and that you have the right to provide it under those
terms.

Report vulnerabilities through the private process in `SECURITY.md`, not a
public issue or pull request.
