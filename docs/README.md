# Hollis Identity Docs

Current state as of 2026-05-18:

- Standalone Express + Prisma identity service is scaffolded and typechecks.
- Shared contracts are consumed from GitHub Packages as `@hollis-studio/contracts@0.2.0-alpha.7`.
- Docker installs packages from GitHub Packages through an npmrc secret; no sibling `hollis-shared` checkout is required.
- Health integration is not cut over yet. Health still owns production auth until the identity-service migration phases are completed.

Operational setup remains in the root [`README.md`](../README.md) until the service gets a fuller runbook set.
