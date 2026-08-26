# Security Policy

## Supported versions

AttestGuard is pre-1.0. Only the latest commit on `main` receives security fixes. Do not process real sensitive data with the Phase 1 local KMS or in-memory vault.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Send a minimal report to the future security contact placeholder `security@example.invalid` and replace this address before public launch. Include the affected version, safe reproduction steps, impact, and any suggested mitigation. Do not include real personal data, credentials, production tokens, or decrypted vault values.

The maintainers should acknowledge a report within three business days, establish severity and remediation scope, and coordinate disclosure after a fix is available.

## Suspected secret exposure

1. Stop affected provider and gateway traffic.
2. Revoke or rotate the exposed credential at its authority; deleting a Git commit is not revocation.
3. Preserve metadata-only evidence without copying the secret into tickets or chat.
4. Rotate related signing, KMS, session, and provider credentials as scope requires.
5. Invalidate active tokens and key leases.
6. Review provider, application, CI, log, trace, and artifact destinations.
7. Document root cause and detection/control changes.

Mock fixtures must be visibly synthetic and inactive. CI rejects detected repository secrets and high-severity dependency advisories.
