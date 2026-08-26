# ADR 0003: Standard AEAD and replaceable KMS boundary

- Status: Accepted for development; production implementation required
- Date: 2026-08-26

## Decision

Encrypt each original value using AES-256-GCM and AAD containing tenant ID, token ID, entity type, purpose, and policy version. Use per-tenant data-encryption keys obtained through a KMS interface. The Phase 1 LocalDevelopmentKMS derives ephemeral tenant keys from an injected 256-bit development root and refuses production mode. Interfaces reserve AWS KMS, Azure Key Vault, and GCP Cloud KMS implementations without pretending they exist.

## Consequences

Ciphertext modification and scope substitution are detected. Memory-managed runtimes cannot promise complete zeroization. Production requires external key wrapping, access audit, rotation, deletion, backup, and recovery procedures before real data is permitted.
