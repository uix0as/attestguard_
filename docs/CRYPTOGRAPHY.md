# Cryptography

Phase 1 uses Node's standard cryptographic library—no custom cipher design.

- TOKEN_ID: 16 bytes from the operating system CSPRNG (128 bits), hex encoded.
- Token AUTH_TAG: HMAC-SHA-256 truncated to 16 bytes, verified with constant-time comparison.
- Stored value: AES-256-GCM with a 96-bit random IV and its full authentication tag.
- AAD: tenant ID, token ID, entity type, purpose, and policy version.
- Key separation: distinct per-tenant DEK and MAC key derivations for the local adapter.

The token envelope never contains plaintext, a plaintext hash, ciphertext, tenant ID, or user ID. This is reversible tokenization/pseudonymization, not anonymization.

`LocalDevelopmentKms` accepts an injected 32-byte root or creates an ephemeral root and refuses `NODE_ENV=production`. AWS KMS, Azure Key Vault, and GCP Cloud KMS types mark integration boundaries only; they are not implemented adapters. Production requires KMS-wrapped per-tenant keys, access audit, rotation, deletion, recovery, and identity-based authorization.
