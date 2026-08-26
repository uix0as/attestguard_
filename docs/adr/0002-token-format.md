# ADR 0002: Opaque authenticated surrogate tokens

- Status: Accepted
- Date: 2026-08-26

## Decision

Use `⟦AG:v1:{ENTITY_TYPE}:{TOKEN_ID}:{AUTH_TAG}⟧` where TOKEN_ID is 128 bits from a cryptographically secure random source and AUTH_TAG is a truncated HMAC-SHA-256 over the version, entity type, token ID, tenant, session, purpose, and policy version.

Tokens contain no plaintext, plaintext hash, ciphertext, tenant, or user. A strict bounded parser rejects unsupported entities, characters, lengths, versions, and partial envelopes before any repository call. Constant-time MAC comparison occurs only for token IDs already authorized by the current input/RAG provenance scope.

## Consequences

The token is pseudonymous and reversible through protected server-side state; it is not anonymous. Model-generated identifiers cannot be used as a vault enumeration oracle. Mutated tokens fail closed.
