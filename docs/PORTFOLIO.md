# Portfolio Notes

## Resume line supported by Phase 1

Built an OpenAI-compatible enterprise AI security gateway prototype using NestJS and Java that blocks local credential findings, pseudonymizes eligible PII with authenticated AES-GCM-backed surrogate tokens, enforces trust-aware provider routing, rejects model-generated token lookups, and fails closed on simulated attestation.

Do not claim implemented RAG, production KMS, real confidential computing, NVIDIA hardware verification, or measured detection accuracy yet.

## Technical decisions

- Kept the transactional security path in a NestJS modular gateway while isolating high-priority credential detection behind a real Java HTTP boundary.
- Bound rehydration to provenance, tenant, user, application, session, purpose, policy version, TTL, MAC, and use count.
- Chose standard AES-256-GCM/HMAC primitives and a KMS interface rather than designing cryptography.
- Made provider trust subordinate to policy and presented simulation as a negative-path capability, never verified hardware.

## Likely interview questions

- Why does unknown-token rejection happen before vault lookup?
- What does tokenization protect, and what document-level secrets remain?
- How would the in-memory repository migrate to PostgreSQL with RLS?
- What evidence must NVIDIA attestation verify before a key lease?
- Why is the Java detector a service while the rest remains modular?

## Approaches rejected or corrected

- NER-only masking: poor for credentials and document-level confidentiality.
- Token IDs as sufficient authorization: creates lookup/replay/cross-tenant risk.
- Mock attestation marked verified: teaches an unsafe trust model.
- Immediate microservice decomposition: expands identity and consistency failure surfaces before operational need.
