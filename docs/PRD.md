# AttestGuard Product Requirements

## Problem

Employees paste personal data, credentials, proprietary source code, internal documents, and RAG content into AI applications. A proxy that only masks names cannot prevent credential disclosure, protect document-level trade secrets, stop cross-tenant re-identification, or prove that a protected execution environment is trustworthy.

AttestGuard provides one policy path in front of external, enterprise-managed, private, and attested model providers. Existing OpenAI clients change their base URL and retain their request shape.

## Product promise

AttestGuard will:

1. detect structured PII, secrets, contextual entities, code, and document-level sensitivity locally;
2. block credentials before provider invocation;
3. pseudonymize eligible personal data with authenticated surrogate tokens;
4. route content according to data class and provider trust rather than user preference alone;
5. release re-identification keys only after the required identity, scope, policy, and attestation checks;
6. scan model output, tool arguments, and retrieved content before release; and
7. emit metadata-only, hash-chained audit events.

## Personas

- **Security administrator:** authors policies, manages trust profiles, tenants, roles, and attestation allowlists.
- **AI application developer:** integrates the compatible API, uses mock providers, and receives safe reason codes.
- **Security analyst:** investigates metadata-only events and verifies the audit chain.
- **Enterprise end user:** receives understandable blocking and routing feedback without needing security expertise.

## Phase 1 acceptance criteria

- NestJS exposes `/v1/chat/completions`, `/v1/responses`, `/v1/scan`, `/v1/tokenize`, `/v1/policies/evaluate`, `/v1/security-events`, `/v1/attestation/status`, `/v1/providers`, `/health`, and `/ready`.
- Java 17 credential-detector participates in the gateway scan path and rejects unsafe or malformed input.
- Eligible PII is replaced before Mock LLM invocation; credential findings block invocation.
- AES-256-GCM protects stored token values, and HMAC authenticates the opaque token envelope.
- JWT identity supplies tenant and user context; request bodies cannot override it.
- Rehydration enforces tenant, user, session, purpose, TTL, input provenance, MAC, and use count.
- Mock attestation is always labeled `SIMULATED — NOT HARDWARE-BACKED` and cannot satisfy an `ATTESTED_TEE` rule.
- Next.js presents the request path, provider trust, decisions, and safe event metadata.
- Security tests cover the high-risk negative paths.

## Non-goals for Phase 1

- Claiming complete anonymization.
- Claiming a general Docker host is confidential computing.
- Pretending NVIDIA evidence has been verified without hardware and service credentials.
- Durable production token storage, production KMS, full Presidio/NER accuracy, OCR, production OIDC, or every provider integration.
- Guaranteeing detection of all languages, encodings, prompt injections, or side channels.

## Trust levels and decisions

| Level | Name | Intended use |
|---:|---|---|
| 0 | `PUBLIC_EXTERNAL` | Public content only |
| 1 | `ENTERPRISE_MANAGED` | Policy-approved pseudonymized content |
| 2 | `PRIVATE_VPC` | Confidential content under private deployment controls |
| 3 | `ATTESTED_TEE` | Restricted content after fresh evidence matches policy |

Policy decisions are `ALLOW`, `TOKENIZE_AND_ALLOW`, `MASK_IRREVERSIBLY`, `REQUIRE_USER_CONFIRMATION`, `ROUTE_TO_PRIVATE_MODEL`, `REQUIRE_ATTESTED_MODEL`, `BLOCK`, or `BLOCK_AND_ALERT`. Every decision includes a stable `AG_POLICY_*` reason code.

## Success measures

The benchmark harness will report per-entity precision, recall and F1; block and routing accuracy; rehydration integrity; cross-tenant isolation; p50/p95 gateway overhead; throughput; prompt utility; and mutation handling. Targets are aspirations until a dated report records real measurements.
