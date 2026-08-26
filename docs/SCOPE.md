# MVP and NVIDIA Confidential Computing Scope

| Capability | Phase 1 | NVIDIA / production extension |
|---|---|---|
| API gateway | NestJS OpenAI-compatible core | HA deployment, quotas, advanced streaming |
| Credential detection | Local Java service + NestJS recognizers | NeMo Guardrails/Morpheus adapters and evaluated models |
| Token vault | AES-256-GCM, HMAC, tenant/user/session/purpose/TTL in memory | PostgreSQL, HSM/KMS-wrapped per-tenant DEKs, rotation jobs |
| LLM | Deterministic Mock provider | NVIDIA NIM private inference and provider credentials |
| Attestation | Explicit simulated provider and fail-closed interfaces | NVIDIA Attestation Suite/RAS evidence, nonce, TCB and measurement allowlists |
| Key release | Policy-shaped simulated denial/lease boundary | Hardware-backed short-lived key leases |
| GPU security | No claim | Confidential GPU + Confidential VM/container deployment |
| Event analytics | Hash-chained in-memory events | Durable SIEM export and NVIDIA Morpheus anomaly pipelines |
| RAG | Security boundary and sanitized-mode design | Local embedding, pgvector, ACL-enforced ingestion/retrieval |

Nothing in the Phase 1 column is evidence that an ordinary VM, Docker container, or mock provider is confidential computing.
