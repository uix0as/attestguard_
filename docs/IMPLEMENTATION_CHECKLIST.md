# Implementation Checklist

## Phase 1A — design

- [x] PRD and explicit non-goals
- [x] architecture and module boundaries
- [x] threat model and trust boundaries
- [x] prompt, RAG, attestation, and streaming data flows
- [x] token, key-management, and modular-monolith ADRs
- [x] implementation/extension scope comparison

## Phase 1B — gateway

- [ ] NestJS scaffold and strict TypeScript
- [ ] JWT-derived tenant context and role guard
- [ ] Java credential-detector service and client
- [ ] local regex/checksum/context recognizers and overlap resolution
- [ ] YAML policy loading with deny override and fail closed
- [ ] AES-256-GCM token vault and HMAC envelope
- [ ] mock provider, provider routing, and downgrade protection
- [ ] OpenAI-compatible chat/responses and security APIs
- [ ] output token/provenance validation and tool-argument guard
- [ ] safe event chain and audit verification

## Phase 1C — experience and delivery

- [ ] Next.js demo/security console
- [ ] non-root Dockerfiles and Compose health checks
- [ ] CI lint, type checks, tests, build, SAST, dependency/container scans, SBOM
- [ ] synthetic fixtures and security/adversarial tests
- [ ] local runbook, demo script, and portfolio truth table

## Extensions

- [ ] durable PostgreSQL repositories and RLS ADR
- [ ] SANITIZED_EMBEDDING RAG implementation with ACL tests
- [ ] production KMS adapters
- [ ] NVIDIA NIM, NeMo Guardrails, attestation, and Morpheus adapters
- [ ] hardware validation report on supported confidential infrastructure
