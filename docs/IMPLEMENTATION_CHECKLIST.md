# Implementation Checklist

## Phase 1A — design

- [x] PRD and explicit non-goals
- [x] architecture and module boundaries
- [x] threat model and trust boundaries
- [x] prompt, RAG, attestation, and streaming data flows
- [x] token, key-management, and modular-monolith ADRs
- [x] implementation/extension scope comparison

## Phase 1B — gateway

- [x] NestJS scaffold and strict TypeScript
- [x] JWT-derived tenant context and role guard
- [x] Java credential-detector service and client
- [x] local regex/checksum/context recognizers and overlap resolution
- [x] YAML policy loading with deny override and fail closed
- [x] AES-256-GCM token vault and HMAC envelope
- [x] mock provider, provider routing, and downgrade protection
- [x] OpenAI-compatible chat/responses and security APIs
- [x] output token/provenance validation and tool-argument guard
- [x] safe event chain and audit verification

## Phase 1C — experience and delivery

- [x] Next.js demo/security console
- [x] non-root Dockerfiles and Compose health checks
- [x] CI lint, type checks, tests, build, SAST, secret/dependency/container scans, SBOM
- [x] synthetic security/adversarial fixtures for the implemented path
- [x] local runbook, demo script, and portfolio truth table

## Extensions

- [ ] durable PostgreSQL repositories and RLS ADR
- [ ] SANITIZED_EMBEDDING RAG implementation with ACL tests
- [ ] production KMS adapters
- [ ] NVIDIA NIM, NeMo Guardrails, attestation, and Morpheus adapters
- [ ] hardware validation report on supported confidential infrastructure
