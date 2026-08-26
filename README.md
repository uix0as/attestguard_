# AttestGuard

> Attestation-Gated Privacy Gateway for Enterprise AI

AttestGuard is a security gateway for OpenAI-compatible AI traffic. Its processing model is:

**Detect → Classify → Tokenize or Block → Route → Attest → Rehydrate**

This repository is being built security-first. The design contract and implementation boundaries are documented before the gateway code. Reversible transformations are described as **pseudonymization**, **reversible tokenization**, or **de-identification**—never complete anonymization.

## Current status

Phase 1 is in progress. The target is a runnable NestJS gateway, a Java credential-detector service, a Next.js security console, a mock LLM, and explicitly simulated attestation. Real NVIDIA attestation, hardware-backed key release, cloud KMS implementations, durable token storage, and production identity integration are planned boundaries, not implemented claims.

See [the PRD](docs/PRD.md), [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), and [security limitations](docs/SECURITY_LIMITATIONS.md).
