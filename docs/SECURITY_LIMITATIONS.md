# Security Limitations

## Phase 1 limitations

- Local development keys and in-memory token records are for demos and tests only. Production startup rejects local-key mode.
- Mock LLM responses establish pipeline behavior, not the security of any external provider.
- Mock attestation is `SIMULATED — NOT HARDWARE-BACKED`; it is not TEE evidence and cannot satisfy restricted policy.
- Java and NestJS detectors demonstrate hybrid, replaceable detector boundaries. They are not a complete Presidio, NER, or secret-scanner corpus.
- Pseudonymization reduces direct identifier disclosure but may leave document meaning, relationships, and trade secrets. Confidential source code and documents must be routed as a whole.
- Output and prompt-injection detection are defense in depth, not semantic proof.
- In-memory audit and policy state are not durable or suitable for regulated retention.
- Streaming validation protects the gateway boundary but cannot undo data already shown on a compromised client.

## Not guaranteed

AttestGuard does not guarantee perfect detection; protection against every encoding, language, or side channel; runtime-memory zeroization; endpoint security; or external-provider confidential computing without fresh verifiable evidence.

## Production prerequisites

Use a production identity provider, mTLS/workload identity for internal endpoints, PostgreSQL with tenant constraints and tested RLS, external KMS/HSM, encrypted backups, controlled log sinks, rate limiting, signed policy rollout, real attestation verification, evidence/measurement lifecycle management, dependency and container scanning, and an incident response process.
