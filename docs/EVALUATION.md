# Evaluation

## Verified on 2026-08-26

| Check | Result |
|---|---|
| NestJS strict TypeScript | Pass |
| NestJS ESLint | Pass |
| Gateway security tests | 16/16 pass |
| Jest line coverage | 57.16% (reported, no pass threshold yet) |
| NestJS production build | Pass |
| Java `javac -Xlint:all -Werror` | Pass |
| Java detector assertions | Pass |
| Live Java → NestJS PII/tokenization route | Pass |
| Live Java → NestJS private-key block (HTTP 403) | Pass |
| Next.js strict TypeScript and lint | Pass |
| Console security-copy test | Pass |
| Next.js production build | Pass |
| npm high/critical audit | 0 reported after lockfile update |

The gateway tests cover secret blocking before provider invocation, PII tokenization, unknown/model-generated token rejection without vault lookup, token mutation, tenant/user isolation, TTL, one-time replay, simulated attestation, key-lease denial, provider downgrade protection, tool arguments, split streaming tokens, and Unicode normalization.

## Not measured yet

No defensible precision/recall/F1, throughput, p50/p95 latency, prompt utility, mutation corpus rate, or container benchmark has been run. The product targets in the PRD remain targets—not results—until the synthetic dataset generator and dated benchmark report are implemented. This gap is a Phase 2 priority.
