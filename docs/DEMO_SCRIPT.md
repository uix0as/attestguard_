# Demo Script

## Three minutes

1. Show the Prompt inspector and the explicit simulated-attestation warning.
2. Submit the synthetic Korean name and phone example. Point out that the mock provider receives only authenticated surrogate tokens and the authorized response is rehydrated for the same scoped user.
3. Submit a visibly synthetic private-key marker. Show `AG_POLICY_SECRET_BLOCKED`, zero additional provider calls in the test evidence, and a metadata-only event.

## Seven minutes

Add the public-to-enterprise routing change, confidential source-code route to `mock-private`, token envelope/AES-GCM design, model-generated token rejection, tenant/user/TTL bindings, and Java detector fail-closed boundary.

## Fifteen minutes

Walk through the system, data flow, trust-boundary and attestation diagrams; run the gateway and Java security suites; verify the audit chain; discuss why pseudonymization is not anonymization; and close with the production gaps: KMS, durable repositories, RAG implementation, real NIM/RAS, OIDC/mTLS, and empirical detection benchmarks.
