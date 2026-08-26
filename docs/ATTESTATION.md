# Attestation and Key Release

## Implemented now

`MockAttestationProvider` always returns:

- status `SIMULATED`;
- `verified: false`; and
- label `SIMULATED — NOT HARDWARE-BACKED`.

It cannot satisfy `ATTESTED_TEE`, and the key-lease service refuses hardware-required leases. This tests failure behavior only.

## Required production flow

1. issue a single-use nonce;
2. obtain evidence from the target workload;
3. validate nonce binding, freshness, signature/certificate chain, and evidence format;
4. compare CPU, GPU, guest, firmware, software, and policy measurements with versioned allowlists;
5. validate TCB status and revocation state;
6. issue a short-lived, tenant/workload/purpose-scoped lease only after success; and
7. require a fresh verification after expiry.

The NVIDIA boundary is designed for NVIDIA Attestation Suite/RAS and confidential GPU deployments with an appropriate CPU Confidential VM/container. No NVIDIA hardware, evidence, credentials, or NIM deployment was available for this implementation, so none is reported as verified.
