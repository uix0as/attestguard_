# Trust Boundaries

```mermaid
flowchart TB
  subgraph U[Untrusted client boundary]
    Client[Client / browser]
    Rag[RAG documents]
  end
  subgraph G[AttestGuard application boundary]
    Auth[JWT verification]
    Gateway[Gateway pipeline]
    Detector[Local detectors]
    Output[Output guard]
    Audit[Safe audit chain]
  end
  subgraph K[Key and data boundary]
    Vault[Encrypted token records]
    KMS[KMS adapter]
  end
  subgraph P[Provider boundary]
    Public[Public external]
    Private[Private VPC]
    TEE[Attested TEE]
  end
  Client --> Auth --> Gateway
  Rag --> Detector
  Gateway --> Detector
  Gateway <--> Vault
  Vault <--> KMS
  Gateway --> Public
  Gateway --> Private
  Gateway --> TEE
  Public --> Output
  Private --> Output
  TEE --> Output
  Output --> Client
  Gateway --> Audit
```

## Boundary rules

- Client-supplied tenant and user fields are untrusted; verified JWT claims are authoritative.
- Retrieved documents are data, never system instructions.
- The gateway owns provider selection; a requested model is a preference only.
- Public providers receive public data or policy-approved pseudonymized data, never raw credentials.
- Provider trust metadata is administrative configuration, not evidence of actual hardware state.
- Vault records are encrypted with tenant-specific data keys. Production data keys must be wrapped by an external KMS.
- `MockAttestationProvider` reports only `SIMULATED — NOT HARDWARE-BACKED`; it cannot release leases requiring `ATTESTED_TEE`.
- An external LLM is not described as confidential computing when its environment cannot be independently verified.
