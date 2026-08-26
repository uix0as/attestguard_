# Data Flows

## Prompt processing

```mermaid
sequenceDiagram
  participant C as Client
  participant G as NestJS Gateway
  participant J as Java Credential Detector
  participant V as Token Vault
  participant R as Policy Router
  participant P as Selected Provider
  participant O as Output Guard
  C->>G: chat completion + JWT
  G->>J: bounded local credential scan
  J-->>G: findings only
  G->>G: PII scan + document classification
  G->>R: principal + findings + requested model
  alt credential or no safe provider
    R-->>C: safe BLOCK reason
  else tokenization allowed
    G->>V: encrypt values under scoped records
    V-->>G: authenticated surrogate tokens
    G->>P: sanitized request
    P-->>O: sanitized response / tool arguments
    O->>O: validate against issued-token scope
    O->>V: rehydrate authorized tokens only
    O-->>C: authorized response + routing metadata
  end
```

## RAG ingestion

```mermaid
sequenceDiagram
  participant D as Document
  participant I as Ingestion Guard
  participant P as Policy
  participant V as Token Vault
  participant E as Local Embedder
  participant S as Vector Store
  D->>I: txt / md / json
  I->>I: type, size, malware boundary, injection scan
  I->>P: sensitivity + entities + ACL
  alt credential or disallowed content
    P-->>D: reject/quarantine
  else SANITIZED_EMBEDDING
    I->>V: pseudonymize eligible values
    I->>E: sanitized chunks only
    E->>S: tenant/document scoped vectors
  end
```

## Attestation and key release

```mermaid
sequenceDiagram
  participant R as Rehydration Service
  participant W as Workload
  participant A as Attestation Verifier
  participant K as Key Lease Service
  participant V as Token Vault
  R->>A: issue nonce
  W->>A: evidence + nonce
  A->>A: freshness, nonce, measurement, TCB, policy
  alt verified hardware evidence
    A->>K: verified result
    K-->>W: short-lived scoped lease
    W->>V: lease + token scope
    V-->>W: authorized plaintext
  else failed, stale, simulated, or unknown
    A-->>W: deny without sensitive detail
  end
```

## Streaming output

A bounded incremental parser retains only the maximum possible token-envelope tail between chunks. Complete tokens are released only after strict syntax, provenance, MAC, and authorization checks. A partial, malformed, mutated, or unknown token fails closed; it is never sent to the vault as a lookup oracle.
