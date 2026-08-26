# ADR 0004: PostgreSQL with pgvector for the future RAG store

- Status: Planned, not implemented
- Date: 2026-08-26

## Decision

Use PostgreSQL plus pgvector when durable RAG repositories are implemented. Tenant ACLs, document metadata, policy versions, and vectors can then share transactions and backup controls. This avoids introducing a second stateful database during the MVP.

## Consequences

Vector workloads must be benchmarked before production sizing. Tenant predicates remain mandatory in repositories; future Row-Level Security is defense in depth. The Compose `future-durable-storage` profile is an integration boundary only—the current gateway does not persist to it.
