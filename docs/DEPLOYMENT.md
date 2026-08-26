# Local Deployment and Dokploy Boundary

## Local demo

Copy `.env.example` to `.env`, replace `JWT_SECRET` with at least 32 random development characters, then run:

```sh
docker compose up --build
```

The API binds to `127.0.0.1:8080`; the console binds to `127.0.0.1:3000`; the Java detector is internal-only. Containers drop Linux capabilities, enable `no-new-privileges`, use UID/GID `10001:10001`, and use read-only filesystems with bounded `/tmp` mounts.

This is a demo profile. The API deliberately runs development local-KMS mode and must not receive real sensitive data.

## Dokploy

Import the repository as a Compose application, configure the environment outside Git, and expose only `web` and the required public API routes through TLS. Keep the Java detector network private. Route `/internal/v1/*` only over an internal/mTLS path in production; Phase 1 additionally enforces the `rehydration_service` JWT role but does not provide a second listener.

Do not enable `future-durable-storage` as if it were integrated. It only starts a pgvector-compatible PostgreSQL boundary; the current gateway remains in memory.

## Production gates

Production needs a real KMS adapter, durable tenant-scoped repositories and migrations, tested PostgreSQL constraints/RLS, OIDC/workload identity, internal mTLS, rate limits, encrypted backup/restore drills, controlled observability sinks, provider credentials, network policies, and real attestation verification. TLS should terminate at the managed ingress/load balancer with authenticated encryption continuing to internal services.

## Backup and restore

There is no durable Phase 1 vault to back up. When PostgreSQL is integrated, back up ciphertext, policy versions, event-chain checkpoints, and wrapped-key metadata; never export plaintext mappings or unwrapped keys. Test restore into an isolated environment and verify tenant constraints and audit-chain continuity.
