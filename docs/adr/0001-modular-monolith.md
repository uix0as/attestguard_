# ADR 0001: Modular gateway with bounded detector service

- Status: Accepted
- Date: 2026-08-26

## Context

The security path shares principal, findings, policy, token scope, routing, output, and audit state. Premature distribution creates authentication and consistency failure modes. A Java implementation is also required to demonstrate a replaceable local high-priority scanner.

## Decision

Use a NestJS modular gateway for the transactional security path and a narrow Java 17 HTTP detector boundary. Keep TokenVault and AttestationVerifier behind interfaces so evidence—not fashion—can justify later extraction. Java service failure fails the scan closed unless an explicitly documented development-only mode is active.

## Consequences

The primary path is easier to test atomically, while detector protocol and timeouts remain real distributed-system concerns. Java gets a small, meaningful role without turning every module into a service.
