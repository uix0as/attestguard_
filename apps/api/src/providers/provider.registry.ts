import { Injectable } from "@nestjs/common";
import { SafeSecurityError } from "../common/safe-error";
import type { DataClass, ProviderMetadata, TrustLevel } from "../common/types";

const TRUST_RANK: Record<TrustLevel, number> = {
  PUBLIC_EXTERNAL: 0,
  ENTERPRISE_MANAGED: 1,
  PRIVATE_VPC: 2,
  ATTESTED_TEE: 3,
};

const PROVIDERS: ProviderMetadata[] = [
  {
    providerId: "mock-external",
    displayName: "Mock External (development only)",
    endpoint: "internal://mock",
    trustLevel: "PUBLIC_EXTERNAL",
    allowedDataClasses: ["PUBLIC"],
    allowedRegions: ["local-dev"],
    supportsStreaming: true,
    supportsTools: true,
    supportsStructuredOutput: true,
    requiresAttestation: false,
    enabled: true,
    simulated: true,
  },
  {
    providerId: "mock-enterprise",
    displayName: "Mock Enterprise Managed (development only)",
    endpoint: "internal://mock",
    trustLevel: "ENTERPRISE_MANAGED",
    allowedDataClasses: ["PUBLIC", "INTERNAL"],
    allowedRegions: ["local-dev"],
    supportsStreaming: true,
    supportsTools: true,
    supportsStructuredOutput: true,
    requiresAttestation: false,
    enabled: true,
    simulated: true,
  },
  {
    providerId: "mock-private",
    displayName: "Mock Private Route (development only)",
    endpoint: "internal://mock",
    trustLevel: "PRIVATE_VPC",
    allowedDataClasses: ["PUBLIC", "INTERNAL", "CONFIDENTIAL"],
    allowedRegions: ["local-dev"],
    supportsStreaming: true,
    supportsTools: true,
    supportsStructuredOutput: true,
    requiresAttestation: false,
    enabled: true,
    simulated: true,
  },
  {
    providerId: "nvidia-nim-attested",
    displayName: "NVIDIA NIM attested boundary (not configured)",
    endpoint: "not-configured",
    trustLevel: "ATTESTED_TEE",
    allowedDataClasses: ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
    allowedRegions: [],
    supportsStreaming: true,
    supportsTools: true,
    supportsStructuredOutput: true,
    requiresAttestation: true,
    enabled: false,
    simulated: false,
  },
];

@Injectable()
export class ProviderRegistry {
  list(): ProviderMetadata[] {
    return PROVIDERS.map((provider) => ({ ...provider }));
  }

  select(
    requestedProvider: string,
    minimumTrust: TrustLevel,
    dataClass: DataClass,
  ): ProviderMetadata {
    const requested = PROVIDERS.find(
      (provider) => provider.providerId === requestedProvider,
    );
    if (
      requested?.enabled &&
      TRUST_RANK[requested.trustLevel] >= TRUST_RANK[minimumTrust] &&
      requested.allowedDataClasses.includes(dataClass)
    ) {
      return { ...requested };
    }
    const selected = PROVIDERS.filter(
      (provider) =>
        provider.enabled &&
        TRUST_RANK[provider.trustLevel] >= TRUST_RANK[minimumTrust] &&
        provider.allowedDataClasses.includes(dataClass),
    ).sort(
      (left, right) =>
        TRUST_RANK[left.trustLevel] - TRUST_RANK[right.trustLevel],
    )[0];

    if (!selected) {
      throw new SafeSecurityError(
        minimumTrust === "ATTESTED_TEE"
          ? "AG_POLICY_ATTESTATION_REQUIRED"
          : "AG_POLICY_NO_TRUSTED_PROVIDER",
        403,
        "No enabled provider satisfies the required trust level",
      );
    }
    return { ...selected };
  }
}
