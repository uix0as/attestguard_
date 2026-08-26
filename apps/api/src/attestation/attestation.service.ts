import { Injectable } from "@nestjs/common";
import { randomUUID } from "node:crypto";
import { SafeSecurityError } from "../common/safe-error";

export interface AttestationResult {
  provider: "MockAttestationProvider" | "NvidiaAttestationProvider";
  status: "VERIFIED" | "FAILED" | "EXPIRED" | "NOT_CONFIGURED" | "SIMULATED";
  verified: boolean;
  label: string;
  nonce?: string;
  evidenceDigest?: string;
  hardwareIdentity?: string;
  cpuMeasurement?: string;
  gpuMeasurement?: string;
  guestMeasurement?: string;
  policyVersion: string;
  tcbStatus: string;
  verifiedAt: string;
  expiresAt: string;
  failureReason?: string;
}

export interface KeyLease {
  leaseId: string;
  tenantId: string;
  expiresAt: string;
  attestationProvider: string;
}

@Injectable()
export class AttestationService {
  status(): AttestationResult {
    const now = new Date();
    return {
      provider: "MockAttestationProvider",
      status: "SIMULATED",
      verified: false,
      label: "SIMULATED — NOT HARDWARE-BACKED",
      policyVersion: "1",
      tcbStatus: "SIMULATED_ONLY",
      verifiedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 60_000).toISOString(),
      failureReason: "Development simulation cannot establish hardware trust",
    };
  }

  verify(nonce: string, evidence: string): AttestationResult {
    void nonce;
    void evidence;
    return this.status();
  }

  issueKeyLease(tenantId: string, requireHardwareBacked: boolean): KeyLease {
    const result = this.status();
    if (requireHardwareBacked || !result.verified) {
      throw new SafeSecurityError(
        "AG_POLICY_ATTESTATION_FAILED",
        403,
        "Hardware-backed attestation was not verified; no key lease was issued",
      );
    }
    return {
      leaseId: randomUUID(),
      tenantId,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      attestationProvider: result.provider,
    };
  }
}
