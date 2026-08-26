import { Body, Controller, Post, Req, UseGuards } from "@nestjs/common";
import { AttestationService } from "../attestation/attestation.service";
import { AuthGuard, type AuthenticatedRequest } from "../auth/auth.guard";
import { SafeSecurityError } from "../common/safe-error";
import {
  TokenVaultService,
  type TokenScope,
} from "../token-vault/token-vault.service";
import { AttestationVerifyDto, KeyLeaseDto, RehydrateDto } from "./dto";

@Controller("/internal/v1")
@UseGuards(AuthGuard)
export class InternalController {
  constructor(
    private readonly vault: TokenVaultService,
    private readonly attestation: AttestationService,
  ) {}

  @Post("/rehydrate")
  rehydrate(
    @Body() body: RehydrateDto,
    @Req() request: AuthenticatedRequest,
  ): unknown {
    this.assertServiceRole(request);
    const scope: TokenScope = {
      principal: request.principal,
      sessionId: body.session_id,
      purpose: body.purpose,
      requestId: body.request_id,
      policyVersion: body.policy_version,
    };
    const authorized = this.vault.authorizedIdsForRequest(
      request.principal.tenantId,
      body.request_id,
    );
    return { value: this.vault.rehydrateToken(body.token, scope, authorized) };
  }

  @Post("/key-leases")
  keyLease(
    @Body() body: KeyLeaseDto,
    @Req() request: AuthenticatedRequest,
  ): unknown {
    this.assertServiceRole(request);
    return this.attestation.issueKeyLease(
      request.principal.tenantId,
      body.require_hardware_backed,
    );
  }

  @Post("/attestation/verify")
  verify(
    @Body() body: AttestationVerifyDto,
    @Req() request: AuthenticatedRequest,
  ): unknown {
    this.assertServiceRole(request);
    return this.attestation.verify(body.nonce, body.evidence);
  }

  private assertServiceRole(request: AuthenticatedRequest): void {
    if (request.principal.role !== "rehydration_service") {
      throw new SafeSecurityError(
        "AG_POLICY_ROLE_DENIED",
        403,
        "Only the rehydration service can access this endpoint",
      );
    }
  }
}
