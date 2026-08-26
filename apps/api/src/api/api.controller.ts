import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
} from "@nestjs/common";
import type { Response } from "express";
import { AttestationService } from "../attestation/attestation.service";
import { AuditService } from "../audit/audit.service";
import { AuthGuard, type AuthenticatedRequest } from "../auth/auth.guard";
import { ClassifierService } from "../classifier/classifier.service";
import { SafeSecurityError } from "../common/safe-error";
import { DetectorService } from "../detector/detector.service";
import { GatewayService } from "../gateway/gateway.service";
import { PolicyService } from "../policy/policy.service";
import { ProviderRegistry } from "../providers/provider.registry";
import {
  TokenVaultService,
  type TokenScope,
} from "../token-vault/token-vault.service";
import { ChatCompletionDto, ResponsesDto, ScanDto, TokenizeDto } from "./dto";

@Controller()
@UseGuards(AuthGuard)
export class ApiController {
  constructor(
    private readonly gateway: GatewayService,
    private readonly detector: DetectorService,
    private readonly classifier: ClassifierService,
    private readonly policy: PolicyService,
    private readonly vault: TokenVaultService,
    private readonly providers: ProviderRegistry,
    private readonly attestation: AttestationService,
    private readonly audit: AuditService,
  ) {}

  @Get("/health")
  health(): { status: "ok" } {
    return { status: "ok" };
  }

  @Get("/ready")
  ready(): { status: "ready" | "not_ready"; policy: boolean } {
    return {
      status: this.policy.isReady() ? "ready" : "not_ready",
      policy: this.policy.isReady(),
    };
  }

  @Post("/v1/chat/completions")
  async chat(
    @Body() body: ChatCompletionDto,
    @Req() request: AuthenticatedRequest,
    @Res({ passthrough: true }) response: Response,
  ): Promise<unknown> {
    const result = await this.gateway.process({
      principal: request.principal,
      requestId: request.requestId,
      requestedProvider: body.model,
      messages: body.messages,
      sessionId: body.session_id ?? request.requestId,
      purpose: body.purpose ?? "chat",
    });
    if (!body.stream) return result;
    response.setHeader("content-type", "text/event-stream");
    response.setHeader("cache-control", "no-cache");
    const chunk = {
      id: result.id,
      object: "chat.completion.chunk",
      created: result.created,
      model: result.model,
      choices: [
        { index: 0, delta: result.choices[0]?.message, finish_reason: null },
      ],
      security: result.security,
    };
    response.write(`data: ${JSON.stringify(chunk)}\n\n`);
    response.write(
      `data: ${JSON.stringify({ ...chunk, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`,
    );
    response.end("data: [DONE]\n\n");
    return undefined;
  }

  @Post("/v1/responses")
  async responses(
    @Body() body: ResponsesDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<unknown> {
    const result = await this.gateway.process({
      principal: request.principal,
      requestId: request.requestId,
      requestedProvider: body.model,
      messages: [{ role: "user", content: body.input }],
      sessionId: body.session_id ?? request.requestId,
      purpose: body.purpose ?? "responses",
    });
    return {
      id: result.id.replace("chatcmpl_", "resp_"),
      object: "response",
      model: result.model,
      output_text: result.choices[0]?.message.content ?? "",
      security: result.security,
    };
  }

  @Post("/v1/scan")
  async scan(@Body() body: ScanDto): Promise<unknown> {
    const findings = await this.detector.scan(body.text);
    return {
      findings: this.detector.toSafeFindings(findings),
      classification: this.classifier.classify(body.text, findings),
    };
  }

  @Post("/v1/policies/evaluate")
  async evaluate(@Body() body: ScanDto): Promise<unknown> {
    const findings = await this.detector.scan(body.text);
    const dataClass = this.classifier.classify(body.text, findings);
    return {
      data_class: dataClass,
      decision: this.policy.evaluate(
        dataClass,
        Array.from(new Set(findings.map((finding) => finding.type))),
      ),
      findings: this.detector.toSafeFindings(findings),
    };
  }

  @Post("/v1/tokenize")
  async tokenize(
    @Body() body: TokenizeDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<unknown> {
    const findings = await this.detector.scan(body.text);
    if (findings.some((finding) => finding.credential)) {
      throw new SafeSecurityError(
        "AG_POLICY_SECRET_BLOCKED",
        403,
        "Credential material cannot be tokenized for model transmission",
      );
    }
    const dataClass = this.classifier.classify(body.text, findings);
    const decision = this.policy.evaluate(
      dataClass,
      Array.from(new Set(findings.map((finding) => finding.type))),
    );
    const scope: TokenScope = {
      principal: request.principal,
      sessionId: body.session_id,
      purpose: body.purpose,
      requestId: request.requestId,
      policyVersion: decision.policyVersion,
    };
    const result = this.vault.tokenize(
      body.text,
      findings,
      scope,
      this.policy.tokenTtlSeconds(),
    );
    return {
      sanitized_text: result.sanitizedText,
      findings: this.detector.toSafeFindings(findings),
      policy_decision_id: decision.id,
    };
  }

  @Get("/v1/security-events")
  securityEvents(@Req() request: AuthenticatedRequest): unknown {
    if (
      !["security_admin", "security_analyst", "tenant_admin"].includes(
        request.principal.role,
      )
    ) {
      throw new SafeSecurityError(
        "AG_POLICY_ROLE_DENIED",
        403,
        "This role cannot view security events",
      );
    }
    return { data: this.audit.list(request.principal.tenantId) };
  }

  @Get("/v1/attestation/status")
  attestationStatus(): unknown {
    return this.attestation.status();
  }

  @Get("/v1/providers")
  providerList(): unknown {
    return { data: this.providers.list() };
  }

  @Get("/v1/audit/verify")
  verifyAudit(@Req() request: AuthenticatedRequest): unknown {
    if (
      !["security_admin", "security_analyst", "tenant_admin"].includes(
        request.principal.role,
      )
    ) {
      throw new SafeSecurityError(
        "AG_POLICY_ROLE_DENIED",
        403,
        "This role cannot verify the audit chain",
      );
    }
    return this.audit.verify();
  }
}
