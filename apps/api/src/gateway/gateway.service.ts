import { Injectable } from "@nestjs/common";
import { randomUUID } from "node:crypto";
import { AttestationService } from "../attestation/attestation.service";
import { AuditService } from "../audit/audit.service";
import { ClassifierService } from "../classifier/classifier.service";
import { SafeSecurityError } from "../common/safe-error";
import type {
  ChatMessage,
  DataClass,
  DetectionFinding,
  PolicyDecision,
  Principal,
  ProviderMetadata,
  SafeFinding,
} from "../common/types";
import { DetectorService } from "../detector/detector.service";
import { OutputGuardService } from "../output-guard/output-guard.service";
import { PolicyService } from "../policy/policy.service";
import { MockProvider } from "../providers/mock.provider";
import { ProviderRegistry } from "../providers/provider.registry";
import {
  TokenVaultService,
  type TokenScope,
} from "../token-vault/token-vault.service";

export interface GatewayRequest {
  principal: Principal;
  requestId: string;
  requestedProvider: string;
  messages: ChatMessage[];
  sessionId: string;
  purpose: string;
}

export interface GatewayResult {
  id: string;
  object: "chat.completion";
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: { role: "assistant"; content: string };
    finish_reason: "stop";
  }>;
  security: {
    request_id: string;
    detected_entities: SafeFinding[];
    data_class: DataClass;
    policy: PolicyDecision;
    requested_provider: string;
    selected_provider: string;
    routing_reason: string;
    provider_trust_level: string;
    provider_simulated: boolean;
    attestation: ReturnType<AttestationService["status"]>;
    sanitized_prompt: string;
    sanitized_response: string;
    authorized_response: string;
  };
}

@Injectable()
export class GatewayService {
  constructor(
    private readonly detector: DetectorService,
    private readonly classifier: ClassifierService,
    private readonly policy: PolicyService,
    private readonly vault: TokenVaultService,
    private readonly providers: ProviderRegistry,
    private readonly mockProvider: MockProvider,
    private readonly outputGuard: OutputGuardService,
    private readonly attestation: AttestationService,
    private readonly audit: AuditService,
  ) {}

  async process(request: GatewayRequest): Promise<GatewayResult> {
    const startedAt = performance.now();
    const findingsByMessage: DetectionFinding[][] = [];
    for (const message of request.messages) {
      findingsByMessage.push(await this.detector.scan(message.content));
    }
    const findings = findingsByMessage.flat();
    const dataClass = this.classifier.classify(
      request.messages.map((message) => message.content).join("\n"),
      findings,
    );
    const decision = this.policy.evaluate(
      dataClass,
      Array.from(new Set(findings.map((finding) => finding.type))),
    );

    if (decision.action === "BLOCK" || decision.action === "BLOCK_AND_ALERT") {
      this.appendAudit(
        request,
        findings,
        decision,
        dataClass,
        undefined,
        startedAt,
      );
      throw new SafeSecurityError(
        decision.reasonCode,
        403,
        "Credential or policy-prohibited content was detected before provider invocation",
      );
    }

    const provider = this.providers.select(
      request.requestedProvider,
      decision.minimumTrust,
      dataClass,
    );
    const scope: TokenScope = {
      principal: request.principal,
      sessionId: request.sessionId,
      purpose: request.purpose,
      requestId: request.requestId,
      policyVersion: decision.policyVersion,
    };
    const issuedTokenIds = new Set<string>();
    const sanitizedMessages = request.messages.map(
      (message, index): ChatMessage => {
        const messageFindings = findingsByMessage[index] ?? [];
        if (
          decision.action !== "TOKENIZE_AND_ALLOW" ||
          messageFindings.length === 0
        )
          return message;
        const tokenized = this.vault.tokenize(
          message.content,
          messageFindings,
          scope,
          this.policy.tokenTtlSeconds(),
        );
        for (const tokenId of tokenized.issuedTokens)
          issuedTokenIds.add(tokenId);
        return { ...message, content: tokenized.sanitizedText };
      },
    );

    const completion = await this.mockProvider.complete(
      provider,
      sanitizedMessages,
    );
    for (const toolCall of completion.toolCalls) {
      const toolFindings = await this.detector.scan(toolCall.arguments);
      this.outputGuard.assertToolArgumentsSafe(toolFindings);
    }
    if (
      decision.requireAttestationForRehydration &&
      !this.attestation.status().verified
    ) {
      this.appendAudit(
        request,
        findings,
        decision,
        dataClass,
        provider,
        startedAt,
      );
      throw new SafeSecurityError(
        "AG_POLICY_ATTESTATION_FAILED",
        403,
        "Required hardware-backed attestation was not verified",
      );
    }
    const authorizedResponse = this.outputGuard.rehydrateAuthorized(
      completion.content,
      scope,
      issuedTokenIds,
      decision.allowRehydration,
    );
    this.appendAudit(
      request,
      findings,
      decision,
      dataClass,
      provider,
      startedAt,
    );

    return {
      id: `chatcmpl_${randomUUID().replaceAll("-", "")}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1_000),
      model: provider.providerId,
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: authorizedResponse },
          finish_reason: "stop",
        },
      ],
      security: {
        request_id: request.requestId,
        detected_entities: this.detector.toSafeFindings(findings),
        data_class: dataClass,
        policy: decision,
        requested_provider: request.requestedProvider,
        selected_provider: provider.providerId,
        routing_reason:
          provider.providerId === request.requestedProvider
            ? decision.reasonCode
            : `${decision.reasonCode}: requested provider did not satisfy policy`,
        provider_trust_level: provider.trustLevel,
        provider_simulated: provider.simulated,
        attestation: this.attestation.status(),
        sanitized_prompt: sanitizedMessages
          .map((message) => message.content)
          .join("\n"),
        sanitized_response: completion.content,
        authorized_response: authorizedResponse,
      },
    };
  }

  private appendAudit(
    request: GatewayRequest,
    findings: DetectionFinding[],
    decision: PolicyDecision,
    _dataClass: DataClass,
    provider: ProviderMetadata | undefined,
    startedAt: number,
  ): void {
    this.audit.append({
      principal: request.principal,
      requestId: request.requestId,
      eventType:
        decision.action === "BLOCK_AND_ALERT"
          ? "POLICY_BLOCK"
          : "GATEWAY_DECISION",
      entityTypes: Array.from(new Set(findings.map((finding) => finding.type))),
      entityCount: findings.length,
      policyId: decision.policyId,
      policyVersion: decision.policyVersion,
      decision: decision.action,
      providerRequested: request.requestedProvider,
      providerSelected: provider?.providerId,
      attestationResult: decision.requireAttestationForRehydration
        ? "FAILED"
        : "NOT_REQUIRED",
      latencyMs: Math.round(performance.now() - startedAt),
    });
  }
}
