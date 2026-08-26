import { AttestationService } from "../src/attestation/attestation.service";
import { AuditService } from "../src/audit/audit.service";
import { ClassifierService } from "../src/classifier/classifier.service";
import { SafeSecurityError } from "../src/common/safe-error";
import type { DetectionFinding, Principal } from "../src/common/types";
import { DetectorService } from "../src/detector/detector.service";
import { JavaCredentialDetector } from "../src/detector/java-credential-detector";
import {
  GatewayService,
  type GatewayRequest,
} from "../src/gateway/gateway.service";
import { OutputGuardService } from "../src/output-guard/output-guard.service";
import { TokenStreamParser } from "../src/output-guard/token-stream.parser";
import { PolicyService } from "../src/policy/policy.service";
import { MockProvider } from "../src/providers/mock.provider";
import { ProviderRegistry } from "../src/providers/provider.registry";
import {
  TokenVaultService,
  type TokenScope,
} from "../src/token-vault/token-vault.service";

const principal: Principal = {
  tenantId: "tenant-synthetic-a",
  userId: "user-synthetic-a",
  role: "developer",
  applicationId: "app-synthetic-a",
};

function createHarness(): {
  detector: DetectorService;
  vault: TokenVaultService;
  mock: MockProvider;
  gateway: GatewayService;
  output: OutputGuardService;
} {
  const javaStub = {
    scan: (): Promise<DetectionFinding[]> => Promise.resolve([]),
  } as unknown as JavaCredentialDetector;
  const detector = new DetectorService(javaStub);
  const classifier = new ClassifierService();
  const policy = new PolicyService();
  const vault = new TokenVaultService();
  const providers = new ProviderRegistry();
  const mock = new MockProvider();
  const output = new OutputGuardService(vault);
  const attestation = new AttestationService();
  const audit = new AuditService();
  const gateway = new GatewayService(
    detector,
    classifier,
    policy,
    vault,
    providers,
    mock,
    output,
    attestation,
    audit,
  );
  return { detector, vault, mock, gateway, output };
}

function request(
  content: string,
  requestedProvider = "mock-external",
): GatewayRequest {
  return {
    principal,
    requestId: "request-synthetic-a",
    requestedProvider,
    messages: [{ role: "user" as const, content }],
    sessionId: "session-synthetic-a",
    purpose: "synthetic-test",
  };
}

function scope(overrides: Partial<TokenScope> = {}): TokenScope {
  return {
    principal,
    requestId: "request-synthetic-a",
    sessionId: "session-synthetic-a",
    purpose: "synthetic-test",
    policyVersion: "1",
    ...overrides,
  };
}

function emailFinding(value = "minsu@example.test"): DetectionFinding {
  return {
    type: "EMAIL_ADDRESS",
    start: 0,
    end: value.length,
    confidence: 0.99,
    source: "synthetic-test",
    value,
    credential: false,
  };
}

describe("AttestGuard security invariants", () => {
  it("test_raw_secret_never_reaches_external_provider", async () => {
    const { gateway, mock } = createHarness();
    const marker = `-----BEGIN ${"PRIVATE"} KEY-----\nSYNTHETIC_DISABLED_DATA`;
    await expect(gateway.process(request(marker))).rejects.toMatchObject({
      reasonCode: "AG_POLICY_SECRET_BLOCKED",
    });
    expect(mock.getCallCountForTest()).toBe(0);
    expect(mock.getLastSanitizedPromptForTest()).toBeUndefined();
  });

  it("test_private_key_is_blocked", async () => {
    const { gateway } = createHarness();
    const marker = `-----BEGIN ${"PRIVATE"} KEY-----`;
    await expect(gateway.process(request(marker))).rejects.toBeInstanceOf(
      SafeSecurityError,
    );
  });

  it("test_pii_is_tokenized_before_provider_call", async () => {
    const { gateway, mock } = createHarness();
    const raw = "김민수 고객의 전화번호 010-1234-5678로 안내해 주세요.";
    const result = await gateway.process(request(raw));
    expect(mock.getLastSanitizedPromptForTest()).toContain("⟦AG:v1:PERSON:");
    expect(mock.getLastSanitizedPromptForTest()).toContain(
      "⟦AG:v1:KR_PHONE_NUMBER:",
    );
    expect(mock.getLastSanitizedPromptForTest()).not.toContain("김민수");
    expect(mock.getLastSanitizedPromptForTest()).not.toContain("010-1234-5678");
    expect(result.choices[0]?.message.content).toContain("김민수");
  });

  it("test_unknown_token_is_not_rehydrated", () => {
    const { vault, output } = createHarness();
    const unknown = `⟦AG:v1:EMAIL_ADDRESS:${"0".repeat(32)}:${"0".repeat(32)}⟧`;
    expect(() =>
      output.rehydrateAuthorized(unknown, scope(), new Set(), true),
    ).toThrow("not issued for this request");
    expect(vault.getLookupCountForTest()).toBe(0);
  });

  it("test_tampered_token_is_rejected", () => {
    const { vault } = createHarness();
    const value = "minsu@example.test";
    const tokenized = vault.tokenize(
      value,
      [emailFinding(value)],
      scope(),
      900,
    );
    const token = tokenized.tokenById.values().next().value as string;
    const parsed = vault.parseToken(token);
    const mutated = `${token.slice(0, -2)}${token.at(-2) === "0" ? "1" : "0"}⟧`;
    expect(() =>
      vault.rehydrateToken(mutated, scope(), new Set([parsed.tokenId])),
    ).toThrow("modified token");
  });

  it("test_model_generated_token_cannot_query_vault", () => {
    const { vault } = createHarness();
    const generated = `⟦AG:v1:EMAIL_ADDRESS:${"a".repeat(32)}:${"b".repeat(32)}⟧`;
    expect(() => vault.rehydrateToken(generated, scope(), new Set())).toThrow(
      SafeSecurityError,
    );
    expect(vault.getLookupCountForTest()).toBe(0);
  });

  it("test_cross_tenant_token_lookup_is_denied", () => {
    const { vault } = createHarness();
    const tokenized = vault.tokenize(
      "minsu@example.test",
      [emailFinding()],
      scope(),
      900,
    );
    const token = tokenized.tokenById.values().next().value as string;
    const parsed = vault.parseToken(token);
    const otherTenant = scope({
      principal: { ...principal, tenantId: "tenant-synthetic-b" },
    });
    expect(() =>
      vault.rehydrateToken(token, otherTenant, new Set([parsed.tokenId])),
    ).toThrow(SafeSecurityError);
  });

  it("test_cross_user_rehydration_is_denied", () => {
    const { vault } = createHarness();
    const tokenized = vault.tokenize(
      "minsu@example.test",
      [emailFinding()],
      scope(),
      900,
    );
    const token = tokenized.tokenById.values().next().value as string;
    const parsed = vault.parseToken(token);
    const otherUser = scope({
      principal: { ...principal, userId: "user-synthetic-b" },
    });
    expect(() =>
      vault.rehydrateToken(token, otherUser, new Set([parsed.tokenId])),
    ).toThrow("Token scope is invalid");
  });

  it("test_expired_token_is_not_rehydrated", () => {
    const { vault } = createHarness();
    const tokenized = vault.tokenize(
      "minsu@example.test",
      [emailFinding()],
      scope(),
      900,
    );
    const token = tokenized.tokenById.values().next().value as string;
    const parsed = vault.parseToken(token);
    vault.expireForTest(principal.tenantId, parsed.tokenId);
    expect(() =>
      vault.rehydrateToken(token, scope(), new Set([parsed.tokenId])),
    ).toThrow("expired");
  });

  it("test_replayed_one_time_token_is_denied", () => {
    const { vault } = createHarness();
    const tokenized = vault.tokenize(
      "minsu@example.test",
      [emailFinding()],
      scope(),
      900,
      true,
    );
    const token = tokenized.tokenById.values().next().value as string;
    const parsed = vault.parseToken(token);
    const authorized = new Set([parsed.tokenId]);
    expect(vault.rehydrateToken(token, scope(), authorized)).toBe(
      "minsu@example.test",
    );
    expect(() => vault.rehydrateToken(token, scope(), authorized)).toThrow(
      "cannot be used again",
    );
  });

  it("test_mock_attestation_is_marked_simulated", () => {
    const attestation = new AttestationService().status();
    expect(attestation.status).toBe("SIMULATED");
    expect(attestation.verified).toBe(false);
    expect(attestation.label).toBe("SIMULATED — NOT HARDWARE-BACKED");
  });

  it("test_attestation_failure_blocks_key_release", () => {
    expect(() =>
      new AttestationService().issueKeyLease(principal.tenantId, true),
    ).toThrow("no key lease was issued");
  });

  it("test_provider_downgrade_is_blocked", async () => {
    const { gateway } = createHarness();
    const result = await gateway.process(
      request("class InternalPlan { private value = 1; }"),
    );
    expect(result.security.data_class).toBe("CONFIDENTIAL");
    expect(result.security.selected_provider).toBe("mock-private");
    expect(result.security.provider_trust_level).toBe("PRIVATE_VPC");
  });

  it("test_credential_cannot_be_sent_via_tool_call", async () => {
    const { detector, output } = createHarness();
    const argumentsText = `{"secret":"-----BEGIN ${"PRIVATE"} KEY-----"}`;
    const findings = await detector.scan(argumentsText);
    expect(() => output.assertToolArgumentsSafe(findings)).toThrow("tool call");
  });

  it("test_streaming_token_split_is_handled", () => {
    const { vault } = createHarness();
    const tokenized = vault.tokenize(
      "minsu@example.test",
      [emailFinding()],
      scope(),
      900,
    );
    const token = tokenized.tokenById.values().next().value as string;
    const parsed = vault.parseToken(token);
    const parser = new TokenStreamParser((candidate) =>
      vault.rehydrateToken(candidate, scope(), new Set([parsed.tokenId])),
    );
    const split = Math.floor(token.length / 2);
    const output =
      parser.feed(`before ${token.slice(0, split)}`) +
      parser.feed(`${token.slice(split)} after`) +
      parser.finish();
    expect(output).toBe("before minsu@example.test after");
  });

  it("test_unicode_obfuscation_detection", async () => {
    const { detector } = createHarness();
    const findings = await detector.scan("email: minsu＠example．test");
    expect(findings.some((finding) => finding.type === "EMAIL_ADDRESS")).toBe(
      true,
    );
  });
});
