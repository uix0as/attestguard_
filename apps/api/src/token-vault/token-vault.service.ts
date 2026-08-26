import { Injectable } from "@nestjs/common";
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { SafeSecurityError } from "../common/safe-error";
import {
  ENTITY_TYPES,
  type DetectionFinding,
  type EntityType,
  type Principal,
} from "../common/types";
import { LocalDevelopmentKms, type KmsAdapter } from "./kms";

const TOKEN_PATTERN = /^⟦AG:v1:([A-Z_]{2,40}):([a-f0-9]{32}):([a-f0-9]{32})⟧$/;
const TOKEN_CANDIDATE = /⟦AG:[^⟧]{1,256}⟧/g;
const KEY_VERSION = "local-v1";

export interface TokenScope {
  principal: Principal;
  sessionId: string;
  purpose: string;
  requestId: string;
  policyVersion: string;
}

interface TokenRecord {
  tokenId: string;
  tenantId: string;
  userId: string;
  sessionId: string;
  applicationId: string;
  entityType: EntityType;
  encryptedOriginalValue: string;
  iv: string;
  authTag: string;
  keyVersion: string;
  purpose: string;
  sourceType: "PROMPT" | "RAG_DOCUMENT";
  sourceDocumentId?: string;
  requestId: string;
  policyVersion: string;
  createdAt: Date;
  expiresAt: Date;
  consumedAt?: Date;
  allowedRehydrationCount: number;
  rehydrationCount: number;
  integrityMetadata: string;
}

export interface TokenizationResult {
  sanitizedText: string;
  issuedTokens: Set<string>;
  tokenById: Map<string, string>;
}

interface ParsedToken {
  raw: string;
  entityType: EntityType;
  tokenId: string;
  authTag: string;
}

@Injectable()
export class TokenVaultService {
  private readonly records = new Map<string, TokenRecord>();
  private readonly kms: KmsAdapter;
  private lookupCount = 0;

  constructor() {
    this.kms = new LocalDevelopmentKms();
  }

  tokenize(
    text: string,
    findings: DetectionFinding[],
    scope: TokenScope,
    ttlSeconds: number,
    oneTime = false,
  ): TokenizationResult {
    const reusable = new Map<string, string>();
    const issuedTokens = new Set<string>();
    const tokenById = new Map<string, string>();
    let sanitizedText = text;
    const tokenizable = findings
      .filter((finding) => !finding.credential)
      .sort((left, right) => right.start - left.start);

    for (const finding of tokenizable) {
      const reuseKey = `${finding.type}\0${finding.value}`;
      let token = reusable.get(reuseKey);
      if (!token) {
        token = this.issueToken(finding, scope, ttlSeconds, oneTime);
        reusable.set(reuseKey, token);
      }
      const parsed = this.parseToken(token);
      issuedTokens.add(parsed.tokenId);
      tokenById.set(parsed.tokenId, token);
      sanitizedText = `${sanitizedText.slice(0, finding.start)}${token}${sanitizedText.slice(finding.end)}`;
    }
    return { sanitizedText, issuedTokens, tokenById };
  }

  extractCandidates(text: string): string[] {
    return Array.from(text.matchAll(TOKEN_CANDIDATE), (match) => match[0]);
  }

  parseToken(raw: string): ParsedToken {
    if (raw.length > 180) {
      throw this.tokenError(
        "AG_POLICY_TOKEN_MALFORMED",
        "The response contained a malformed token",
      );
    }
    const match = TOKEN_PATTERN.exec(raw);
    if (!match) {
      throw this.tokenError(
        "AG_POLICY_TOKEN_MALFORMED",
        "The response contained a malformed token",
      );
    }
    const [, entityType, tokenId, authTag] = match;
    if (
      !entityType ||
      !tokenId ||
      !authTag ||
      !ENTITY_TYPES.includes(entityType as EntityType)
    ) {
      throw this.tokenError(
        "AG_POLICY_TOKEN_MALFORMED",
        "The response contained a malformed token",
      );
    }
    return { raw, entityType: entityType as EntityType, tokenId, authTag };
  }

  rehydrateToken(
    raw: string,
    scope: TokenScope,
    authorizedTokenIds: Set<string>,
  ): string {
    const parsed = this.parseToken(raw);
    if (!authorizedTokenIds.has(parsed.tokenId)) {
      throw this.tokenError(
        "AG_POLICY_UNKNOWN_TOKEN",
        "The response contained a token that was not issued for this request",
      );
    }
    const expectedMac = this.createTokenMac(
      parsed.entityType,
      parsed.tokenId,
      scope,
    );
    const supplied = Buffer.from(parsed.authTag, "hex");
    const expected = Buffer.from(expectedMac, "hex");
    if (
      supplied.length !== expected.length ||
      !timingSafeEqual(supplied, expected)
    ) {
      throw this.tokenError(
        "AG_POLICY_TOKEN_TAMPERED",
        "The response contained a modified token",
      );
    }

    this.lookupCount += 1;
    const record = this.records.get(
      this.recordKey(scope.principal.tenantId, parsed.tokenId),
    );
    if (!record) {
      throw this.tokenError(
        "AG_POLICY_UNKNOWN_TOKEN",
        "The token mapping is unavailable",
      );
    }
    this.assertRecordScope(record, scope, parsed.entityType);
    if (record.expiresAt.getTime() <= Date.now()) {
      throw this.tokenError("AG_POLICY_TOKEN_EXPIRED", "The token has expired");
    }
    if (record.rehydrationCount >= record.allowedRehydrationCount) {
      throw this.tokenError(
        "AG_POLICY_TOKEN_REPLAYED",
        "The token cannot be used again",
      );
    }
    const plaintext = this.decrypt(record);
    record.rehydrationCount += 1;
    if (record.rehydrationCount >= record.allowedRehydrationCount)
      record.consumedAt = new Date();
    return plaintext;
  }

  authorizedIdsForRequest(tenantId: string, requestId: string): Set<string> {
    return new Set(
      Array.from(this.records.values())
        .filter(
          (record) =>
            record.tenantId === tenantId && record.requestId === requestId,
        )
        .map((record) => record.tokenId),
    );
  }

  getLookupCountForTest(): number {
    return this.lookupCount;
  }

  expireForTest(tenantId: string, tokenId: string): void {
    const record = this.records.get(this.recordKey(tenantId, tokenId));
    if (record) record.expiresAt = new Date(0);
  }

  private issueToken(
    finding: DetectionFinding,
    scope: TokenScope,
    ttlSeconds: number,
    oneTime: boolean,
  ): string {
    const tokenId = randomBytes(16).toString("hex");
    const authTag = this.createTokenMac(finding.type, tokenId, scope);
    const token = `⟦AG:v1:${finding.type}:${tokenId}:${authTag}⟧`;
    const encrypted = this.encrypt(finding.value, finding.type, tokenId, scope);
    const now = new Date();
    this.records.set(this.recordKey(scope.principal.tenantId, tokenId), {
      tokenId,
      tenantId: scope.principal.tenantId,
      userId: scope.principal.userId,
      sessionId: scope.sessionId,
      applicationId: scope.principal.applicationId,
      entityType: finding.type,
      encryptedOriginalValue: encrypted.ciphertext,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      keyVersion: KEY_VERSION,
      purpose: scope.purpose,
      sourceType: "PROMPT",
      requestId: scope.requestId,
      policyVersion: scope.policyVersion,
      createdAt: now,
      expiresAt: new Date(now.getTime() + ttlSeconds * 1_000),
      allowedRehydrationCount: oneTime ? 1 : 10,
      rehydrationCount: 0,
      integrityMetadata: "AES-256-GCM+AAD",
    });
    return token;
  }

  private createTokenMac(
    entityType: EntityType,
    tokenId: string,
    scope: TokenScope,
  ): string {
    const key = this.kms.getTenantMacKey(scope.principal.tenantId, KEY_VERSION);
    return createHmac("sha256", key)
      .update(
        [
          "v1",
          entityType,
          tokenId,
          scope.principal.tenantId,
          scope.sessionId,
          scope.purpose,
          scope.policyVersion,
        ].join("\0"),
      )
      .digest("hex")
      .slice(0, 32);
  }

  private encrypt(
    plaintext: string,
    entityType: EntityType,
    tokenId: string,
    scope: TokenScope,
  ): { ciphertext: string; iv: string; authTag: string } {
    const iv = randomBytes(12);
    const cipher = createCipheriv(
      "aes-256-gcm",
      this.kms.getTenantDek(scope.principal.tenantId, KEY_VERSION),
      iv,
    );
    cipher.setAAD(
      this.aad(
        scope.principal.tenantId,
        tokenId,
        entityType,
        scope.purpose,
        scope.policyVersion,
      ),
    );
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    return {
      ciphertext: ciphertext.toString("base64"),
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
    };
  }

  private decrypt(record: TokenRecord): string {
    try {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        this.kms.getTenantDek(record.tenantId, record.keyVersion),
        Buffer.from(record.iv, "base64"),
      );
      decipher.setAAD(
        this.aad(
          record.tenantId,
          record.tokenId,
          record.entityType,
          record.purpose,
          record.policyVersion,
        ),
      );
      decipher.setAuthTag(Buffer.from(record.authTag, "base64"));
      return Buffer.concat([
        decipher.update(Buffer.from(record.encryptedOriginalValue, "base64")),
        decipher.final(),
      ]).toString("utf8");
    } catch {
      throw this.tokenError(
        "AG_POLICY_TOKEN_INTEGRITY_FAILED",
        "Token integrity validation failed",
      );
    }
  }

  private assertRecordScope(
    record: TokenRecord,
    scope: TokenScope,
    entityType: EntityType,
  ): void {
    if (record.tenantId !== scope.principal.tenantId) {
      throw this.tokenError(
        "AG_POLICY_CROSS_TENANT_DENIED",
        "Token scope is invalid",
      );
    }
    if (record.userId !== scope.principal.userId) {
      throw this.tokenError(
        "AG_POLICY_CROSS_USER_DENIED",
        "Token scope is invalid",
      );
    }
    if (
      record.sessionId !== scope.sessionId ||
      record.purpose !== scope.purpose ||
      record.applicationId !== scope.principal.applicationId ||
      record.policyVersion !== scope.policyVersion ||
      record.requestId !== scope.requestId ||
      record.entityType !== entityType
    ) {
      throw this.tokenError(
        "AG_POLICY_TOKEN_SCOPE_DENIED",
        "Token scope is invalid",
      );
    }
  }

  private aad(
    tenantId: string,
    tokenId: string,
    entityType: EntityType,
    purpose: string,
    policyVersion: string,
  ): Buffer {
    return Buffer.from(
      [tenantId, tokenId, entityType, purpose, policyVersion].join("\0"),
    );
  }

  private recordKey(tenantId: string, tokenId: string): string {
    return `${tenantId}\0${tokenId}`;
  }

  private tokenError(reasonCode: string, message: string): SafeSecurityError {
    return new SafeSecurityError(reasonCode, 403, message);
  }
}
