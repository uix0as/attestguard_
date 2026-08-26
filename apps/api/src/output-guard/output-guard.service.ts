import { Injectable } from "@nestjs/common";
import { SafeSecurityError } from "../common/safe-error";
import type { DetectionFinding } from "../common/types";
import type { TokenScope } from "../token-vault/token-vault.service";
import { TokenVaultService } from "../token-vault/token-vault.service";

@Injectable()
export class OutputGuardService {
  constructor(private readonly vault: TokenVaultService) {}

  rehydrateAuthorized(
    content: string,
    scope: TokenScope,
    authorizedTokenIds: Set<string>,
    allowRehydration: boolean,
  ): string {
    const candidates = this.vault.extractCandidates(content);
    const candidateFree = candidates.reduce(
      (remaining, token) => remaining.replace(token, ""),
      content,
    );
    if (candidateFree.includes("⟦AG:")) {
      throw new SafeSecurityError(
        "AG_POLICY_TOKEN_MALFORMED",
        403,
        "The model response contained an incomplete or oversized security token",
      );
    }
    for (const candidate of candidates) this.vault.parseToken(candidate);
    if (!allowRehydration) return content;
    let authorized = content;
    for (const candidate of candidates) {
      const plaintext = this.vault.rehydrateToken(
        candidate,
        scope,
        authorizedTokenIds,
      );
      authorized = authorized.replaceAll(candidate, plaintext);
    }
    return authorized;
  }

  assertToolArgumentsSafe(findings: DetectionFinding[]): void {
    if (findings.some((finding) => finding.credential)) {
      throw new SafeSecurityError(
        "AG_POLICY_TOOL_CREDENTIAL_BLOCKED",
        403,
        "A tool call attempted to transmit credential material",
      );
    }
  }
}
