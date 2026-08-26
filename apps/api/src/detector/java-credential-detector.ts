import { Injectable } from "@nestjs/common";
import { SafeSecurityError } from "../common/safe-error";
import {
  ENTITY_TYPES,
  type DetectionFinding,
  type EntityType,
} from "../common/types";
import type { CredentialDetector } from "./detector.types";

interface JavaFinding {
  type: string;
  start: number;
  end: number;
  confidence: number;
  source: string;
}

@Injectable()
export class JavaCredentialDetector implements CredentialDetector {
  async scan(text: string): Promise<DetectionFinding[]> {
    const endpoint = process.env.JAVA_DETECTOR_URL ?? "http://localhost:8090";
    const required = process.env.JAVA_DETECTOR_REQUIRED !== "false";
    try {
      const response = await fetch(`${endpoint}/scan`, {
        method: "POST",
        headers: { "content-type": "text/plain; charset=utf-8" },
        body: text,
        signal: AbortSignal.timeout(1_500),
      });
      if (!response.ok) {
        throw new Error(`detector status ${response.status}`);
      }
      const payload = (await response.json()) as { findings?: JavaFinding[] };
      return (payload.findings ?? []).flatMap((finding): DetectionFinding[] => {
        if (!this.validFinding(finding, text.length)) return [];
        return [
          {
            ...finding,
            type: finding.type as EntityType,
            value: text.slice(finding.start, finding.end),
            credential: true,
          },
        ];
      });
    } catch {
      if (required) {
        throw new SafeSecurityError(
          "AG_POLICY_DETECTOR_UNAVAILABLE",
          503,
          "The high-priority credential detector is unavailable; the request was not sent",
        );
      }
      return [];
    }
  }

  private validFinding(finding: JavaFinding, textLength: number): boolean {
    return (
      ENTITY_TYPES.includes(finding.type as EntityType) &&
      Number.isInteger(finding.start) &&
      Number.isInteger(finding.end) &&
      finding.start >= 0 &&
      finding.end > finding.start &&
      finding.end <= textLength &&
      finding.confidence >= 0 &&
      finding.confidence <= 1 &&
      finding.source === "java-secret-scanner"
    );
  }
}
