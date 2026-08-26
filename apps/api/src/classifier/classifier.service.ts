import { Injectable } from "@nestjs/common";
import type { DataClass, DetectionFinding } from "../common/types";

@Injectable()
export class ClassifierService {
  classify(text: string, findings: DetectionFinding[]): DataClass {
    if (findings.some((finding) => finding.credential)) return "CREDENTIAL";
    if (/\b(?:top secret|restricted|최고기밀|대외비)\b/i.test(text))
      return "RESTRICTED";
    if (
      findings.some((finding) =>
        [
          "PROPRIETARY_SOURCE_CODE",
          "CONFIDENTIAL_DOCUMENT",
          "INTERNAL_HOSTNAME",
        ].includes(finding.type),
      ) ||
      /\b(?:confidential|attorney.client privileged|financial forecast|영업비밀|비공개 프로젝트)\b/i.test(
        text,
      )
    ) {
      return "CONFIDENTIAL";
    }
    if (findings.length > 0) return "INTERNAL";
    return "PUBLIC";
  }
}
