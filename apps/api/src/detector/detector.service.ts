import { Injectable } from "@nestjs/common";
import type {
  DetectionFinding,
  EntityType,
  SafeFinding,
} from "../common/types";
import { CREDENTIAL_TYPES } from "./detector.types";
import { JavaCredentialDetector } from "./java-credential-detector";

interface Pattern {
  type: EntityType;
  regex: RegExp;
  confidence: number;
  source: string;
  validate?: (value: string) => boolean;
}

interface NormalizedText {
  text: string;
  startMap: number[];
  endMap: number[];
}

const PATTERNS: Pattern[] = [
  {
    type: "PRIVATE_KEY",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    confidence: 1,
    source: "secret-regex",
  },
  {
    type: "AWS_ACCESS_KEY",
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    confidence: 0.99,
    source: "secret-regex",
  },
  {
    type: "GITHUB_TOKEN",
    regex: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,255}\b/g,
    confidence: 0.99,
    source: "secret-regex",
  },
  {
    type: "JWT",
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    confidence: 0.98,
    source: "secret-regex",
  },
  {
    type: "DATABASE_URI",
    regex:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:/]+:[^\s@]+@[^\s]+/gi,
    confidence: 0.99,
    source: "secret-regex",
  },
  {
    type: "AWS_SECRET_KEY",
    regex:
      /(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}['"]?/gi,
    confidence: 0.99,
    source: "context-secret",
  },
  {
    type: "PASSWORD_IN_CONFIG",
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"\r\n]{8,}['"]/gi,
    confidence: 0.95,
    source: "context-secret",
  },
  {
    type: "OAUTH_TOKEN",
    regex:
      /(?:refresh_token|oauth_token)\s*[:=]\s*['"]?[A-Za-z0-9._~-]{20,}['"]?/gi,
    confidence: 0.96,
    source: "context-secret",
  },
  {
    type: "EMAIL_ADDRESS",
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    confidence: 0.99,
    source: "structured-regex",
  },
  {
    type: "KR_PHONE_NUMBER",
    regex: /(?<!\d)01[016789][ -]?\d{3,4}[ -]?\d{4}(?!\d)/g,
    confidence: 0.99,
    source: "kr-recognizer",
  },
  {
    type: "KR_RRN",
    regex: /(?<!\d)\d{6}[ -]?[1-4]\d{6}(?!\d)/g,
    confidence: 0.99,
    source: "kr-checksum",
    validate: isValidKoreanRrn,
  },
  {
    type: "CREDIT_CARD",
    regex: /(?<!\d)(?:\d[ -]?){13,19}(?!\d)/g,
    confidence: 0.98,
    source: "luhn-checksum",
    validate: isValidLuhn,
  },
  {
    type: "IP_ADDRESS",
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    confidence: 0.8,
    source: "structured-regex",
    validate: isValidIpv4,
  },
  {
    type: "INTERNAL_HOSTNAME",
    regex: /\b[a-z0-9][a-z0-9.-]*\.(?:internal|corp|local)\b/gi,
    confidence: 0.9,
    source: "enterprise-context",
  },
  {
    type: "PROPRIETARY_SOURCE_CODE",
    regex:
      /(?:package\s+[a-z][\w.]+;|class\s+[A-Z]\w+\s*\{|function\s+\w+\s*\([^)]*\)\s*\{)/g,
    confidence: 0.82,
    source: "source-code-aware",
  },
  {
    type: "PERSON",
    regex: /[가-힣]{2,4}(?=\s*(?:고객|님|씨))/g,
    confidence: 0.78,
    source: "local-context",
  },
];

const PRIORITY = new Map<EntityType, number>([
  ...Array.from(CREDENTIAL_TYPES).map((type): [EntityType, number] => [
    type,
    100,
  ]),
  ["KR_RRN", 80],
  ["CREDIT_CARD", 80],
  ["EMAIL_ADDRESS", 70],
  ["KR_PHONE_NUMBER", 70],
  ["PROPRIETARY_SOURCE_CODE", 40],
  ["PERSON", 30],
]);

@Injectable()
export class DetectorService {
  constructor(private readonly javaDetector: JavaCredentialDetector) {}

  async scan(text: string): Promise<DetectionFinding[]> {
    const [javaFindings, localFindings] = await Promise.all([
      this.javaDetector.scan(text),
      Promise.resolve(this.scanLocally(text)),
    ]);
    return resolveOverlaps([...javaFindings, ...localFindings]);
  }

  toSafeFindings(findings: DetectionFinding[]): SafeFinding[] {
    return findings.map((finding) => ({
      type: finding.type,
      start: finding.start,
      end: finding.end,
      confidence: finding.confidence,
      source: finding.source,
      credential: finding.credential,
    }));
  }

  private scanLocally(original: string): DetectionFinding[] {
    const normalized = normalizeWithOffsetMap(original);
    const findings: DetectionFinding[] = [];
    for (const pattern of PATTERNS) {
      pattern.regex.lastIndex = 0;
      for (const match of normalized.text.matchAll(pattern.regex)) {
        const normalizedStart = match.index;
        const normalizedEnd = normalizedStart + match[0].length;
        const start = normalized.startMap[normalizedStart];
        const end = normalized.endMap[normalizedEnd - 1];
        if (start === undefined || end === undefined) continue;
        const value = original.slice(start, end);
        if (pattern.validate && !pattern.validate(value)) continue;
        findings.push({
          type: pattern.type,
          start,
          end,
          confidence: pattern.confidence,
          source: pattern.source,
          value,
          credential: CREDENTIAL_TYPES.has(pattern.type),
        });
      }
    }
    return findings;
  }
}

function normalizeWithOffsetMap(original: string): NormalizedText {
  let text = "";
  const startMap: number[] = [];
  const endMap: number[] = [];
  let offset = 0;
  for (const character of original) {
    const normalized = character.normalize("NFKC");
    for (const normalizedCharacter of normalized) {
      for (let index = 0; index < normalizedCharacter.length; index += 1) {
        startMap.push(offset);
        endMap.push(offset + character.length);
      }
      text += normalizedCharacter;
    }
    offset += character.length;
  }
  return { text, startMap, endMap };
}

function resolveOverlaps(findings: DetectionFinding[]): DetectionFinding[] {
  const sorted = [...findings].sort((left, right) => {
    const priority =
      (PRIORITY.get(right.type) ?? 10) - (PRIORITY.get(left.type) ?? 10);
    if (priority !== 0) return priority;
    const length = right.end - right.start - (left.end - left.start);
    if (length !== 0) return length;
    return right.confidence - left.confidence;
  });
  const accepted: DetectionFinding[] = [];
  for (const finding of sorted) {
    const duplicate = accepted.some(
      (existing) =>
        existing.start === finding.start &&
        existing.end === finding.end &&
        existing.type === finding.type,
    );
    const overlap = accepted.some(
      (existing) =>
        finding.start < existing.end && finding.end > existing.start,
    );
    if (!duplicate && !overlap) accepted.push(finding);
  }
  return accepted.sort((left, right) => left.start - right.start);
}

function digits(value: string): string {
  return value.replace(/\D/g, "");
}

function isValidLuhn(value: string): boolean {
  const sequence = digits(value);
  if (
    sequence.length < 13 ||
    sequence.length > 19 ||
    /^(\d)\1+$/.test(sequence)
  )
    return false;
  let sum = 0;
  let double = false;
  for (let index = sequence.length - 1; index >= 0; index -= 1) {
    const raw = sequence[index];
    if (raw === undefined) return false;
    let digit = Number(raw);
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

function isValidKoreanRrn(value: string): boolean {
  const sequence = digits(value);
  if (!/^\d{6}[1-4]\d{6}$/.test(sequence)) return false;
  const weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
  const checksum = weights.reduce(
    (sum, weight, index) => sum + Number(sequence[index]) * weight,
    0,
  );
  return (11 - (checksum % 11)) % 10 === Number(sequence[12]);
}

function isValidIpv4(value: string): boolean {
  return value
    .split(".")
    .every((part) => Number(part) >= 0 && Number(part) <= 255);
}
