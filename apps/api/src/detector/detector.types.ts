import type { DetectionFinding, EntityType } from "../common/types";

export const CREDENTIAL_TYPES = new Set<EntityType>([
  "AWS_ACCESS_KEY",
  "AWS_SECRET_KEY",
  "GITHUB_TOKEN",
  "GENERIC_API_KEY",
  "JWT",
  "PRIVATE_KEY",
  "DATABASE_URI",
  "PASSWORD_IN_CONFIG",
  "KUBERNETES_SECRET",
  "SESSION_COOKIE",
  "OAUTH_TOKEN",
]);

export interface CredentialDetector {
  scan(text: string): Promise<DetectionFinding[]>;
}
