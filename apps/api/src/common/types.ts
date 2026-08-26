export const ENTITY_TYPES = [
  "PERSON",
  "EMAIL_ADDRESS",
  "PHONE_NUMBER",
  "KR_PHONE_NUMBER",
  "KR_RRN",
  "KR_PASSPORT",
  "CREDIT_CARD",
  "BANK_ACCOUNT",
  "ADDRESS",
  "DATE_OF_BIRTH",
  "IP_ADDRESS",
  "CUSTOMER_ID",
  "EMPLOYEE_ID",
  "MEDICAL_RECORD_ID",
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
  "PROPRIETARY_SOURCE_CODE",
  "INTERNAL_PROJECT_NAME",
  "CONFIDENTIAL_DOCUMENT",
  "FINANCIAL_FORECAST",
  "LEGAL_PRIVILEGED_CONTENT",
  "INTERNAL_HOSTNAME",
] as const;

export type EntityType = (typeof ENTITY_TYPES)[number];
export type DataClass =
  "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED" | "CREDENTIAL";
export type PolicyAction =
  | "ALLOW"
  | "TOKENIZE_AND_ALLOW"
  | "MASK_IRREVERSIBLY"
  | "REQUIRE_USER_CONFIRMATION"
  | "ROUTE_TO_PRIVATE_MODEL"
  | "REQUIRE_ATTESTED_MODEL"
  | "BLOCK"
  | "BLOCK_AND_ALERT";
export type TrustLevel =
  "PUBLIC_EXTERNAL" | "ENTERPRISE_MANAGED" | "PRIVATE_VPC" | "ATTESTED_TEE";

export interface Principal {
  tenantId: string;
  userId: string;
  role:
    | "tenant_admin"
    | "security_admin"
    | "security_analyst"
    | "developer"
    | "end_user"
    | "rehydration_service";
  applicationId: string;
}

export interface DetectionFinding {
  type: EntityType;
  start: number;
  end: number;
  confidence: number;
  source: string;
  value: string;
  credential: boolean;
}

export type SafeFinding = Omit<DetectionFinding, "value">;

export interface PolicyDecision {
  id: string;
  action: PolicyAction;
  reasonCode: string;
  policyId: string;
  policyVersion: string;
  minimumTrust: TrustLevel;
  allowRehydration: boolean;
  requireAttestationForRehydration: boolean;
}

export interface ProviderMetadata {
  providerId: string;
  displayName: string;
  endpoint: string;
  trustLevel: TrustLevel;
  allowedDataClasses: DataClass[];
  allowedRegions: string[];
  supportsStreaming: boolean;
  supportsTools: boolean;
  supportsStructuredOutput: boolean;
  requiresAttestation: boolean;
  enabled: boolean;
  simulated: boolean;
}

export interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
}
