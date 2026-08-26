import { Injectable } from "@nestjs/common";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "yaml";
import { SafeSecurityError } from "../common/safe-error";
import type {
  DataClass,
  EntityType,
  PolicyAction,
  PolicyDecision,
  TrustLevel,
} from "../common/types";

interface PolicyRule {
  id: string;
  priority: number;
  when: { entity_types?: EntityType[]; data_class?: DataClass[] };
  action: PolicyAction;
  minimum_provider_trust?: TrustLevel;
  require_attestation_for_rehydration?: boolean;
}

interface PolicyDocument {
  version: string;
  defaults: {
    failure_mode: "closed";
    token_ttl_seconds: number;
    minimum_provider_trust: TrustLevel;
    allow_rehydration: boolean;
  };
  rules: PolicyRule[];
}

const ACTIONS: PolicyAction[] = [
  "ALLOW",
  "TOKENIZE_AND_ALLOW",
  "MASK_IRREVERSIBLY",
  "REQUIRE_USER_CONFIRMATION",
  "ROUTE_TO_PRIVATE_MODEL",
  "REQUIRE_ATTESTED_MODEL",
  "BLOCK",
  "BLOCK_AND_ALERT",
];
const TRUST_LEVELS: TrustLevel[] = [
  "PUBLIC_EXTERNAL",
  "ENTERPRISE_MANAGED",
  "PRIVATE_VPC",
  "ATTESTED_TEE",
];

@Injectable()
export class PolicyService {
  private readonly policy: PolicyDocument | undefined;

  constructor() {
    try {
      this.policy = this.loadPolicy();
    } catch {
      this.policy = undefined;
    }
  }

  isReady(): boolean {
    return this.policy !== undefined;
  }

  tokenTtlSeconds(): number {
    return this.requirePolicy().defaults.token_ttl_seconds;
  }

  evaluate(dataClass: DataClass, entityTypes: EntityType[]): PolicyDecision {
    const policy = this.requirePolicy();
    const entitySet = new Set(entityTypes);
    const matches = policy.rules
      .filter((rule) => {
        const entityMatch =
          rule.when.entity_types?.some((type) => entitySet.has(type)) ?? false;
        const classMatch = rule.when.data_class?.includes(dataClass) ?? false;
        return entityMatch || classMatch;
      })
      .sort((left, right) => {
        const priority = right.priority - left.priority;
        if (priority !== 0) return priority;
        const deny = Number(isDeny(right.action)) - Number(isDeny(left.action));
        if (deny !== 0) return deny;
        return specificity(right) - specificity(left);
      });

    const rule = matches[0];
    if (!rule) {
      throw new SafeSecurityError(
        "AG_POLICY_NO_MATCH_FAIL_CLOSED",
        403,
        "No policy rule safely allowed this request",
      );
    }
    return {
      id: randomUUID(),
      action: rule.action,
      reasonCode: reasonCodeFor(rule.action),
      policyId: rule.id,
      policyVersion: policy.version,
      minimumTrust:
        rule.minimum_provider_trust ?? policy.defaults.minimum_provider_trust,
      allowRehydration:
        policy.defaults.allow_rehydration && !isDeny(rule.action),
      requireAttestationForRehydration:
        rule.require_attestation_for_rehydration ?? false,
    };
  }

  private requirePolicy(): PolicyDocument {
    if (!this.policy) {
      throw new SafeSecurityError(
        "AG_POLICY_CONFIGURATION_INVALID",
        503,
        "Policy configuration is unavailable; the request was not sent",
      );
    }
    return this.policy;
  }

  private loadPolicy(): PolicyDocument {
    const candidates = [
      process.env.POLICY_FILE,
      resolve(process.cwd(), "policies/default.yaml"),
      resolve(process.cwd(), "../../policies/default.yaml"),
    ].filter((candidate): candidate is string => Boolean(candidate));
    let raw: string | undefined;
    for (const candidate of candidates) {
      try {
        raw = readFileSync(candidate, "utf8");
        break;
      } catch {
        continue;
      }
    }
    if (!raw) throw new Error("Policy file not found");
    const value = parse(raw) as Partial<PolicyDocument>;
    if (
      typeof value.version !== "string" ||
      value.defaults?.failure_mode !== "closed" ||
      !Number.isInteger(value.defaults.token_ttl_seconds) ||
      !TRUST_LEVELS.includes(value.defaults.minimum_provider_trust) ||
      typeof value.defaults.allow_rehydration !== "boolean" ||
      !Array.isArray(value.rules) ||
      value.rules.length === 0
    ) {
      throw new Error("Invalid policy document");
    }
    for (const rule of value.rules) {
      if (
        typeof rule.id !== "string" ||
        !Number.isInteger(rule.priority) ||
        !ACTIONS.includes(rule.action) ||
        !rule.when ||
        (rule.minimum_provider_trust &&
          !TRUST_LEVELS.includes(rule.minimum_provider_trust))
      ) {
        throw new Error("Invalid policy rule");
      }
    }
    return value as PolicyDocument;
  }
}

function isDeny(action: PolicyAction): boolean {
  return action === "BLOCK" || action === "BLOCK_AND_ALERT";
}

function specificity(rule: PolicyRule): number {
  return (
    (rule.when.entity_types?.length ?? 0) + (rule.when.data_class?.length ?? 0)
  );
}

function reasonCodeFor(action: PolicyAction): string {
  switch (action) {
    case "BLOCK":
    case "BLOCK_AND_ALERT":
      return "AG_POLICY_SECRET_BLOCKED";
    case "ROUTE_TO_PRIVATE_MODEL":
      return "AG_POLICY_PRIVATE_MODEL_REQUIRED";
    case "REQUIRE_ATTESTED_MODEL":
      return "AG_POLICY_ATTESTED_MODEL_REQUIRED";
    case "TOKENIZE_AND_ALLOW":
      return "AG_POLICY_PSEUDONYMIZATION_REQUIRED";
    default:
      return "AG_POLICY_ALLOWED";
  }
}
