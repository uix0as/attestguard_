import { Injectable } from "@nestjs/common";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import type { EntityType, PolicyAction, Principal } from "../common/types";

export interface SecurityEvent {
  eventId: string;
  timestamp: string;
  tenantId: string;
  userIdHash: string;
  applicationId: string;
  requestId: string;
  eventType: string;
  entityTypes: EntityType[];
  entityCount: number;
  policyId: string;
  policyVersion: string;
  decision: PolicyAction;
  providerRequested: string;
  providerSelected?: string;
  attestationResult: "SIMULATED" | "NOT_REQUIRED" | "FAILED";
  latencyMs: number;
  previousEventHash: string;
  eventHash: string;
}

type EventInput = Omit<
  SecurityEvent,
  | "eventId"
  | "timestamp"
  | "userIdHash"
  | "previousEventHash"
  | "eventHash"
  | "tenantId"
  | "applicationId"
> & { principal: Principal };

@Injectable()
export class AuditService {
  private readonly events: SecurityEvent[] = [];
  private readonly userHashKey = randomBytes(32);

  append(input: EventInput): SecurityEvent {
    const previousEventHash = this.events.at(-1)?.eventHash ?? "GENESIS";
    const { principal, ...safeInput } = input;
    const unsigned = {
      ...safeInput,
      eventId: randomUUID(),
      timestamp: new Date().toISOString(),
      tenantId: principal.tenantId,
      userIdHash: createHmac("sha256", this.userHashKey)
        .update(`${principal.tenantId}\0${principal.userId}`)
        .digest("hex"),
      applicationId: principal.applicationId,
      previousEventHash,
    };
    const event: SecurityEvent = {
      ...unsigned,
      eventHash: this.hash(unsigned),
    };
    this.events.push(event);
    return { ...event };
  }

  list(tenantId: string): SecurityEvent[] {
    return this.events
      .filter((event) => event.tenantId === tenantId)
      .map((event) => ({ ...event }));
  }

  verify(): { valid: boolean; checkedEvents: number } {
    let previous = "GENESIS";
    for (const event of this.events) {
      const { eventHash, ...unsigned } = event;
      if (
        unsigned.previousEventHash !== previous ||
        this.hash(unsigned) !== eventHash
      ) {
        return { valid: false, checkedEvents: this.events.indexOf(event) + 1 };
      }
      previous = eventHash;
    }
    return { valid: true, checkedEvents: this.events.length };
  }

  private hash(value: object): string {
    return createHash("sha256").update(JSON.stringify(value)).digest("hex");
  }
}
