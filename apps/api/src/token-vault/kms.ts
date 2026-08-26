import { createHmac, randomBytes } from "node:crypto";

export interface KmsAdapter {
  getTenantDek(tenantId: string, keyVersion: string): Buffer;
  getTenantMacKey(tenantId: string, keyVersion: string): Buffer;
}

export class LocalDevelopmentKms implements KmsAdapter {
  private readonly rootKey: Buffer;

  constructor() {
    if (process.env.NODE_ENV === "production") {
      throw new Error("LocalDevelopmentKms is prohibited in production");
    }
    const configured = process.env.LOCAL_KMS_ROOT_KEY;
    this.rootKey = configured
      ? Buffer.from(configured, "base64")
      : randomBytes(32);
    if (this.rootKey.length !== 32) {
      throw new Error("LOCAL_KMS_ROOT_KEY must decode to exactly 32 bytes");
    }
  }

  getTenantDek(tenantId: string, keyVersion: string): Buffer {
    return this.derive("dek", tenantId, keyVersion);
  }

  getTenantMacKey(tenantId: string, keyVersion: string): Buffer {
    return this.derive("mac", tenantId, keyVersion);
  }

  private derive(kind: string, tenantId: string, keyVersion: string): Buffer {
    return createHmac("sha256", this.rootKey)
      .update(`attestguard:${kind}:${keyVersion}:${tenantId}`)
      .digest();
  }
}

export type AwsKmsAdapter = KmsAdapter;
export type AzureKeyVaultAdapter = KmsAdapter;
export type GcpKmsAdapter = KmsAdapter;
