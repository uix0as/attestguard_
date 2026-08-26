import { Module } from "@nestjs/common";
import { ApiController } from "./api/api.controller";
import { InternalController } from "./api/internal.controller";
import { AuditService } from "./audit/audit.service";
import { AuthGuard } from "./auth/auth.guard";
import { AttestationService } from "./attestation/attestation.service";
import { ClassifierService } from "./classifier/classifier.service";
import { DetectorService } from "./detector/detector.service";
import { JavaCredentialDetector } from "./detector/java-credential-detector";
import { GatewayService } from "./gateway/gateway.service";
import { OutputGuardService } from "./output-guard/output-guard.service";
import { PolicyService } from "./policy/policy.service";
import { MockProvider } from "./providers/mock.provider";
import { ProviderRegistry } from "./providers/provider.registry";
import { TokenVaultService } from "./token-vault/token-vault.service";

@Module({
  controllers: [ApiController, InternalController],
  providers: [
    AuthGuard,
    AuditService,
    AttestationService,
    ClassifierService,
    JavaCredentialDetector,
    DetectorService,
    PolicyService,
    TokenVaultService,
    MockProvider,
    ProviderRegistry,
    OutputGuardService,
    GatewayService,
  ],
})
export class AppModule {}
