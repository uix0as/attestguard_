import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import type { Request } from "express";
import { verify } from "jsonwebtoken";
import type { Principal } from "../common/types";

interface JwtClaims {
  sub?: string;
  tenant_id?: string;
  role?: Principal["role"];
  application_id?: string;
}

export interface AuthenticatedRequest extends Request {
  principal: Principal;
  requestId: string;
}

const ROLES: Principal["role"][] = [
  "tenant_admin",
  "security_admin",
  "security_analyst",
  "developer",
  "end_user",
  "rehydration_service",
];

@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    if (request.path === "/health" || request.path === "/ready") {
      return true;
    }

    const authorization = request.header("authorization");
    if (!authorization?.startsWith("Bearer ")) {
      throw new UnauthorizedException("A bearer token is required");
    }

    const secret = process.env.JWT_SECRET;
    if (!secret || secret.length < 32) {
      throw new UnauthorizedException("Authentication is not configured");
    }

    let claims: JwtClaims;
    try {
      claims = verify(authorization.slice(7), secret, {
        algorithms: ["HS256"],
        audience: "attestguard-api",
        issuer: "attestguard-dev",
      }) as JwtClaims;
    } catch {
      throw new UnauthorizedException("The bearer token is invalid or expired");
    }

    if (
      !claims.sub ||
      !claims.tenant_id ||
      !claims.application_id ||
      !claims.role ||
      !ROLES.includes(claims.role)
    ) {
      throw new UnauthorizedException("Required identity claims are missing");
    }

    const authenticated = request as AuthenticatedRequest;
    authenticated.principal = {
      tenantId: claims.tenant_id,
      userId: claims.sub,
      role: claims.role,
      applicationId: claims.application_id,
    };
    authenticated.requestId =
      request.header("x-request-id") ?? crypto.randomUUID();
    return true;
  }
}
