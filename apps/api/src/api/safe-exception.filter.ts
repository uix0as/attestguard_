import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from "@nestjs/common";
import type { Request, Response } from "express";
import { SafeSecurityError } from "../common/safe-error";

@Catch()
export class SafeExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const request = http.getRequest<Request>();
    const response = http.getResponse<Response>();
    if (exception instanceof SafeSecurityError) {
      response.status(exception.statusCode).json({
        error: {
          message: exception.message,
          type: "attestguard_security_error",
          code: exception.reasonCode,
          request_id: request.header("x-request-id") ?? "generated-server-side",
        },
      });
      return;
    }
    if (exception instanceof HttpException) {
      response.status(exception.getStatus()).json({
        error: {
          message: "The request was rejected",
          type: "invalid_request_error",
          code: "AG_REQUEST_INVALID",
          request_id: request.header("x-request-id") ?? "generated-server-side",
        },
      });
      return;
    }
    response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
      error: {
        message: "The gateway failed safely without sending the request",
        type: "attestguard_internal_error",
        code: "AG_INTERNAL_FAIL_CLOSED",
        request_id: request.header("x-request-id") ?? "generated-server-side",
      },
    });
  }
}
