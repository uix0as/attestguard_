export class SafeSecurityError extends Error {
  constructor(
    readonly reasonCode: string,
    readonly statusCode: number,
    message: string,
  ) {
    super(message);
    this.name = "SafeSecurityError";
  }
}
