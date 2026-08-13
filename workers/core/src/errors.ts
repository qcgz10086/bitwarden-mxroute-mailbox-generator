export type ServiceErrorCode =
  | "MX_CLIENT"
  | "MX_UNAUTHORIZED"
  | "MX_NOT_FOUND"
  | "MX_CONFLICT"
  | "MX_RATE_LIMITED"
  | "MX_SERVER"
  | "MX_TIMEOUT"
  | "MX_INVALID_RESPONSE";

export class ServiceError extends Error {
  constructor(readonly code: ServiceErrorCode) {
    super(code);
    this.name = "ServiceError";
  }
}
