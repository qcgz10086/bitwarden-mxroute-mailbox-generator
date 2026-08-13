import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import type { AdminIdentity } from "../../../packages/contracts/src/index";

export class AccessError extends Error {
  constructor(readonly status = 401) { super("UNAUTHORIZED"); }
}

export interface AccessConfig { readonly teamDomain: string; readonly audience: string; readonly adminEmails: string; }

export async function validateAccess(request: Request, config: AccessConfig, suppliedJwks?: JWTVerifyGetKey): Promise<AdminIdentity> {
  const assertion = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!assertion) throw new AccessError();
  const issuer = config.teamDomain.replace(/\/$/, "");
  const jwks = suppliedJwks ?? createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
  try {
    const { payload } = await jwtVerify(assertion, jwks, { issuer, audience: config.audience });
    if (typeof payload.sub !== "string" || payload.sub.length === 0 || typeof payload.email !== "string") throw new AccessError();
    const email = payload.email.toLowerCase();
    const allowed = config.adminEmails.split(",").map((value) => value.trim().toLowerCase()).filter(Boolean);
    if (allowed.length > 0 && !allowed.includes(email)) throw new AccessError();
    return { subject: payload.sub, email };
  } catch { throw new AccessError(); }
}
