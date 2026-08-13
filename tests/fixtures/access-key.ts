import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet } from "jose";

export async function accessFixture() {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = "test-key";
  const jwks: JSONWebKeySet = { keys: [publicJwk] };
  const issue = (claims: Record<string, unknown> = {}, options: { issuer?: string; audience?: string; expires?: string } = {}) =>
    new SignJWT({ email: "ADMIN@EXAMPLE.COM", ...claims })
      .setProtectedHeader({ alg: "RS256", kid: "test-key" })
      .setSubject("access-user")
      .setIssuer(options.issuer ?? "https://team.cloudflareaccess.com")
      .setAudience(options.audience ?? "admin-aud")
      .setIssuedAt()
      .setExpirationTime(options.expires ?? "5m")
      .sign(privateKey);
  return { privateKey, publicKey, jwks, issue };
}
