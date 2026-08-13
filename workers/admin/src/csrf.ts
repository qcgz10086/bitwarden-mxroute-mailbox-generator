const CSRF_COOKIE = "csrf";

export function createCsrfToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function csrfCookie(token: string): string {
  return `${CSRF_COOKIE}=${token}; Secure; HttpOnly; SameSite=Strict; Path=/`;
}

export function validateCsrf(request: Request, origin: string): boolean {
  if (request.headers.get("Origin") !== origin) return false;
  const header = request.headers.get("X-CSRF-Token") ?? "";
  const cookie = parseCookie(request.headers.get("Cookie") ?? "", CSRF_COOKIE) ?? "";
  return header.length === cookie.length && header.length > 0 && constantTimeEqual(header, cookie);
}

function parseCookie(value: string, name: string): string | undefined {
  for (const part of value.split(";")) {
    const index = part.indexOf("=");
    if (index >= 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return undefined;
}

function constantTimeEqual(left: string, right: string): boolean {
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return mismatch === 0;
}
