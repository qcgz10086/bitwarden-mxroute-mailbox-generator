const PUBLIC_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
} as const;

export function publicResponseHeaders(requestId: string): Headers {
  return new Headers({
    ...PUBLIC_HEADERS,
    "X-Request-Id": requestId,
  });
}

export function preflightResponse(requestId: string): Response {
  const headers = publicResponseHeaders(requestId);
  headers.set("Access-Control-Allow-Headers", "Authentication, Content-Type");
  headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  headers.set("Access-Control-Max-Age", "600");
  return new Response(null, { status: 204, headers });
}
