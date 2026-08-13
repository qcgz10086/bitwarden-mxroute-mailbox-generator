const FORBIDDEN = [
  { code: "EVAL", pattern: /\beval\s*\(/i },
  { code: "SOURCE_MAP", pattern: /sourceMappingURL/i },
  { code: "REMOTE_OR_ACTIVE_SCHEME", pattern: /(?:\b(?:https?|wss?|ftp|data|javascript|vbscript|blob|file|ipfs|chrome-extension):|(?:^|[\s"'(=])\/\/)/i },
  { code: "RUNTIME_IMPORT", pattern: /\bimport\s*(?:\(|[^;]*?\bfrom\s*)/i },
  { code: "SECRET_MARKER", pattern: /MXROUTE_API_KEY|TOKEN_PEPPER|ENC_KEY_V\d|Cf-Access-Jwt-Assertion|Authentication\s*:/i },
];

export function findUnsafeAssetContent(content) {
  return FORBIDDEN.find((rule) => rule.pattern.test(content))?.code ?? null;
}
