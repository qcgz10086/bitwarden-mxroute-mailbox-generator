# Bitwarden MXroute Mailbox Generator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Cloudflare Workers service that lets unmodified Bitwarden clients create real MXroute mailboxes while keeping each independent 18-character password encrypted and manageable behind Cloudflare Access.

**Architecture:** A public Generator Worker implements the minimum SimpleLogin endpoint, an Access-protected Admin Worker serves the management UI, and a non-public Core Worker owns D1, encryption keys, API-token verification, MXroute access, state machines, and recovery jobs. Generator and Admin call Core only through typed Cloudflare Service Binding RPC.

**Tech Stack:** TypeScript, Cloudflare Workers, WorkerEntrypoint RPC, D1/SQLite migrations, Web Crypto, `jose`, Vitest 4.1+, `@cloudflare/vitest-pool-workers`, Wrangler, and a dependency-free HTML/CSS/TypeScript admin UI bundled with esbuild.

## Global Constraints

- The email local part is 12 characters generated from `23456789abcdefghjkmnpqrstuvwxyz`; it never uses request `hostname` or `mode` to select a name or domain.
- Each mailbox password is exactly 18 characters, independently generated, and contains at least one uppercase letter, one lowercase letter, and one digit.
- New mailboxes use the active default domain and a 100 MB quota unless an administrator changes the configured default.
- Bitwarden receives only the email address; no public response or log may contain a mailbox password, MXroute credential, raw API token, or authentication header.
- Mailbox passwords use AES-256-GCM with a unique 96-bit nonce and AAD `public_id|email|key_version`.
- Generator and Admin have no D1, MXroute, encryption-key, or token-pepper bindings.
- Core has no public route and `workers_dev` is false; all Core calls use Service Binding RPC.
- Admin verifies the Access JWT signature, issuer, audience, expiry, and allowed email, then enforces Origin and double-submit CSRF checks.
- No individual-mailbox disable action is exposed. The destructive action is permanent deletion with exact-email confirmation.
- D1 Time Travel retention is disclosed in the delete confirmation and operations documentation.
- Production secrets are entered through interactive Wrangler prompts or Secrets Store, never command-line values, source files, `.dev.vars` committed to Git, or logs.

## File Structure

```text
package.json                         npm scripts and dependency pins
package-lock.json                    reproducible dependency graph
tsconfig.json                        shared strict TypeScript settings
vitest.config.ts                     workerd unit-test projects
vitest.integration.config.ts         multi-Worker integration harness config
.gitignore                           local secrets, build output, Wrangler state
packages/contracts/src/index.ts      RPC DTOs, status values, and error envelopes
packages/security/src/random.ts      unbiased prefix/password/token generation
packages/security/src/crypto.ts      AES-GCM and HMAC primitives
workers/core/src/index.ts            private RPC entrypoint and scheduled recovery
workers/core/src/service.ts          orchestration and state transitions
workers/core/src/repository.ts       D1 queries and conditional state updates
workers/core/src/mxroute.ts          typed MXroute HTTP client
workers/core/src/errors.ts           normalized internal/upstream errors
workers/core/migrations/0001.sql     schema, indexes, limits, and triggers
workers/core/wrangler.jsonc          private Worker, D1, cron, required secrets
workers/generator/src/index.ts       SimpleLogin-compatible HTTP adapter
workers/generator/src/cors.ts        strict CORS and response headers
workers/generator/wrangler.jsonc     public route, rate limiter, Core binding
workers/admin/src/index.ts           Access-protected admin API and asset router
workers/admin/src/access.ts          Access JWT validation
workers/admin/src/csrf.ts            Origin and double-submit CSRF validation
workers/admin/public/index.html      management-page shell
workers/admin/ui/app.ts              UI state, API calls, and safe DOM rendering
workers/admin/ui/styles.css          responsive management-page styling
workers/admin/wrangler.jsonc         Access hostname, assets, Core binding
scripts/build-admin.mjs              deterministic admin asset build
scripts/bootstrap-cloudflare.ps1     D1 creation, migrations, type generation
scripts/set-secrets.ps1              interactive secret setup without shell history
tests/unit/security.test.ts          randomness, password, encryption, HMAC tests
tests/unit/repository.test.ts        migrations, triggers, queries, transitions
tests/unit/mxroute.test.ts           request and response contract tests
tests/unit/core-generation.test.ts   creation state-machine tests
tests/unit/core-admin.test.ts        reset, delete, sync, token, recovery tests
tests/unit/generator.test.ts          SimpleLogin, CORS, and error mapping tests
tests/unit/admin-auth.test.ts         Access JWT, Origin, CSRF, and headers tests
tests/unit/admin-ui.test.ts           UI escaping and confirmation behavior tests
tests/integration/workers.test.ts     three-Worker Service Binding flow
tests/fixtures/access-key.ts          ephemeral test JWT issuer/keypair
docs/operations.md                   deploy, Access, Bitwarden, rotation, recovery
```

---

### Task 1: Scaffold the TypeScript Worker workspace

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `vitest.config.ts`
- Create: `vitest.integration.config.ts`
- Create: `.gitignore`
- Create: `packages/contracts/src/index.ts`
- Create: `workers/core/wrangler.jsonc`
- Create: `workers/generator/wrangler.jsonc`
- Create: `workers/admin/wrangler.jsonc`

**Interfaces:**
- Consumes: None.
- Produces: `MailboxStatus`, `AdminIdentity`, `AliasResult`, `MailboxSummary`, `CoreErrorEnvelope`, `GenerateResult`, and typed Wrangler service-binding names `CORE` and `DB`.

- [ ] **Step 0: Initialize the repository because the current workspace is not a Git worktree**

Run:

```powershell
git init
git switch -c feat/bitwarden-mxroute-generator
```

Expected: Git reports an initialized repository on branch `feat/bitwarden-mxroute-generator`.

- [ ] **Step 1: Add the workspace manifest and exact scripts**

Create `package.json` with private ESM mode, Node `>=22`, and these scripts:

```json
{
  "name": "bitwarden-mxroute-mailbox-generator",
  "private": true,
  "type": "module",
  "engines": { "node": ">=22" },
  "scripts": {
    "build": "npm run build:admin && npm run typecheck",
    "build:admin": "node scripts/build-admin.mjs",
    "typecheck": "tsc --noEmit",
    "test": "vitest run --config vitest.config.ts",
    "test:integration": "vitest run --config vitest.integration.config.ts --max-workers=1 --no-isolate",
    "types": "wrangler types -c workers/core/wrangler.jsonc -c workers/generator/wrangler.jsonc -c workers/admin/wrangler.jsonc",
    "check": "npm run typecheck && npm test && npm run test:integration"
  },
  "dependencies": { "jose": "^6.2.8" },
  "devDependencies": {
    "@cloudflare/vitest-pool-workers": "^0.21.2",
    "@cloudflare/workers-types": "^5.20260813.1",
    "esbuild": "^0.28.2",
    "typescript": "^7.0.2",
    "vitest": "^4.1.10",
    "wrangler": "^4.122.0"
  }
}
```

- [ ] **Step 2: Install and lock dependencies**

Run:

```powershell
npm install
```

Expected: `package-lock.json` is created and `npm audit --omit=dev` reports no known production vulnerability.

- [ ] **Step 3: Add strict TypeScript and test configuration**

Set `target` and `lib` to ES2023, enable `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, and include `packages`, `workers`, `tests`, and generated Worker declarations. Configure `cloudflareTest()` against Core for unit tests and reserve the separate integration config for `createTestHarness()`.

Use this base in `vitest.config.ts`:

```ts
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./workers/core/wrangler.jsonc" } })],
  test: { include: ["tests/unit/**/*.test.ts"] },
});
```

- [ ] **Step 4: Define shared RPC contracts**

Create immutable structured-clone-safe DTOs in `packages/contracts/src/index.ts`:

```ts
export type MailboxStatus =
  | "pending" | "active" | "failed" | "resetting"
  | "reset_unknown" | "deleting" | "delete_failed";

export interface AdminIdentity { subject: string; email: string; }
export interface AliasResult { id: number; email: string; enabled: true; creation_timestamp: number; name: null; note: null; }
export interface MailboxSummary { publicId: string; email: string; domain: string; quotaMb: number; status: MailboxStatus; createdAt: string; failureCode: string | null; }
export interface MailboxPage { items: MailboxSummary[]; nextCursor: string | null; }
export interface GenerateResult { alias: AliasResult; requestId: string; }
export interface CoreErrorEnvelope { code: string; message: string; retryable: boolean; requestId: string; }
```

- [ ] **Step 5: Add safe base Wrangler configurations**

Set Core to `workers_dev: false`, declare `DB`, required secrets `MXROUTE_SERVER`, `MXROUTE_USERNAME`, `MXROUTE_API_KEY`, `TOKEN_PEPPER`, `ENC_KEY_V1`, and a five-minute cron. Set Generator and Admin service bindings to `bitwarden-mxroute-core`; give Generator a pre-auth IP Rate Limiting binding of 30 requests per 60 seconds and a token-fingerprint binding of 5 requests per 60 seconds. Set Admin assets to `workers/admin/public` with an `ASSETS` binding and `run_worker_first: true`, so the Admin Worker validates Access JWTs and adds security headers before serving either API responses or static assets.

- [ ] **Step 6: Generate binding types and verify the empty workspace**

Run:

```powershell
npm run types
npm run typecheck
```

Expected: both commands exit 0 and generated environment interfaces expose only the bindings assigned to each Worker.

- [ ] **Step 7: Commit the scaffold**

```powershell
git add package.json package-lock.json tsconfig.json vitest*.config.ts .gitignore packages workers
git commit -m "chore: scaffold mailbox generator workers"
```

---

### Task 2: Implement and test security primitives

**Files:**
- Create: `packages/security/src/random.ts`
- Create: `packages/security/src/crypto.ts`
- Create: `tests/unit/security.test.ts`

**Interfaces:**
- Consumes: Web Crypto available in workerd.
- Produces: `randomPrefix(length): string`, `randomMailboxPassword(): string`, `randomApiToken(): string`, `encryptPassword(input): Promise<EncryptedPassword>`, `decryptPassword(input): Promise<string>`, and `tokenHmac(token, pepper): Promise<Uint8Array>`.

- [ ] **Step 1: Write failing randomness and password tests**

Cover exact prefix length/alphabet, 18-character password length, required uppercase/lowercase/digit classes, 2,000-sample uniqueness, and 32-byte API-token entropy encoded as base64url.

```ts
it("generates an MXroute-compatible 18-character password", () => {
  const password = randomMailboxPassword();
  expect(password).toHaveLength(18);
  expect(password).toMatch(/[A-Z]/);
  expect(password).toMatch(/[a-z]/);
  expect(password).toMatch(/[0-9]/);
});
```

- [ ] **Step 2: Run the randomness tests and observe failure**

Run:

```powershell
npx vitest run tests/unit/security.test.ts
```

Expected: failure because `packages/security/src/random.ts` does not exist.

- [ ] **Step 3: Implement unbiased random selection and forced character classes**

Use rejection sampling for alphabet selection and a cryptographic Fisher-Yates shuffle. Define these exact alphabets:

```ts
const PREFIX = "23456789abcdefghjkmnpqrstuvwxyz";
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER = "abcdefghjkmnpqrstuvwxyz";
const DIGITS = "23456789";
const SYMBOLS = "!@#$%_-";
```

Seed the password with one character from UPPER, LOWER, and DIGITS, fill the remaining 15 positions from their union with SYMBOLS, then securely shuffle.

- [ ] **Step 4: Write failing AES-GCM and HMAC tests**

Test round-trip, unique nonces, wrong-key rejection, modified-ciphertext rejection, changed-email AAD rejection, deterministic token HMAC, and unequal HMACs for different tokens.

- [ ] **Step 5: Implement AES-GCM and HMAC using Web Crypto**

Use this encrypted value shape:

```ts
export interface EncryptedPassword {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  keyVersion: number;
}
```

Import base64url Worker secrets into non-extractable CryptoKeys, use a 12-byte nonce, and construct AAD with UTF-8 encoding of `${publicId}|${email}|${keyVersion}`.

- [ ] **Step 6: Run security tests and typecheck**

```powershell
npx vitest run tests/unit/security.test.ts
npm run typecheck
```

Expected: all security tests pass and TypeScript exits 0.

- [ ] **Step 7: Commit security primitives**

```powershell
git add packages/security tests/unit/security.test.ts
git commit -m "feat: add mailbox credential cryptography"
```

---

### Task 3: Create the D1 schema and repository

**Files:**
- Create: `workers/core/migrations/0001.sql`
- Create: `workers/core/src/repository.ts`
- Create: `tests/unit/repository.test.ts`

**Interfaces:**
- Consumes: `D1Database`, DTOs from `packages/contracts`.
- Produces: `Repository` methods `reservePendingMailbox`, `transitionMailbox`, `findMailbox`, `pageMailboxes`, `saveNextPassword`, `completePasswordReset`, `removeMailbox`, `syncDomains`, `setDefaultDomain`, `getSettings`, `createTokenDigest`, `verifyTokenDigest`, and `appendAudit`.

- [ ] **Step 1: Write the complete migration**

Create the six tables from the approved design, indexes on `mailboxes(email)`, `mailboxes(status, updated_at)`, and `audit_events(created_at)`, plus foreign keys. Store byte values as BLOB and timestamps as RFC3339 text.

Add triggers that abort with stable messages:

```sql
CREATE TRIGGER enforce_daily_limit_insert
BEFORE INSERT ON creation_counters
WHEN NEW.count > CAST((SELECT value FROM settings WHERE key = 'daily_creation_limit') AS INTEGER)
BEGIN SELECT RAISE(ABORT, 'DAILY_LIMIT'); END;

CREATE TRIGGER enforce_daily_limit_update
BEFORE UPDATE OF count ON creation_counters
WHEN NEW.count > CAST((SELECT value FROM settings WHERE key = 'daily_creation_limit') AS INTEGER)
BEGIN SELECT RAISE(ABORT, 'DAILY_LIMIT'); END;

CREATE TRIGGER enforce_total_managed_limit
BEFORE INSERT ON mailboxes
WHEN (SELECT COUNT(*) FROM mailboxes) >= CAST((SELECT value FROM settings WHERE key = 'total_managed_limit') AS INTEGER)
BEGIN SELECT RAISE(ABORT, 'TOTAL_LIMIT'); END;
```

Seed `mailbox_quota_mb=100`, `prefix_length=12`, `daily_creation_limit=30`, `total_managed_limit=500`, and `generation_enabled=true`; do not seed a default domain.

- [ ] **Step 2: Write failing repository tests against migrated D1**

Test defaults, unique email enforcement, atomic `DB.batch()` reservation, trigger rollback at daily and total limits, allowed status transitions, pagination, inactive-domain rejection, exactly one default domain, token revocation, and audit redaction fields.

- [ ] **Step 3: Run repository tests and observe failure**

```powershell
npx vitest run tests/unit/repository.test.ts
```

Expected: failure because `Repository` is not implemented.

- [ ] **Step 4: Implement prepared-statement-only repository methods**

Every query uses positional bindings; dynamic sort columns are selected from a closed enum. `transitionMailbox(publicId, from, to, patch)` must include `WHERE public_id = ? AND status IN (...)` and throw `INVALID_STATE` when `meta.changes !== 1`.

Use a transactional batch for counter reservation and pending insert:

```ts
await db.batch([
  db.prepare(`INSERT INTO creation_counters(date, token_id, count) VALUES(?, ?, 1)
    ON CONFLICT(date, token_id) DO UPDATE SET count = count + 1`).bind(date, tokenId),
  db.prepare(`INSERT INTO mailboxes(public_id,email,local_part,domain,password_ciphertext,password_nonce,encryption_key_version,quota_mb,status,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?, 'pending', ?, ?)`).bind(
      publicId, email, localPart, domain, ciphertext, nonce, keyVersion, quotaMb, now, now,
    ),
]);
```

The migration triggers make limit failures roll back both statements.

- [ ] **Step 5: Run repository tests and inspect migration integrity**

```powershell
npx vitest run tests/unit/repository.test.ts
npx wrangler d1 migrations apply DB --local --config workers/core/wrangler.jsonc
```

Expected: tests pass and Wrangler reports migration `0001` applied.

- [ ] **Step 6: Commit schema and repository**

```powershell
git add workers/core/migrations workers/core/src/repository.ts tests/unit/repository.test.ts
git commit -m "feat: add encrypted mailbox repository"
```

---

### Task 4: Implement the MXroute client and normalized errors

**Files:**
- Create: `workers/core/src/mxroute.ts`
- Create: `workers/core/src/errors.ts`
- Create: `tests/unit/mxroute.test.ts`

**Interfaces:**
- Consumes: fixed base URL `https://api.mxroute.com` and Core-only credentials.
- Produces: `MxrouteClient.listDomains()`, `getMailbox(domain,user)`, `createMailbox(domain,user,password,quotaMb)`, `updateMailbox(domain,user,patch)`, `deleteMailbox(domain,user)`, and normalized `ServiceError` codes.

- [ ] **Step 1: Write failing HTTP contract tests**

Mock outbound fetch and assert exact method, URL encoding, three authentication headers, JSON body, 10-second abort timeout, JSON content type, and no credential values in thrown error messages.

Test mappings: 401→`MX_UNAUTHORIZED`, 404→`MX_NOT_FOUND`, 409→`MX_CONFLICT`, 429→`MX_RATE_LIMITED`, 5xx→`MX_SERVER`, timeout→`MX_TIMEOUT`, malformed JSON→`MX_INVALID_RESPONSE`.

- [ ] **Step 2: Run the client tests and observe failure**

```powershell
npx vitest run tests/unit/mxroute.test.ts
```

Expected: failure because `MxrouteClient` is missing.

- [ ] **Step 3: Implement the fixed-origin typed client**

Construct URLs only from the constant origin plus `encodeURIComponent(domain)` and `encodeURIComponent(user)`. Never accept a base URL from a request. Treat DELETE 404 as an idempotent success only in `deleteMailbox`; preserve 404 for query methods.

Use exact creation body:

```ts
{
  username: localPart,
  password,
  quota: quotaMb,
  limit: 9600
}
```

- [ ] **Step 4: Add response shape validation**

Validate `success` and `data` fields with explicit type guards. Do not store or propagate the entire upstream response; return only typed domain/mailbox facts needed by Core.

- [ ] **Step 5: Run client tests and typecheck**

```powershell
npx vitest run tests/unit/mxroute.test.ts
npm run typecheck
```

Expected: all contract tests pass.

- [ ] **Step 6: Commit the MXroute boundary**

```powershell
git add workers/core/src/mxroute.ts workers/core/src/errors.ts tests/unit/mxroute.test.ts
git commit -m "feat: add mxroute api client"
```

---

### Task 5: Implement Core mailbox generation

**Files:**
- Create: `workers/core/src/service.ts`
- Create: `workers/core/src/index.ts`
- Create: `tests/unit/core-generation.test.ts`

**Interfaces:**
- Consumes: `Repository`, `MxrouteClient`, security primitives, `TOKEN_PEPPER`, and versioned encryption key.
- Produces: RPC `generateMailbox(rawToken: string): Promise<GenerateResult>` and `CoreService` WorkerEntrypoint.

- [ ] **Step 1: Write failing happy-path and authorization tests**

Assert invalid/revoked tokens fail before random generation or MXroute calls; disabled generation fails; missing/inactive default domain fails; success creates one 100 MB mailbox, stores ciphertext rather than plaintext, transitions pending→active, and returns only the SimpleLogin alias fields.

- [ ] **Step 2: Write failing collision, quota, and timeout tests**

Cover five conflict retries with distinct prefixes, daily/total trigger errors, 429, explicit 4xx, 5xx, timeout, and D1 failure before the MXroute call. Assert an ambiguous timeout retains the encrypted pending row and returns retryable 503 semantics.

- [ ] **Step 3: Run generation tests and observe failure**

```powershell
npx vitest run tests/unit/core-generation.test.ts
```

Expected: failure because `MailboxService.generateMailbox` is missing.

- [ ] **Step 4: Implement generation orchestration**

Use this order exactly:

```ts
verifyToken → loadSettings → validateGenerationEnabled → validateDefaultDomain
→ generatePrefixAndPassword → encrypt → reservePendingMailbox
→ mxroute.createMailbox → transitionToActive → appendAudit → returnAlias
```

On conflict, mark the current row failed, release its daily reservation, and retry with a new prefix. On timeout/server uncertainty, retain pending and never release the reservation until reconciliation proves non-existence.

- [ ] **Step 5: Export a private RPC entrypoint**

`workers/core/src/index.ts` exports a `CoreService extends WorkerEntrypoint<CoreEnv>` with `generateMailbox` and no `fetch()` method. Construct dependencies from `this.env`; do not log RPC arguments.

- [ ] **Step 6: Run generation tests and typecheck**

```powershell
npx vitest run tests/unit/core-generation.test.ts
npm run typecheck
```

Expected: all generation tests pass.

- [ ] **Step 7: Commit mailbox generation**

```powershell
git add workers/core/src/service.ts workers/core/src/index.ts tests/unit/core-generation.test.ts
git commit -m "feat: create encrypted mxroute mailboxes"
```

---

### Task 6: Implement Core administration and recovery state machines

**Files:**
- Modify: `workers/core/src/service.ts`
- Modify: `workers/core/src/index.ts`
- Modify: `workers/core/src/repository.ts`
- Create: `tests/unit/core-admin.test.ts`

**Interfaces:**
- Consumes: verified `AdminIdentity` supplied only by Admin Worker.
- Produces: RPC methods `pageMailboxes`, `revealPassword`, `resetPassword`, `deleteMailbox`, `syncDomains`, `setDefaultDomain`, `createApiToken`, `revokeApiToken`, `updateSettings`, `pageAudit`, and scheduled `reconcilePending`/`reconcileResetUnknown`.

- [ ] **Step 1: Write failing domain, settings, token, and list tests**

Test domain sync marks missing domains inactive without deleting them, rejects inactive defaults, paginates mailbox/audit data, enforces numeric setting ranges, emits a raw API token exactly once, stores only its HMAC, supports two overlapping valid tokens, and rejects a revoked token.

- [ ] **Step 2: Write failing reveal and reset tests**

Assert reveal decrypts only active/exception states and writes a reveal audit event without password data. Test reset happy path, explicit failure rollback, timeout→`reset_unknown`, and recovery reusing the same encrypted candidate password until PATCH succeeds.

- [ ] **Step 3: Write failing permanent-delete tests**

Require exact email confirmation; test active→deleting→removed, upstream 404 as success, explicit failure→`delete_failed`, timeout followed by GET existence check, and audit retention without any password column.

- [ ] **Step 4: Run administration tests and observe failure**

```powershell
npx vitest run tests/unit/core-admin.test.ts
```

Expected: failures for unimplemented RPC operations.

- [ ] **Step 5: Implement admin operations and state guards**

All mutating operations append success/failure audit events with `actor_type=admin`, verified email/subject, normalized code, and request ID. Reveal responses remain structured-clone values and must not be logged.

- [ ] **Step 6: Implement scheduled reconciliation with bounded backoff**

Add `scheduled()` to Core. Each run processes at most 25 stale rows older than five minutes. Pending rows use GET existence checks; reset-unknown rows repeat PATCH with the stored candidate password; deleting rows re-check existence. Increment an attempt count and stop automatic retries after eight attempts while leaving the row visible to administrators.

- [ ] **Step 7: Run administration and all Core tests**

```powershell
npx vitest run tests/unit/core-admin.test.ts tests/unit/core-generation.test.ts tests/unit/repository.test.ts
npm run typecheck
```

Expected: all Core tests pass.

- [ ] **Step 8: Commit administration and recovery**

```powershell
git add workers/core tests/unit/core-admin.test.ts
git commit -m "feat: manage and recover mxroute mailboxes"
```

---

### Task 7: Implement the public SimpleLogin-compatible Generator Worker

**Files:**
- Create: `workers/generator/src/cors.ts`
- Create: `workers/generator/src/index.ts`
- Create: `tests/unit/generator.test.ts`

**Interfaces:**
- Consumes: `env.CORE.generateMailbox(token)`, `env.PREAUTH_RATE_LIMITER.limit({key})`, and `env.TOKEN_RATE_LIMITER.limit({key})`.
- Produces: HTTP `POST /api/alias/random/new`, `OPTIONS /api/alias/random/new`, and `GET /healthz`.

- [ ] **Step 1: Write failing SimpleLogin contract tests**

Test 201 response shape, `Authentication` header extraction, accepted but ignored `hostname` and `mode`, missing token 401, pre-auth IP throttling, token-fingerprint throttling, malformed method 405, unknown path 404, Core retryable error 503, quota error 429, and no password-shaped fields in any body.

- [ ] **Step 2: Write failing CORS and cache tests**

Assert OPTIONS allows POST, `Authentication`, and `Content-Type`; public API uses wildcard origin without credentials; every API response contains `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

- [ ] **Step 3: Run Generator tests and observe failure**

```powershell
npx vitest run tests/unit/generator.test.ts
```

Expected: failure because the HTTP adapter is missing.

- [ ] **Step 4: Implement the minimal route table and rate limiting**

Use a closed route switch. Apply the 30-per-minute pre-auth limit to the `CF-Connecting-IP` value before parsing credentials; this layer only absorbs invalid-token floods and is not an accounting control. Hash the presented API token with SHA-256 and use the first 16 hex bytes for the 5-per-minute token limit; never pass the raw token to either limiter or logs. Call Core only after both applicable limits succeed.

- [ ] **Step 5: Implement stable error mapping**

Map internal codes to a SimpleLogin body `{ "error": "..." }` while keeping request IDs in `X-Request-Id`. Do not expose stack traces, upstream messages, D1 statements, or domain configuration.

- [ ] **Step 6: Run Generator tests and typecheck**

```powershell
npx vitest run tests/unit/generator.test.ts
npm run typecheck
```

Expected: all Generator tests pass.

- [ ] **Step 7: Commit the Generator Worker**

```powershell
git add workers/generator tests/unit/generator.test.ts
git commit -m "feat: expose bitwarden mailbox generator api"
```

---

### Task 8: Implement Access authentication, CSRF, and the Admin API

**Files:**
- Create: `workers/admin/src/access.ts`
- Create: `workers/admin/src/csrf.ts`
- Create: `workers/admin/src/index.ts`
- Create: `tests/fixtures/access-key.ts`
- Create: `tests/unit/admin-auth.test.ts`

**Interfaces:**
- Consumes: `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, `ADMIN_EMAILS`, `ADMIN_ORIGIN`, static assets, and typed Core RPC.
- Produces: authenticated `/api/mailboxes`, `/api/domains`, `/api/settings`, `/api/tokens`, `/api/audit`, reveal/reset/delete actions, and Access-validated static-asset responses.

- [ ] **Step 1: Write failing Access JWT tests with an ephemeral keypair**

Use `jose` to mint test JWTs and assert rejection of missing header, bad signature, wrong issuer, wrong audience, expired token, absent email, and email outside `ADMIN_EMAILS`. Assert success returns `{subject,email}` only.

- [ ] **Step 2: Write failing Origin and CSRF tests**

GET `/api/session` issues a 32-byte base64url host-only cookie with `Secure; SameSite=Strict; Path=/`. State-changing POST/PUT/DELETE requests must have exact `Origin === ADMIN_ORIGIN`, cookie token, and matching `X-CSRF-Token`; reject mismatches with 403.

- [ ] **Step 3: Write failing Admin API and security-header tests**

Test every route maps typed JSON to the corresponding Core RPC. Reveal uses POST and `Cache-Control: no-store`; delete requires `confirmationEmail`; unknown routes return 404. Assert CSP, `frame-ancestors 'none'`, nosniff, no-referrer, and no-store on API responses.

- [ ] **Step 4: Run Admin tests and observe failure**

```powershell
npx vitest run tests/unit/admin-auth.test.ts
```

Expected: failures for missing authentication and router modules.

- [ ] **Step 5: Implement JWT validation using a remote JWKS**

Use `createRemoteJWKSet(new URL(`${teamDomain}/cdn-cgi/access/certs`))` and `jwtVerify` with exact issuer and audience. Normalize configured emails to lowercase and compare exact addresses. Perform this verification before routing every request, including `/`, JavaScript, CSS, and all `/api/*` paths.

- [ ] **Step 6: Implement CSRF and the closed Admin route table**

Parse bodies with size limits, validate every field, cap page size at 100, and reject unexpected status/domain/setting values. Pass the verified identity explicitly to each Core method.

- [ ] **Step 7: Run Admin tests and typecheck**

```powershell
npx vitest run tests/unit/admin-auth.test.ts
npm run typecheck
```

Expected: all Admin authentication and API tests pass.

- [ ] **Step 8: Commit the Admin API**

```powershell
git add workers/admin/src tests/fixtures tests/unit/admin-auth.test.ts
git commit -m "feat: add access-protected mailbox admin api"
```

---

### Task 9: Build the management UI

**Files:**
- Create: `workers/admin/public/index.html`
- Create: `workers/admin/ui/app.ts`
- Create: `workers/admin/ui/styles.css`
- Create: `scripts/build-admin.mjs`
- Create: `tests/unit/admin-ui.test.ts`

**Interfaces:**
- Consumes: Admin API from Task 8.
- Produces: responsive mailbox/domain/token/settings/audit views with safe reveal, reset, and delete interactions.

- [ ] **Step 1: Write failing DOM-independent UI tests**

Extract and test `text(node,value)`, `formatMailboxRow`, `validateDeleteConfirmation`, and API-client behavior. Assert hostile email/domain text such as `<img src=x onerror=alert(1)>` is assigned through `textContent`, never interpolated into HTML.

- [ ] **Step 2: Run UI tests and observe failure**

```powershell
npx vitest run tests/unit/admin-ui.test.ts
```

Expected: failure because UI helpers do not exist.

- [ ] **Step 3: Create the accessible page shell and navigation**

Include Mailboxes, Domains, API Tokens, Settings, Audit, and Recovery sections; semantic tables; labeled inputs; keyboard-operable dialogs; a live status region; and no third-party fonts, scripts, images, analytics, or CDN resources.

- [ ] **Step 4: Implement safe mailbox actions**

Password reveal must require an explicit click, render masked by default, keep plaintext only in a local variable, clear it after 60 seconds or row close, and use `navigator.clipboard.writeText` only after direct user action. Delete dialog requires typing the complete email and displays the D1 Time Travel 7/30-day ciphertext-retention notice.

- [ ] **Step 5: Implement domains, settings, tokens, audit, and recovery views**

Domain sync and default selection use active domains only. Token creation displays the raw token once with a copy button and dismissal warning. Settings enforce quota 1–102400 MB, daily limit 1–1000, and total managed limit 1–100000 in both browser and server validation.

- [ ] **Step 6: Add deterministic asset build**

`scripts/build-admin.mjs` invokes esbuild with `bundle:true`, `format:"esm"`, `target:"es2023"`, `minify:true`, writes `public/app.js`, copies/minifies CSS to `public/styles.css`, and fails if either output contains `eval(` or a source-map reference.

- [ ] **Step 7: Run UI tests and build**

```powershell
npx vitest run tests/unit/admin-ui.test.ts
npm run build:admin
```

Expected: tests pass and `workers/admin/public/app.js` plus `styles.css` are generated without inline secrets or external URLs.

- [ ] **Step 8: Commit the management UI**

```powershell
git add workers/admin/public workers/admin/ui scripts/build-admin.mjs tests/unit/admin-ui.test.ts
git commit -m "feat: add secure mailbox management interface"
```

---

### Task 10: Add multi-Worker integration and failure-injection tests

**Files:**
- Create: `tests/integration/workers.test.ts`
- Modify: `vitest.integration.config.ts`
- Modify: all three `wrangler.jsonc` files as required by generated binding types

**Interfaces:**
- Consumes: complete Generator/Admin/Core modules and test D1 migration.
- Produces: executable proof that HTTP→Service Binding→Core→D1 works without leaking Core publicly.

- [ ] **Step 1: Configure the Wrangler test harness for three Workers**

Use `createTestHarness({workers:[...]})` with Core, Generator, and Admin configs. Override secrets with fixed test-only base64 keys, bind a test D1 database with migration `0001`, and mock only outbound MXroute and Access JWKS requests.

- [ ] **Step 2: Write the failing end-to-end generation test**

Create an active domain/default and API token through Core test handles, POST through Generator, assert 201/email shape, assert the MXroute request has quota 100 and an 18-character password, and query D1 to prove that exact password bytes do not occur in any text/BLOB serialization.

- [ ] **Step 3: Write the failing Admin flow test**

Send a valid Access JWT and CSRF pair through Admin, list the created mailbox, reveal the password, reset it, verify the second MXroute PATCH uses a different 18-character password, then permanently delete and assert both MXroute DELETE and mailbox-row removal.

- [ ] **Step 4: Write failure-injection tests**

Inject conflict, rate limit, timeout after upstream creation, D1 transition failure, reset timeout, delete timeout, forged Access JWT, revoked token, and repeated cron runs. Assert no active mailbox lacks a recoverable current/candidate password and no error response contains credentials.

- [ ] **Step 5: Run integration tests serially**

```powershell
npm run test:integration
```

Expected: all multi-Worker tests pass under `--max-workers=1 --no-isolate`.

- [ ] **Step 6: Run the complete verification suite**

```powershell
npm run check
npm audit --omit=dev
```

Expected: typecheck, unit tests, integration tests, and production dependency audit all pass.

- [ ] **Step 7: Commit integration coverage**

```powershell
git add tests/integration vitest.integration.config.ts workers/*/wrangler.jsonc
git commit -m "test: verify mailbox generator across workers"
```

---

### Task 11: Add secure bootstrap, deployment, and operations documentation

**Files:**
- Create: `scripts/bootstrap-cloudflare.ps1`
- Create: `scripts/set-secrets.ps1`
- Create: `docs/operations.md`
- Create: `README.md`

**Interfaces:**
- Consumes: a logged-in Wrangler session, Cloudflare account, two public hostnames, Access application values, and MXroute credentials.
- Produces: reproducible staging/production deployment and Bitwarden configuration instructions.

- [ ] **Step 1: Implement the idempotent bootstrap script**

The script checks `wrangler whoami`, creates `bitwarden-mxroute-staging` or `bitwarden-mxroute-production` D1 with `wrangler d1 create --binding DB --update-config`, applies migrations remotely, runs `wrangler types`, and stops on any non-zero exit code. It never accepts secret values as command-line parameters.

- [ ] **Step 2: Implement interactive secret setup**

`scripts/set-secrets.ps1` calls `wrangler secret put` without `--value` for `MXROUTE_SERVER`, `MXROUTE_USERNAME`, `MXROUTE_API_KEY`, `TOKEN_PEPPER`, and `ENC_KEY_V1`. It generates pepper/encryption key locally with `RandomNumberGenerator.Fill`, pipes them directly to Wrangler stdin, and prints only secret names and success state.

- [ ] **Step 3: Write the operations runbook**

Document exact order: create D1, apply migrations, set secrets, deploy Core, bind/deploy Generator and Admin, assign custom domains, disable Core public routes, create Cloudflare Access application, copy Team Domain/AUD, configure allowed admin emails/origin, enable MFA, sync domains, select default, create a Bitwarden token, and configure Bitwarden SimpleLogin Server URL/API Key on desktop and mobile.

Include rollback, token rotation, MXroute key rotation, AES key rotation, failed-state recovery, D1 Time Travel restoration, log redaction, emergency generation shutdown, and deletion-retention explanations.

- [ ] **Step 4: Add a real staging smoke-test checklist**

The checklist requires one disposable MXroute domain and verifies: Bitwarden desktop creates an address, Bitwarden mobile creates another, both have 100 MB quota, each password is 18 characters and logs in, reset invalidates the old password, delete removes the account, invalid Token gets 401, non-Access browser is blocked, and D1 export contains no plaintext password.

- [ ] **Step 5: Run final local verification**

```powershell
npm run check
npm run build
git diff --check
git status --short
```

Expected: all verification commands pass; status contains only intended documentation/scripts or is clean after commit.

- [ ] **Step 6: Commit deployment support**

```powershell
git add scripts docs README.md
git commit -m "docs: add secure deployment and operations runbook"
```

---

## Final Verification Gate

- [ ] Run `npm run check` and retain the passing output.
- [ ] Run `npm audit --omit=dev` and resolve any production advisory before deployment.
- [ ] Run `npx wrangler deploy --dry-run --config` for Core, Generator, and Admin; verify Core has no route and no `workers.dev` endpoint.
- [ ] Verify generated Worker environment types show D1 and secrets only on Core.
- [ ] Complete the real staging smoke-test checklist on both Bitwarden desktop/browser and mobile.
- [ ] Confirm logs, D1 export, API responses, browser storage, and built admin assets contain no plaintext mailbox password, raw token, or MXroute credential.
- [ ] Request code review, address findings, and rerun the complete verification suite before production deployment.

## Source References

- Approved design: `docs/superpowers/specs/2026-08-13-bitwarden-mxroute-mailbox-generator-design.md`
- Bitwarden generator: https://bitwarden.com/en-gb/help/generator/
- SimpleLogin API: https://github.com/simple-login/app/blob/master/docs/api.md
- Cloudflare Service Binding RPC: https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/rpc/
- Cloudflare RPC TypeScript: https://developers.cloudflare.com/workers/runtime-apis/rpc/typescript/
- Cloudflare D1 batch transactions: https://developers.cloudflare.com/d1/worker-api/d1-database/
- Cloudflare Workers Vitest: https://developers.cloudflare.com/workers/testing/vitest-integration/write-your-first-test/
- Cloudflare test harness: https://developers.cloudflare.com/workers/testing/test-harness/get-started/
- Cloudflare Access JWT validation: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/
- Cloudflare Cron Triggers: https://developers.cloudflare.com/workers/configuration/cron-triggers/
