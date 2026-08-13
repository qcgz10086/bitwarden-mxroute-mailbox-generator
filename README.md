# Bitwarden MXroute 独立邮箱生成器

这是一个运行在 **Cloudflare Workers**（不是“workspage”）上的三 Worker 服务：Bitwarden 桌面端和手机端通过 SimpleLogin 兼容接口创建真实 MXroute 独立邮箱；管理页受 Cloudflare Access 登录保护。

- 邮箱前缀：12 位纯随机串，例如 `q8v2ka7m3wc@example.com`
- 邮箱密码：每个邮箱独立生成，严格 18 位；只以 AES-256-GCM 密文存入 D1
- 默认容量：100 MB，可在管理页调整后影响新邮箱
- 多域名：从 MXroute 同步，在管理页选择一个默认域名
- 删除：只有永久删除，没有单邮箱停用
- Bitwarden：只得到邮箱地址，不得到邮箱密码

## 架构

```text
Bitwarden -> Generator Worker -> Core Worker -> MXroute / D1
Browser   -> Access -> Admin Worker -> Core Worker
```

Security note: Core exposes separate least-privilege RPC surfaces. Generator binds only to
`GeneratorEntrypoint`, Admin binds only to `AdminEntrypoint`, and the default export only runs
scheduled recovery. Do not remove the `services[].entrypoint` selectors.

API-token issuance is two phase. The browser reuses a client operation ID after a lost response;
Core retains the pending raw token only as AES-GCM ciphertext for ten minutes. Copying or explicitly
accepting it acknowledges the token, atomically erases the ciphertext, and activates authentication.
Acknowledgement is idempotent for the same Access subject, token ID, and operation ID, so a lost ACK
response can be retried without recovering or retaining the raw token. The management table labels
each credential as Pending (with expiry), Active, or Revoked.
Unacknowledged tokens cannot authenticate and cron revokes expired pending records. A known token ID
is revoked with a same-origin keepalive request during page unload.

Generator 和 Admin 只有 Core 服务绑定；D1、MXroute 凭据、Token pepper 和 AES 密钥仅存在于无公网路由的 Core。Admin Worker 还会自行验证 Access JWT、允许的邮箱、Origin 和双提交 CSRF。

## 本地验证

要求 Node.js 22 或更新版本：

```powershell
npm ci
npm run check
npm run build
npm audit --omit=dev
npx wrangler deploy --dry-run --config workers/core/wrangler.jsonc
npx wrangler deploy --dry-run --config workers/generator/wrangler.jsonc
npx wrangler deploy --dry-run --config workers/admin/wrangler.jsonc
```

上面三条只验证仓库内本地测试模板能够打包，不认证 Prepare 配置，也不能作为实际环境的上线门禁。实际部署必须按下述顺序对 Finalize `-WhatIf` 生成的环境配置重新执行全部三条 dry-run。

完整的 Cloudflare 初始化、Access、Bitwarden 配置、轮换、恢复和真实预发布验收步骤见 [docs/operations.md](docs/operations.md)。脚本支持 `-WhatIf`，先预览：

```powershell
$accountId = '0123456789abcdef0123456789abcdef'
.\scripts\bootstrap-cloudflare.ps1 -Environment staging -AccountId $accountId -Phase Prepare -Confirm
.\scripts\set-secrets.ps1 -Environment staging -AccountId $accountId -Confirm
```

创建 Access 应用并取得 Admin 输入后，先执行 Finalize `-WhatIf`；它只生成最终配置并预览操作，不部署。然后对最终生成的三份配置逐一 dry-run，检查绑定、Core 无 route/`workers.dev`、cron 和 Admin vars，最后才执行同一条 Finalize 命令并把 `-WhatIf` 改为 `-Confirm`：

```powershell
.\scripts\bootstrap-cloudflare.ps1 `
  -Environment staging -AccountId $accountId -Phase Finalize `
  -AccessTeamDomain 'https://team.cloudflareaccess.com' -AccessAud '复制的-aud-tag' `
  -AdminEmails 'admin@example.com' -AdminOrigin 'https://mail-admin.example.com' `
  -GeneratorHostname 'generator.example.com' -AdminHostname 'mail-admin.example.com' -WhatIf
npx wrangler deploy --dry-run --config .wrangler/environments/staging/core.jsonc
npx wrangler deploy --dry-run --config .wrangler/environments/staging/generator.jsonc
npx wrangler deploy --dry-run --config .wrangler/environments/staging/admin.jsonc
.\scripts\bootstrap-cloudflare.ps1 `
  -Environment staging -AccountId $accountId -Phase Finalize `
  -AccessTeamDomain 'https://team.cloudflareaccess.com' -AccessAud '复制的-aud-tag' `
  -AdminEmails 'admin@example.com' -AdminOrigin 'https://mail-admin.example.com' `
  -GeneratorHostname 'generator.example.com' -AdminHostname 'mail-admin.example.com' -Confirm
```

部署脚本只使用 `.wrangler/environments/<environment>` 下按环境生成且被 Git 忽略的配置，不会改写仓库中的生产模板。每次远程写操作前都会把预期 Account ID 与 `wrangler whoami` 核对，并校验 D1、Worker 名称、服务绑定和公网路由。完整顺序是：Prepare 私有 Core shell → 交互设置 Secret → 创建 Access/MFA policy → Finalize 迁移并发布。

不要提交 `.dev.vars`、`.env`、Wrangler 状态目录或生成的环境配置。真实部署和桌面/手机烟测需要操作者登录 Cloudflare、MXroute 和 Bitwarden 后完成；本仓库的本地测试不会执行这些外部变更。

如果本机存在 `Cloudflare API.txt` 或 `MXroute Email Hosting API.txt`，它们只允许留在本地：不要打印、解析、上传或提交。`.gitignore` 已对这两个精确文件名提供额外保护；部署脚本也不会自动读取它们，所有 Secret 仍通过受保护的交互输入或本机密码学随机数进入 Wrangler stdin。
