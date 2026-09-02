# Bitwarden × MXroute 独立邮箱生成器

本项目**不修改** Bitwarden。操作者在 Bitwarden 的「用户名生成器 → 转发邮箱别名 → SimpleLogin」中，把 Server URL 指向自己部署的 Generator，用管理页签发的 Token 当 API Key；每次生成会在操作者自己的 **MXroute 域名**上创建一封真实独立邮箱。**邮箱密码永远不会进入 Bitwarden**；查看与重置只在管理界面完成。

适用：已有 MXroute、Cloudflare、自托管/小团队 Bitwarden 的运维人员。
**不是**批量注册/滥用工具，**不是**完整 SimpleLogin，**不是**网页邮箱，**不是**官方 Bitwarden 插件。

## 功能

- Bitwarden SimpleLogin 兼容接口：`POST /api/alias/random/new`（另有 `OPTIONS` 与 `GET /healthz`）。
- 本地部分：12 位随机字符；每个邮箱独立 18 位密码；默认容量 100 MB。
- 三个 Worker：公网 **Generator**、无公网路由的私有 **Core**、**Admin** 管理页。
- 双语管理页：同步域名、配额与默认域、生成总开关、Token 签发/撤销、显示/重置密码、永久删除、审计。
- 邮箱密码以 AES-256-GCM 存入 D1；Bitwarden Token 为加 pepper 的 HMAC，明文只显示一次。
- 删除只有永久删除，没有单邮箱停用。

## 架构

```text
Bitwarden  -->  Generator（公网，Token，限流，CORS）
                  -->  Core GeneratorEntrypoint  -->  MXroute / D1

Browser    -->  Admin（日常为管理员密码会话）
                  -->  Core AdminEntrypoint
```

Cloudflare Access 用于管理端**密码重置相关身份路径**（以及建议作为 Admin 主机名的边缘保护）。细节见 [docs/operations.md](docs/operations.md)。

仓库里的 `workers/*/wrangler.jsonc` 只是**本地测试模板**。真实环境配置写在被 Git 忽略的 `.wrangler/environments/<env>/`。

安全边界：Generator 只绑定 `GeneratorEntrypoint`，Admin 只绑定 `AdminEntrypoint`；Core 默认导出仅跑定时恢复。不要去掉 `services[].entrypoint` 选择器。Generator / Admin 没有 D1、MXroute 凭据、pepper 或 AES 密钥。

## 要求

- Node.js 22+
- PowerShell 7+
- Wrangler（已登录目标 Cloudflare 账户）
- MXroute 凭据与至少一个已配置域名
- 两个 HTTPS 主机名（Generator 与 Admin）

完整部署、Access、轮换、恢复与预发布烟测见 **[docs/operations.md](docs/operations.md)**。

## 快速开始（本地校验）

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

完整的 Cloudflare 初始化、Access、Bitwarden 配置、轮换、恢复和真实预发布验收步骤见 [docs/operations.md](docs/operations.md)。

## 配置与密钥

### Secrets（`scripts/set-secrets.ps1`）

不要使用 Wrangler 的 `--value` 方式写入 Secret。脚本把值送进 Wrangler stdin；输出只显示名称和 `SET`/`PRESENT`。

| Secret | 写入目标 | 来源 |
|---|---|---|
| `MXROUTE_SERVER` | Core | 受保护的交互输入 |
| `MXROUTE_USERNAME` | Core | 受保护的交互输入 |
| `MXROUTE_API_KEY` | Core | 受保护的交互输入 |
| `TOKEN_PEPPER` | Core | 本机 CSPRNG（32 字节） |
| `ENC_KEY_V1` | Core | 本机 CSPRNG（32 字节）；**不要覆盖或删除** |
| `ADMIN_SESSION_KEY` | **Admin Worker** | 若 Admin 尚无此 Secret，脚本生成 256-bit 随机值并写入 Admin |

已有生成密钥不会被覆盖。`-RotateMxroute` **只**轮换三项 MXroute 值。`set-secrets.ps1` **会**在 Admin 缺少 `ADMIN_SESSION_KEY` 时为其生成并设置；不是「只写 Core 的五项 Secret」。

### Admin 非 Secret 变量（Finalize 写入）

- `ACCESS_TEAM_DOMAIN`：完整 Team Domain，例如 `https://team.cloudflareaccess.com`，无路径。
- `ACCESS_AUD`：Access 应用 AUD tag。
- `ADMIN_EMAILS`：允许的管理员邮箱，逗号分隔。
- `ADMIN_ORIGIN`：Admin 精确 origin，无结尾 `/`。

可选 Turnstile：`TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY`。缺少 `ADMIN_SESSION_KEY` 时 Admin 返回 `SERVER_MISCONFIGURED`。

日常管理登录是**管理员密码会话**，不是每个请求都验 Access JWT。Access JWT 用于 `/reset` 与 `/api/auth/reset`，并建议作为 Admin 主机名的边缘保护。

### Bindings

- **Generator**：`CORE` 指向 `GeneratorEntrypoint`；`PREAUTH_RATE_LIMITER` 30/60s；`TOKEN_RATE_LIMITER` 5/60s。
- **Admin**：`CORE` 指向 `AdminEntrypoint`；`ASSETS`；四项 vars；Secret `ADMIN_SESSION_KEY`。
- **Core**：`DB` + 五项 Core Secret；`workers_dev=false`；无公网 `routes`；cron `*/5 * * * *`。

## 用脚本部署

没有 Cloudflare 一键部署。上线只用这两个 PowerShell 7 脚本（先 `-WhatIf` 预览，再 `-Confirm` 改远程）：

| 脚本 | 作用 |
|---|---|
| `scripts/bootstrap-cloudflare.ps1` | `-Phase Prepare` 建 D1 和无私网 Core shell；`-Phase Finalize` 写最终配置、跑迁移、发布三个 Worker 和自定义域名 |
| `scripts/set-secrets.ps1` | 交互写入 Core 的 MXroute 三项；本机生成 `TOKEN_PEPPER` / `ENC_KEY_V1`（已有不覆盖）；Admin 缺少 `ADMIN_SESSION_KEY` 时生成并写入 Admin |

不要把仓库里的 workers/*/wrangler.jsonc 当生产配置。脚本只读写 Git 忽略的 .wrangler/environments 目录。

### 参数

| 参数 | 值 |
|---|---|
| `-Environment` | 只能是 `staging` 或 `production` |
| `-AccountId` | Cloudflare 仪表板 32 位 hex，且必须出现在 wrangler whoami 输出里 |
| `-Profile` | 可选，Wrangler 配置名 |
| `-Phase` | 仅 bootstrap：`Prepare`（默认）或 `Finalize` |
| `-RotateMxroute` | 仅 set-secrets：只轮换三项 MXroute |

Finalize 还要（脚本会校验格式）：

| 参数 | 约束 |
|---|---|
| `-AccessTeamDomain` | https Team Domain，形如 team.cloudflareaccess.com，不要路径 |
| `-AccessAud` | Access 应用 AUD |
| `-AdminEmails` | 逗号分隔邮箱 |
| `-AdminOrigin` | 精确 HTTPS origin，无路径、无结尾斜杠 |
| `-GeneratorHostname` | 小写 DNS 主机名 |
| `-AdminHostname` | 小写 DNS；AdminOrigin 必须等于 https:// 加上该主机名 |

预发布名称：bitwarden-mxroute-core-staging、generator-staging、admin-staging，D1 bitwarden-mxroute-staging。生产去掉 -staging，D1 为 bitwarden-mxroute-production。

### 逐步操作（预发布）

在仓库根目录用 PowerShell 7。

1. 进入 pwsh，安装依赖并登录 Wrangler，把仪表板里的 32 位 Account ID 赋给变量 accountId。
2. Prepare：先 WhatIf 再 Confirm。只建 D1 和无私网 Core shell（此时无计划任务、无公网路由）。
3. 跑 set-secrets.ps1：提示时输入三项 MXroute；pepper、AES、Admin 会话密钥由脚本生成。不要把 Secret 写在命令行参数里。
4. 在 Zero Trust 为 Admin 主机名建 Self-hosted Access（保护整站，开 MFA，允许列表与 ADMIN_EMAILS 一致），复制 Team Domain 和 AUD。
5. Finalize 先 WhatIf（只生成最终 jsonc），再对生成配置做 dry-run，通过后把同一条 Finalize 改成 Confirm。
6. 生产：Environment 改成 production，配置目录和主机名换成生产值。

下面是对应命令。完整清单、轮换和回滚见 [docs/operations.md](docs/operations.md)。

### 命令示例

脚本支持 `-WhatIf`，先预览：

```powershell
$accountId = '0123456789abcdef0123456789abcdef'
.\scripts\bootstrap-cloudflare.ps1 -Environment staging -AccountId $accountId -Phase Prepare -WhatIf
.\scripts\bootstrap-cloudflare.ps1 -Environment staging -AccountId $accountId -Phase Prepare -Confirm
.\scripts\set-secrets.ps1 -Environment staging -AccountId $accountId -WhatIf
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

### AI 部署\n\n把下面整段提示词复制给能跑本机终端的助手（Cursor、Claude Code 等），填好变量后让它执行。MXroute 密钥不要贴进聊天，用脚本交互输入。同一份也在 [docs/ai-deploy-prompt.md](docs/ai-deploy-prompt.md)。\n\n```text\n你是本仓库的部署助手。仓库：bitwarden-mxroute-mailbox-generator。只做 Cloudflare Workers 部署，不要改应用代码、不要开 PR 改业务逻辑、不要打印或提交任何密钥。

先读 README.md 的「用脚本部署」和 docs/operations.md。上线只用这两个脚本：
- scripts/bootstrap-cloudflare.ps1
- scripts/set-secrets.ps1
必须用 PowerShell 7（pwsh）。每个会改远程的命令都先加 -WhatIf，操作者确认后再 -Confirm。不要对 workers 目录下的测试配置做实际上线。

操作者会提供这些值（缺任何一项就停下来问，不要编造）：
- Environment：staging 或 production
- AccountId：32 位 hex，必须能在 wrangler whoami 输出里找到
- 可选 Profile
- GeneratorHostname、AdminHostname（小写 DNS）
- AdminOrigin：必须等于 https:// 加上 AdminHostname，无路径、无结尾斜杠
- AccessTeamDomain：https 的 Access Team Domain
- AccessAud
- AdminEmails：逗号分隔
- MXroute 三项：不要贴进聊天；用 set-secrets.ps1 的交互输入

硬性禁止：
- 把 Secret 写进命令行参数、日志、截图、git commit
- 读取或上传名为 Cloudflare API.txt 或 MXroute Email Hosting API.txt 的文件
- 覆盖已有 TOKEN_PEPPER、ENC_KEY_V1、ADMIN_SESSION_KEY
- 删除 D1、Core 或上游邮箱来急救
- 把 Core 绑到 workers.dev 或加公网路由

执行顺序：
1. 确认 pwsh、Node 22+、依赖已安装、wrangler 已登录，Account ID 与给定值一致。
2. 运行 bootstrap 脚本 Phase Prepare：先 WhatIf，操作者同意后再 Confirm。
3. 运行 set-secrets 脚本：先 WhatIf 再 Confirm。MXroute 三项走交互；pepper、AES、Admin 会话密钥由脚本生成（已有则跳过）。
4. 若 Access 应用还不存在：停下来，让操作者在 Zero Trust 为 Admin 主机名创建 Self-hosted Access（保护整站、MFA、允许列表与 AdminEmails 一致），再把 Team Domain 和 AUD 发你。
5. 运行 bootstrap 脚本 Phase Finalize：先 WhatIf。再对 .wrangler/environments 下该环境的三份 jsonc 做 dry-run。通过后再 Finalize Confirm。
6. 完成后只汇报 Worker 名称、主机名、请求是否成功，不要输出 Secret 或 Token。提醒操作者去 Admin 同步域名、开生成、签发 Bitwarden Token。

参数格式以脚本校验为准：AccessTeamDomain 必须是 https 的 cloudflareaccess.com Team Domain；AdminOrigin 必须与 AdminHostname 精确对应。命令示例见 README「命令示例」。生产把 Environment 换成 production。\n```\n\n## 使用

### 管理端

登录 Admin 后：同步域名 → 选默认域名 → 按需调整新邮箱容量（默认 100 MB）→ 打开「允许生成」→ 创建 Bitwarden Token。原始 Token **只显示一次**，立刻存进 Bitwarden。最多约两个有效 Token 便于轮换。签发是两阶段（Pending 约 10 分钟，确认后才可鉴权）。

### Bitwarden

用户名生成器 → 转发邮箱别名 → SimpleLogin：

- **Server URL**：Generator 的 HTTPS origin（不要填 Admin / Core）
- **API Key**：管理页展示过一次的原始 Token

请求 Header 是 `Authentication`。查询参数 `hostname` / `mode` **会被忽略**。公开路径仅 `GET /healthz` 和 `POST` / `OPTIONS` `/api/alias/random/new`。

## 安全说明

- 不要去掉 `services[].entrypoint`；Generator / Admin 不绑定 D1，也不持有 MXroute / pepper / `ENC_KEY_V1`
- Admin：密码会话、Origin 校验、双提交 CSRF；重置路径校验 Access JWT 与允许邮箱
- 日志不要写明文密码、原始 Token、MXroute Key、完整认证头
- 丢失 `ENC_KEY_V1` 则对应密文不可恢复；丢失 `TOKEN_PEPPER` 则现有 Token 全部失效
- Bitwarden 无创建幂等键：成功响应丢失后再点一次可能再建一个邮箱

紧急停生成：管理页关掉生成开关。不要为了急救删除 D1 / Core / 密钥 / 上游邮箱。

## 免责声明

- 与 Bitwarden、MXroute、Cloudflare、SimpleLogin **无官方关系**
- 仓库 **未声明开源许可证**
- 仅用于你拥有或被明确授权的域名与邮件账户；须遵守上游条款与当地法律

完整运维、轮换、灾难恢复：[docs/operations.md](docs/operations.md)。
