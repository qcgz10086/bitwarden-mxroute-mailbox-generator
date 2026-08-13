# 部署与运维手册

## 1. 安全边界和命名

本项目部署到 Cloudflare **Workers**。建议预发布与生产使用不同 Cloudflare 账户；若共用账户，至少使用不同 D1、Worker 名称、主机名、Access 应用、MXroute 测试域名和所有密钥。

| 资源 | 预发布 | 生产 |
|---|---|---|
| D1 | `bitwarden-mxroute-staging` | `bitwarden-mxroute-production` |
| Core | `bitwarden-mxroute-core-staging` | `bitwarden-mxroute-core` |
| Generator | `bitwarden-mxroute-generator-staging` | `bitwarden-mxroute-generator` |
| Admin | `bitwarden-mxroute-admin-staging` | `bitwarden-mxroute-admin` |

仓库中的三个 Wrangler 配置只用于本地测试模板，部署脚本绝不修改它们。脚本为每个环境生成 `.wrangler/environments/<environment>/{core,generator,admin}.jsonc`；该目录被 Git 忽略。生成时固定并复核 Cloudflare Account ID、环境 Worker 名称、D1 名称/ID、Generator/Admin 的 Core 服务目标、`workers_dev=false` 和 Core 无公网路由，预发布不能覆盖或绑定生产资源。

前置条件：PowerShell 7+、Node.js 22+、`npm ci` 完成、Wrangler 已登录、已人工从 Cloudflare 仪表板复制目标账户的 32 位 Account ID、两个公开 HTTPS 主机名（Generator/Admin）、MXroute API 凭据、至少一个已在 MXroute 配置好的域名。Cloudflare 和身份提供商账号都启用 MFA；部署令牌只授予该 Account ID 下所需的 Workers、D1、路由和 Access 最小权限。脚本可选 `-Profile <wrangler-profile>`，并从 `wrangler whoami` 输出提取所有 Account ID，只有明确包含预期值才继续。

## 2. 部署顺序

以下示例先部署预发布。运行会修改远程状态的命令前先使用 `-WhatIf` 或 `--dry-run`。

### 2.1 Prepare：创建 D1 和私有 Core shell

```powershell
npx wrangler whoami
$accountId = '0123456789abcdef0123456789abcdef' # 从 Cloudflare 仪表板复制
.\scripts\bootstrap-cloudflare.ps1 -Environment staging -AccountId $accountId -Phase Prepare -Profile personal -WhatIf
.\scripts\bootstrap-cloudflare.ps1 -Environment staging -AccountId $accountId -Phase Prepare -Profile personal -Confirm
```

Prepare 只接受 `staging`/`production`，先完成账户、项目路径、Node、连续的 `0001.sql`、`0002.sql`、三个生成配置和服务绑定校验。它按精确环境名称查询 D1；不存在时只对生成的 Core 配置执行 `d1 create --binding DB --update-config`。随后部署一个使用真实 Core 代码但没有 route、`workers.dev`、Custom Domain 或 cron 的私有 shell，使下一步 `secret list/put` 有确定的目标。此时 Core 没有公网入口，也不会运行恢复计划任务；脚本不会让重定向的 Secret stdin 被 Wrangler 的“是否创建 Worker”提示占用。

### 2.2 设置 Core Secret

Secret 不作为参数出现，也不写入命令历史、文件或脚本输出：

```powershell
.\scripts\set-secrets.ps1 -Environment staging -AccountId $accountId -Profile personal -WhatIf
.\scripts\set-secrets.ps1 -Environment staging -AccountId $accountId -Profile personal -Confirm
```

脚本对 `MXROUTE_SERVER`、`MXROUTE_USERNAME`、`MXROUTE_API_KEY` 使用受保护的交互输入；`TOKEN_PEPPER` 和 `ENC_KEY_V1` 在本机用 `RandomNumberGenerator.Fill` 生成 32 字节随机值，并直接送入 `wrangler secret put` 的标准输入。Wrangler 输出被丢弃，只显示 Secret 名称和 `SET`/`PRESENT`。已有生成密钥不会被覆盖；`-RotateMxroute` 只轮换三项 MXroute 值。

脚本要求 Prepare 创建的 Core shell 已存在；`secret list` 失败时立即停止，不会把 Secret 内容送进一个确认提示。每次写入前再次验证 Account ID、环境生成配置、Worker 名称、D1 和服务绑定。不要跳过 Prepare，也不要手工用 `--value` 设置 Secret。

### 2.3 配置非 Secret 变量和服务绑定

Admin 运行时必须有以下非 Secret 变量：

- `ACCESS_TEAM_DOMAIN`：完整 Team Domain，例如 `https://team.cloudflareaccess.com`，不能带路径。
- `ACCESS_AUD`：Access 应用的 Application Audience (AUD) tag。
- `ADMIN_EMAILS`：允许的管理员邮箱，逗号分隔。
- `ADMIN_ORIGIN`：Admin 的精确 origin，例如 `https://mail-admin.example.com`，不能有结尾 `/`。

这些值由 Finalize 参数写入被忽略的环境 Admin 配置；它们不是密码，但仍要经过变更审查。确认：

- Core 配置只有 `DB` 和五项 Secret，`workers_dev` 为 `false`，没有 `routes`。
- Generator 只有 `CORE`、`PREAUTH_RATE_LIMITER`（30/60 秒）和 `TOKEN_RATE_LIMITER`（5/60 秒）。
- Admin 只有 `CORE`、`ASSETS` 和上述四项变量。
- Generator/Admin 的 `CORE` 指向同一环境的 Core。

### 2.4 创建 Access，再 Finalize 迁移和发布

```powershell
npm run check
npm run build
npm audit --omit=dev
$configRoot = '.wrangler/environments/staging'
npx wrangler deploy --dry-run --config "$configRoot/core.jsonc" --profile personal
npx wrangler deploy --dry-run --config "$configRoot/generator.jsonc" --profile personal
npx wrangler deploy --dry-run --config "$configRoot/admin.jsonc" --profile personal
```

先按 2.5 创建保护 Admin 主机名的 Access 应用和 MFA policy，取得 Team Domain/AUD。确认 Access policy 已存在后执行：

```powershell
.\scripts\bootstrap-cloudflare.ps1 `
  -Environment staging -AccountId $accountId -Phase Finalize -Profile personal `
  -AccessTeamDomain 'https://team.cloudflareaccess.com' -AccessAud '复制的-aud-tag' `
  -AdminEmails 'admin@example.com' -AdminOrigin 'https://mail-admin.example.com' `
  -GeneratorHostname 'generator.example.com' -AdminHostname 'mail-admin.example.com' -WhatIf

# 核对 WhatIf 中的 account/environment/config/database/workers/domains 后改用 -Confirm
```

Finalize 再次验证远程 D1 ID和五项 Core Secret，之后按顺序应用尚未执行的迁移、部署带 cron 的 Core、发布 Generator/Admin Custom Domain并生成类型。Core 始终没有 route、Custom Domain 或 `workers.dev` URL。Generator 的公开路径只有 `POST/OPTIONS /api/alias/random/new` 和 `GET /healthz`。不要手工重排、改写或跳过已上线迁移。

### 2.5 Cloudflare Access

1. 在 Zero Trust 创建 Self-hosted Access application，域名为 Admin 自定义域名，保护 `/*`。
2. 建立只允许指定管理员身份的 Allow policy；要求身份提供商 MFA。建议会话 15–30 分钟。
3. 从应用复制 AUD tag 到 `ACCESS_AUD`；Team Domain 填入 `ACCESS_TEAM_DOMAIN`。
4. `ADMIN_EMAILS` 与 Allow policy 使用同一组规范化邮箱；`ADMIN_ORIGIN` 与浏览器地址栏 origin 完全一致。
5. 用未登录/无权限的浏览器确认请求在到达 Worker 前被 Access 拦截；再登录确认管理页可用。Access 是第一层，Admin Worker 的 JWT/邮箱验证是第二层。

### 2.6 初始化管理数据

登录管理页后依次执行：

1. “同步域名”，确认所有期望 MXroute 域名出现；不存在的旧域名只会变为 inactive。
2. 选择一个 active 域名作为默认域名。
3. 保持默认新邮箱容量 `100 MB`、随机前缀长度 `12`；按 MXroute 每分钟写入限制设置每日/总量上限。
4. 确认“允许生成”已开启。
5. 创建一个命名清晰的 Bitwarden Token。原始 Token 只显示一次，立即保存到 Bitwarden；D1 只保存 peppered HMAC。最多同时有两个有效 Token，便于轮换。

### 2.7 Bitwarden 桌面和手机

两端分别进入“用户名生成器”，选择“转发邮箱别名”→“SimpleLogin”：

- Server URL：Generator 的 HTTPS origin，例如 `https://generator.example.com`（不要填 Admin/Core）。
- API Key：管理页刚显示一次的原始 Bitwarden Token。

保存后生成。Bitwarden 会向 `POST /api/alias/random/new` 发送 `Authentication` header；请求里的 `hostname`/`mode` 会被忽略。成功只返回邮箱地址，绝不返回独立的 18 位邮箱密码。密码只在 Access 管理页经显式“显示密码”操作解密。

## 3. 预发布真实烟测（必须由操作者完成）

本清单会创建、登录、重置和永久删除真实 MXroute 邮箱；本地单元/集成测试不能替代，也不能标记为完成。使用一个可丢弃域名，记录 request ID，不记录任何密码或 Token。

- [ ] Bitwarden 桌面端创建地址，地址是默认测试域名上的 12 位允许字符随机串。
- [ ] Bitwarden 手机端另建一个不同地址。
- [ ] MXroute 显示两个邮箱容量均为 100 MB。
- [ ] 管理页逐个显示密码；两者严格 18 位，均可登录对应邮箱。
- [ ] 重置其中一个密码；旧密码不能登录，新 18 位密码能登录。
- [ ] 输入完整邮箱确认后永久删除；MXroute 查询确认账号不存在，管理页记录消失。
- [ ] 用无效和已撤销 Token 请求 Generator，均返回 401 且响应无敏感字段。
- [ ] 无 Access 会话/不在允许邮箱列表的浏览器无法打开 Admin。
- [ ] 导出预发布 D1，确认没有明文邮箱密码、原始 Token、MXroute Key 或完整认证 header。
- [ ] 检查 Worker 日志、API 响应、浏览器存储和构建后的 Admin 资产，无上述敏感值。

删除是 MXroute 永久删除，不提供单邮箱“停用”。但是 Cloudflare D1 Time Travel 在恢复窗口内仍可能保留**历史密文**：免费计划通常 7 天，付费计划最长 30 天。上线时以 Cloudflare 当前计划页面/仪表板显示的实际保留期为准，并把这一点纳入删除告知。

## 4. 日常运维

### 紧急停止生成

首选在管理页设置 `generationEnabled=false`；Generator 随后返回临时不可用，已有邮箱和管理功能不受影响。若 Admin 不可用，在 Cloudflare 移除 Generator 的 Custom Domain/route，或部署一个经过审查的维护版本。不要删除 D1、Core、密钥或 MXroute 邮箱。恢复前查明原因，再在管理页开启并做一次测试生成。

### Bitwarden Token 轮换

在管理页创建第二个 Token，把桌面和手机都改为新 Token并各测试一次，然后撤销旧 Token。不要先撤销旧 Token；不要把原始 Token放进日志、工单或命令行。若 `TOKEN_PEPPER` 丢失，现有 Token 全部无法验证；当前版本没有无中断 pepper 轮换机制，应在维护窗口禁用生成、更新 pepper、重新创建/配置 Token 后再开启。

### MXroute API Key 轮换

先在 MXroute 创建/启用新 Key，在管理页关闭生成并等待进行中的请求结束，然后在维护窗口执行：

```powershell
.\scripts\set-secrets.ps1 -Environment production -AccountId $accountId -Profile personal -RotateMxroute -Confirm
```

对域名同步、创建/重置/删除各做预发布测试，再撤销旧 Key。此开关会重新输入 Server、Username、API Key，避免混用一组凭据。

### AES 密钥分阶段轮换

**绝不能覆盖或删除 `ENC_KEY_V1`。** 当前代码只读取 V1，尚未提供在线重加密命令，因此轮换必须先做一个经测试的代码/迁移版本：

1. 新增 `ENC_KEY_V2` Secret，但保留 V1；代码同时读取 `{1: V1, 2: V2}`，新写入使用版本 2。
2. 通过受 Access 保护、可审计、可重试的批处理逐条解密 V1 并用新 nonce/AAD 重加密为 V2；每批前做 D1 bookmark。
3. 查询确认所有当前与候选密码的 key version 都为 2，并在预发布抽样登录、重置、恢复。
4. 先部署不再写 V1 但仍可读 V1 的版本，观察完整恢复窗口。
5. 最后部署移除 V1 读取的版本，再删除 `ENC_KEY_V1`。任何一步失败都保留两把钥匙并回滚代码，不能回滚到只认识 V1 的代码后继续写 V2。

### 失败状态恢复

Core 每五分钟运行恢复任务，有限批次处理 `pending`、`resetting/reset_unknown` 和仍处于 `deleting` 的记录；当前 cron **不会自动选择 `delete_failed`**。超时场景保留加密候选密码并幂等重试，避免 MXroute 已改密码而本地丢失。查看管理页状态和审计 request ID；不要直接编辑密文、nonce、状态或计数。`delete_failed` 必须由管理员在管理页确认完整邮箱后手工重试永久删除。上游持续故障时先关闭生成，修复凭据/服务后再手工重试，并让定时任务处理其他可恢复状态。

### 日志和导出脱敏

只记录 request ID、稳定错误码、动作、结果和必要邮箱；禁止记录邮箱密码/密文、原始 Token、Token HMAC、MXroute 凭据、`Authentication`、`Cf-Access-Jwt-Assertion`、Cookie、CSRF 值或上游原始响应。共享日志/截图前再次搜索这些字段。D1 导出属于敏感备份，即使只有密文也要加密存储、限制访问并按保留策略销毁。

## 5. 回滚、D1 恢复和灾难处理

Worker 回滚与数据库回滚是两件事。先关闭生成并保存当前 D1 Time Travel bookmark；将三个 Worker 回滚到彼此兼容且认识当前 schema/key version 的已知版本。代码回滚不会撤销 D1 迁移或 MXroute 写操作，绝不能运行破坏性“down migration”。

需要恢复 D1 时，在 Cloudflare D1 Time Travel 中选删除/错误发生前的 bookmark 或时间点，优先恢复到**新数据库**并离线核对，再在维护窗口切换 Core 绑定。免费/付费恢复窗口通常分别为 7/最长 30 天，必须以当前账户显示为准。恢复旧快照可能重新出现已从 MXroute 永久删除的邮箱**密文记录**；它不会在 MXroute 重建邮箱。切换后先保持生成关闭，核对域名、默认设置、Token 状态和异常状态，再进行最小烟测。

密钥丢失处理：不要轮换覆盖来“修复”。丢失 AES key 的对应密文不可恢复；从受控 Secret/灾备恢复同版本 key。MXroute 凭据泄漏则先在上游撤销，再更新 Worker Secret。Cloudflare/Access 账号疑似被接管时移除公开 Generator 路由、吊销会话与部署令牌、轮换所有上游凭据，完成 D1/审计比对后再恢复服务。

## 6. 上线前最终门禁

```powershell
npm run check
npm run build
npm audit --omit=dev
$configRoot = '.wrangler/environments/staging'
npx wrangler deploy --dry-run --config "$configRoot/core.jsonc" --profile personal
npx wrangler deploy --dry-run --config "$configRoot/generator.jsonc" --profile personal
npx wrangler deploy --dry-run --config "$configRoot/admin.jsonc" --profile personal
pwsh -File scripts/test-operations.ps1
New-Item -ItemType Directory -Force work/types | Out-Null
npx wrangler types work/types/core.d.ts --include-runtime false --env-interface CoreGeneratedEnv --config "$configRoot/core.jsonc" --profile personal
npx wrangler types work/types/generator.d.ts --include-runtime false --env-interface GeneratorGeneratedEnv --config "$configRoot/generator.jsonc" --profile personal
npx wrangler types work/types/admin.d.ts --include-runtime false --env-interface AdminGeneratedEnv --config "$configRoot/admin.jsonc" --profile personal
git diff --check
git status --short
```

人工检查三份生成的环境类型和 dry-run 输出：D1/五项 Secret 只在 Core；Generator/Admin 不得出现这些绑定；Core 没有 route 且 `workers_dev=false`。`work/` 已被 Git 忽略，这些审计类型不能提交。完成第 3 节的真实桌面/手机烟测、日志/导出/资产泄漏检查和代码评审后，才能把相同已审核版本推广到生产。
