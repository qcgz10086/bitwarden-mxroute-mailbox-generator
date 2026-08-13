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

完整的 Cloudflare 初始化、Access、Bitwarden 配置、轮换、恢复和真实预发布验收步骤见 [docs/operations.md](docs/operations.md)。脚本支持 `-WhatIf`，先预览：

```powershell
.\scripts\bootstrap-cloudflare.ps1 -Environment staging -WhatIf
.\scripts\set-secrets.ps1 -Environment staging -WhatIf
```

不要提交 `.dev.vars`、`.env`、Wrangler 状态目录或生成的环境配置。真实部署和桌面/手机烟测需要操作者登录 Cloudflare、MXroute 和 Bitwarden 后完成；本仓库的本地测试不会执行这些外部变更。
