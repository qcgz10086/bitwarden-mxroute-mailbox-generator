# Bitwarden 与 MXroute 独立邮箱生成器设计

日期：2026-08-13  
状态：已确认，等待规格审阅

## 1. 目标

构建一套部署在 Cloudflare Workers 上的服务，使原版 Bitwarden 浏览器扩展、桌面端和手机端能够通过“SimpleLogin 自托管服务器”设置，调用 MXroute API 创建真实的独立邮箱账户。

每次生成必须满足：

- 使用管理端选择的默认 MXroute 域名。
- 本地部分为 12 位密码学安全随机字符串。
- 每个邮箱拥有独立的 18 位随机密码。
- 邮箱容量固定为 100 MB；管理员之后可调整默认值。
- Bitwarden 只接收邮箱地址，不接收邮箱密码。
- 邮箱密码经过 AES-256-GCM 加密后存入 Cloudflare D1。
- 管理员通过 Cloudflare Access 保护的页面查看、复制、重置或永久删除邮箱。
- 支持同步多个 MXroute 域名并设置一个默认域名。
- 不提供“停用”功能，因为给定 MXroute API 不支持暂停单个邮箱。

## 2. 非目标

- 不修改或维护 Bitwarden 客户端分支。
- 不实现完整的 SimpleLogin 服务，只实现 Bitwarden 生成邮箱所需的最小兼容接口。
- 不提供邮件阅读、发送或 Webmail 功能。
- 不实现邮箱转发别名或 catch-all 模式。
- 不声称能够提前清除 D1 Time Travel 恢复窗口中的历史密文。

## 3. 外部依赖与约束

### 3.1 MXroute

基础地址为 `https://api.mxroute.com`，所有请求使用以下 Header：

- `X-Server`
- `X-Username`
- `X-API-Key`

本系统使用以下接口：

- `GET /domains`：同步可用域名。
- `POST /domains/{domain}/email-accounts`：创建邮箱。
- `GET /domains/{domain}/email-accounts/{user}`：查询与超时恢复。
- `PATCH /domains/{domain}/email-accounts/{user}`：重置密码或调整容量。
- `DELETE /domains/{domain}/email-accounts/{user}`：永久删除邮箱。

MXroute 写操作限制为每分钟 20 次。本系统的默认创建限额必须低于该值。

### 3.2 Bitwarden / SimpleLogin 兼容层

Bitwarden 配置为：

- 用户名类型：转发邮箱别名。
- 服务：SimpleLogin。
- Server URL：Generator Worker 的 HTTPS 地址。
- API Key：管理页面生成的一次性可见 Token。

兼容接口：

```http
POST /api/alias/random/new
Authentication: <token>
Content-Type: application/json
```

`hostname` 与 `mode` 查询参数可以出现，但系统不得用它们控制域名、上游 URL 或邮箱前缀；系统只使用管理端配置的默认域名和纯随机前缀。

成功响应使用 HTTP 201：

```json
{
  "id": 123,
  "email": "k7m4x9q2wp6c@example.com",
  "enabled": true,
  "creation_timestamp": 1786612345,
  "name": null,
  "note": null,
  "alias": "k7m4x9q2wp6c@example.com"
}
```

`alias` 重复 `email`：Bitwarden 当前 SimpleLogin 集成从响应 JSON 读取 `json.alias` 作为生成的转发地址；缺少该字段时 Bitwarden 会报 "Unknown SimpleLogin error"（即使邮箱已在 MXroute 创建成功）。保留完整 alias 对象以兼容旧客户端读取 `email`。

错误响应使用 SimpleLogin 兼容格式：

```json
{
  "error": "human-readable message"
}
```

## 4. 架构

系统由三个独立 Worker 组成：

```text
Bitwarden
    |
    v
Generator Worker（公网、Token 鉴权、CORS、边缘限流）
    |
    | Cloudflare Service Binding RPC
    v
Core Worker（无公网路由）
    ^
    | Cloudflare Service Binding RPC
    |
Admin Worker（Cloudflare Access、管理页面、JWT 验证）
```

### 4.1 Generator Worker

职责：

- 仅开放 SimpleLogin 最小兼容接口和健康检查。
- 处理浏览器扩展所需的 CORS 预检。
- 只允许必要的 HTTP 方法和 Header。
- 执行 Cloudflare 边缘限流。
- 将 Token 和生成请求通过 Service Binding 交给 Core Worker。
- 返回兼容响应，绝不返回密码或 MXroute 原始响应。

Generator Worker 不绑定 D1，不持有 MXroute 凭据或密码加密密钥。

### 4.2 Admin Worker

职责：

- 提供静态管理页面和管理 API。
- 置于 Cloudflare Access 后面。
- 在 Worker 内再次验证 `Cf-Access-Jwt-Assertion` 的签名、`iss`、`aud` 和过期时间。
- 可选限制允许的管理员邮箱地址。
- 验证 Origin 与 CSRF Token。
- 将经过验证的管理员身份传给 Core Worker。

Admin Worker 不绑定 D1，不持有 MXroute 凭据或密码加密密钥。

### 4.3 Core Worker

职责：

- 只能通过 Service Binding RPC 调用，不开放公网路由。
- 独占 D1 绑定、MXroute 凭据、Token HMAC pepper 和 AES-GCM 密钥。
- 验证 Bitwarden Token。
- 执行权威创建额度、总量限制和所有状态转换。
- 创建、查询、重置和删除 MXroute 邮箱。
- 加密、解密和轮换邮箱密码。
- 记录不含敏感数据的审计事件。

Core Worker 的 `workers.dev` 与预览公网入口必须禁用。

## 5. 数据模型

### 5.1 `domains`

- `domain TEXT PRIMARY KEY`
- `is_active INTEGER NOT NULL`
- `synced_at TEXT NOT NULL`

同步时不直接删除旧域名。MXroute 中不再存在的域名标记为 inactive，不能用于新建邮箱；已有邮箱记录仍可显示。

### 5.2 `settings`

- `default_domain`
- `mailbox_quota_mb`，默认 100。
- `prefix_length`，固定初始值 12。
- `daily_creation_limit`，默认 30。
- `total_managed_limit`，默认 500；统计所有尚未永久删除的记录，包括 `pending`、`active`、重置中和删除失败状态。
- `generation_enabled`，默认 true。

设置默认域名前必须验证该域名存在且为 active。任意时刻最多只能有一个默认域名。

### 5.3 `mailboxes`

- `id INTEGER PRIMARY KEY AUTOINCREMENT`
- `public_id TEXT UNIQUE NOT NULL`
- `email TEXT UNIQUE NOT NULL`
- `local_part TEXT NOT NULL`
- `domain TEXT NOT NULL`
- `password_ciphertext BLOB NOT NULL`
- `password_nonce BLOB NOT NULL`
- `encryption_key_version INTEGER NOT NULL`
- `next_password_ciphertext BLOB NULL`
- `next_password_nonce BLOB NULL`
- `quota_mb INTEGER NOT NULL`
- `status TEXT NOT NULL`
- `failure_code TEXT NULL`
- `created_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`

状态值：

- `pending`
- `active`
- `failed`
- `resetting`
- `reset_unknown`
- `deleting`
- `delete_failed`

### 5.4 `api_tokens`

- `id TEXT PRIMARY KEY`
- `name TEXT NOT NULL`
- `token_hmac BLOB UNIQUE NOT NULL`
- `created_at TEXT NOT NULL`
- `last_used_at TEXT NULL`
- `revoked_at TEXT NULL`

原始 Token 由 Web Crypto 生成，只在创建响应中显示一次。D1 只保存带 pepper 的 HMAC。允许同时存在两个有效 Token，以便无中断轮换。

### 5.5 `creation_counters`

- `date TEXT NOT NULL`
- `token_id TEXT NOT NULL`
- `count INTEGER NOT NULL`
- 复合主键：`date, token_id`

Core Worker 使用带条件的更新执行每日硬限制。边缘 Rate Limiting 仅用于快速削峰，不能代替该表。

### 5.6 `audit_events`

- `id TEXT PRIMARY KEY`
- `actor_type TEXT NOT NULL`
- `actor_id TEXT NOT NULL`
- `action TEXT NOT NULL`
- `email TEXT NULL`
- `result TEXT NOT NULL`
- `error_code TEXT NULL`
- `request_id TEXT NOT NULL`
- `created_at TEXT NOT NULL`

审计记录不得包含明文或密文密码、原始 Token、MXroute Key、完整认证 Header 或包含敏感数据的上游响应。

## 6. 密码与 Token 安全

邮箱密码使用 Web Crypto AES-256-GCM：

- 每条密码使用独立、不可复用的 96 位随机 nonce。
- AAD 为 `public_id | email | key_version`。
- 密文包含 GCM Authentication Tag。
- D1 保存 `key_version`，Worker Secrets 保存版本化密钥，例如 `ENC_KEY_V1`。
- 轮换时先添加新密钥，再分批重加密，确认所有记录迁移后才移除旧密钥。

邮箱密码为 18 位，必须满足 MXroute 的大写、小写和数字要求，并使用 MXroute 可接受的安全符号集合。

Token 验证使用 HMAC-SHA-256：

- 原始 Token 至少包含 256 位随机熵。
- Core Worker 使用 secret pepper 计算 HMAC，与 D1 中固定长度结果比较。
- 原始 Token、Token Header 和密码不得写入日志。

密码显示接口必须：

- 使用 POST。
- 返回 `Cache-Control: no-store`。
- 不允许 Service Worker、浏览器持久化存储或前端日志记录明文。
- 密码默认隐藏，仅在用户明确操作时解密。

## 7. 创建状态机

1. Generator Worker 验证请求形状并执行边缘限流。
2. Core Worker 验证 Token、紧急开关、每日额度和总受管邮箱上限；`pending` 记录同样占用总量，防止利用上游超时绕过限制。
3. Core Worker验证默认域名存在且 active。
4. 使用 Web Crypto 从去除易混淆字符的字母数字表生成 12 位随机前缀。
5. 生成 18 位随机邮箱密码。
6. 在同一 D1 事务中保留每日额度并写入加密密码及 `pending` 记录。
7. 调用 MXroute 创建 100 MB 邮箱。
8. 成功后更新为 `active`，写审计记录并返回 HTTP 201。
9. 如果 MXroute 返回冲突，原记录标记为 `failed`，释放额度并最多使用新地址重试五次。
10. 明确失败时标记 `failed` 并释放额度。
11. 请求超时或结果不明确时保留 `pending`，返回可重试的 503；后台恢复任务查询该邮箱是否实际存在。

后台恢复：

- 邮箱存在：标记为 `active`。
- 邮箱不存在：标记为 `failed` 并释放额度。
- MXroute 仍不可用：保持 `pending` 并使用有上限的指数退避重试。

## 8. 重置密码状态机

1. 生成并加密候选新密码，写入 `next_password_*`，状态变为 `resetting`。
2. 使用候选密码调用 MXroute PATCH。
3. 成功后将候选密文替换为当前密文，清除 `next_password_*`，状态回到 `active`。
4. 明确失败时清除候选密文并回到 `active`，记录错误。
5. 超时时改为 `reset_unknown`。
6. 恢复任务用同一个候选密码重复 PATCH；该操作对最终密码是幂等的。成功后完成密文切换。

该流程确保 MXroute 已修改密码但 D1 尚未更新时，候选密码仍可恢复。

## 9. 永久删除状态机

1. 管理员必须输入完整邮箱地址确认。
2. Core Worker 验证输入与记录完全一致。
3. 状态改为 `deleting`。
4. 调用 MXroute DELETE。
5. MXroute 返回成功或 NOT_FOUND 时，删除当前 `mailboxes` 记录，并写入不含密码的审计记录。
6. 明确失败或超时且邮箱仍存在时，状态变为 `delete_failed`，管理端允许重试。

界面必须说明：邮箱会从 MXroute 永久删除，但 D1 Time Travel 可能在恢复窗口内保留旧的加密历史记录。免费计划通常为 7 天，付费计划最长 30 天。

## 10. 管理页面

管理页面包括：

- 邮箱列表、分页、搜索、域名筛选和状态筛选。
- 显示、隐藏和复制密码。
- 重置邮箱密码。
- 输入完整邮箱确认后永久删除。
- 同步 MXroute 域名。
- 设置默认域名。
- 调整默认容量、每日创建上限和总受管邮箱上限。
- 紧急关闭或恢复 Bitwarden 生成接口。
- 创建、撤销和轮换 Bitwarden Token。
- 查看审计记录和需要恢复处理的异常状态。

前端要求：

- 严格 Content Security Policy，不加载第三方脚本。
- 所有动态文本使用安全文本节点，不使用不受控的 `innerHTML`。
- 状态变更和密码显示请求验证 Origin 与 CSRF Token。
- Access 会话建议为 15 至 30 分钟，身份提供商启用 MFA。
- 管理 API 返回统一错误码，不显示上游凭据或堆栈。

## 11. CORS 与 HTTP 安全

Generator Worker：

- 仅允许兼容接口所需的 POST 与 OPTIONS。
- 允许 `Authentication` 和 `Content-Type` Header。
- 不使用 Cookie 或浏览器凭据。
- 所有未知路径返回 404。
- 设置适当的 `X-Content-Type-Options` 和禁止缓存 Header。

Admin Worker：

- 验证 Access JWT，而不只是检查 Header 是否存在。
- 验证 Origin 与 CSRF Token。
- 设置 CSP、`frame-ancestors 'none'`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer` 与 `Cache-Control: no-store`。

## 12. 故障处理与一致性

- 所有外部操作生成 request ID，用于审计和关联日志。
- MXroute 5xx、网络错误和 429 使用有上限的指数退避；不得无限重试。
- 429 应读取可用的限流信息并延迟后台恢复任务。
- 创建、重置和删除均采用显式状态机，禁止在状态不明时直接丢弃密文。
- 域名同步失败不得清空现有域名表或改变默认域名。
- Core Worker 不把 MXroute 原始错误直接返回给 Bitwarden或浏览器。

## 13. 测试策略

### 13.1 单元测试

- 随机前缀字符集、长度和冲突重试。
- 密码复杂度。
- AES-GCM 加解密、AAD 防调换和错误密钥失败。
- Token HMAC 验证、撤销和轮换。
- Access JWT 的 `iss`、`aud`、签名和过期验证。
- 每日额度与总量限制。
- 所有状态转换和非法转换拒绝。

### 13.2 契约测试

- Bitwarden/SimpleLogin 请求路径、Header、状态码和响应字段。
- MXroute 五个所需接口的请求格式。
- CORS 预检与浏览器扩展请求。

### 13.3 故障注入测试

- MXroute 冲突、401、404、429、5xx 和超时。
- D1 在创建前、创建后、密码重置中和删除中的写入失败。
- 重复请求、恢复任务重复运行和并发创建。
- Access JWT 缺失、伪造、错误 audience 和过期。

### 13.4 端到端验收

- Bitwarden 浏览器扩展创建真实 MXroute 邮箱。
- Bitwarden 手机端创建真实 MXroute 邮箱。
- 新邮箱容量为 100 MB。
- 管理页显示并复制的密码可以登录邮箱。
- 重置后旧密码失效，新密码有效。
- 永久删除后 MXroute 中不再存在该邮箱。
- 非 Access 用户不能打开管理端。
- 无效或撤销 Token 不能创建邮箱。
- D1 导出中不存在明文邮箱密码。
- 模拟 MXroute 超时和 D1 写入失败时，不产生密码不可恢复的活动邮箱。

## 14. 部署与运维

- 使用独立的开发、预发布和生产环境及独立 D1 数据库。
- 生产 Secret 通过 Worker Secrets 或 Secrets Store 设置，不进入源码、Wrangler 明文配置或终端历史。
- Cloudflare 账户和 Access 身份提供商启用 MFA。
- 部署令牌采用最小权限。
- Core Worker 禁用公网路由。
- 上线前先在测试域名创建、登录、重置和删除一个真实邮箱。
- 定期轮换 MXroute API Key、Bitwarden Token 和加密主密钥。

## 15. 已接受的剩余风险

- Cloudflare 账户或 MXroute 主账户被完全接管时，攻击者可能获得系统控制权。
- D1 Time Travel 会在有限恢复窗口内保留历史密文。
- Bitwarden 不提供请求幂等键；响应在创建成功后丢失时，用户再次点击可能创建第二个邮箱。所有邮箱仍会出现在管理页面中，不会丢失密码。
- Cloudflare 边缘限流是宽松和最终一致的；权威额度必须由 Core Worker 和 D1 执行。

## 16. 参考资料

- Bitwarden 用户名生成器：https://bitwarden.com/en-gb/help/generator/
- SimpleLogin API：https://github.com/simple-login/app/blob/master/docs/api.md
- Cloudflare Service Bindings：https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/rpc/
- Cloudflare Access JWT 验证：https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/
- Cloudflare D1：https://developers.cloudflare.com/d1/get-started/
- Cloudflare D1 Time Travel：https://developers.cloudflare.com/d1/reference/time-travel/
- Cloudflare Workers Secrets：https://developers.cloudflare.com/workers/configuration/secrets/
- Cloudflare Workers Rate Limiting：https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/
