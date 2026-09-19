---
description: "Login gate, TOTP MFA, signed sessions, and workspace-scoped account isolation for the DeepSeek Harness Web GUI"
---

# dsh-plugin-auth-gate

English | [中文](#中文)

A DeepSeek Harness bundle that puts the whole Web surface behind a login gate:

- **Login gate** — every HTTP route (including the SPA fallback and `/api`)
  and every WebSocket upgrade requires a valid session. Unauthenticated
  browsers are redirected to `/login?next=…`; API clients receive
  `401` JSON. Passwords are stored with **scrypt** (N=16384, per-user salt,
  constant-time compare). Login failures are rate limited per
  (client, username) with escalating lockout, persisted across restarts. The
  **first administrator can only be created from the machine itself**
  (loopback check on `/auth/bootstrap`), and the bootstrap endpoint
  disappears once an account exists.
- **MFA (two-step verification)** — standard RFC 6238 TOTP (SHA-1, 6 digits,
  30 s step, ±1 step drift window), compatible with Google Authenticator,
  1Password, Authy, and FreeOTP. Setup shows the `otpauth://` URI as a QR
  code (a dependency-free QR encoder, verified against the RFC test vectors
  and real decoders) plus the secret for manual entry, and issues **10
  one-time backup codes** (stored as SHA-256 digests, burned on use).
  Administrators can disable MFA for any account
  (`POST /auth/mfa/disable` or `scripts/admin.mjs disable-mfa`); self-service
  disable requires the account password.
- **User management (initial admin only)** — `/admin/users` renders the
  bundled user-management panel (create accounts, optionally as ordinary
  admins, delete, disable MFA, sign out everyone). The module belongs **only
  to the initial administrator** — the account created by first-entry
  bootstrap (`initial` flag in the store). Other admins are ordinary roles:
  they get a 403 page and their API calls to `/auth/users*`,
  `/auth/mfa/disable` (other accounts), and `/auth/logout-all {scope:"all"}`
  are rejected. The initial administrator cannot be deleted.
- **Sessions & permissions** — the cookie carries only
  `sid + HMAC-SHA256(workspace secret, sid)`; the session row lives in the
  workspace store, so password change, logout, logout-all, expiry, and
  administrator deletion all revoke access immediately.
  **Workspace session isolation**: accounts, sessions, MFA secrets, lockout
  counters, and the signing secret live in `<workspace>/.dsh-auth`, and a
  session is bound to its workspace id — a cookie minted for workspace A
  never authenticates workspace B.
- **UI & performance** — the login page follows the DSH light/dark themes
  (auto via `prefers-color-scheme`, manual toggle persisted in the
  `dsh_theme` cookie) and both languages (zh/en from `Accept-Language` with a
  manual switch in `dsh_locale`). Remote responses are gzip-compressed
  automatically (the patch keeps the transport's `compression: gzip`); all
  auth endpoints are `Cache-Control: no-store`, so edge caches can hold the
  login page's immutable assets without ever caching auth state.

## Install

```sh
# inside the profile directory (dsh --profile web's home)
pnpm add dsh-plugin-auth-gate
```

Enable the plugin page's install flow in the Web sidebar **Plugins** page, or
add the bundle to the profile's `package.json`:

```json
{
  "dsh": {
    "profile": {
      "bundles": ["dsh-base", "dsh-web-app", "dsh-plugin-auth-gate"]
    }
  }
}
```

The bundle patch (`cordis.patch.yml`) overrides the transport's `webserver`
row with `dsh-plugin-auth-gate/webserver` (`GatedWebServer`). Because the gate
lives inside the service every other row injects, **route registration order
carries no security weight** — rows registered before or after the gate all
pass through it. Install the bundle **after** `dsh-web-app`; the patch
restates the webserver row's whole config (host/port stay driven by
`--host`/`--port` through `webStartup`).

### Configuration

The `auth` block on the `webserver` row:

| Field | Default | Meaning |
| --- | --- | --- |
| `dataDir` | `.dsh-auth` | Account/session storage; absolute, or relative to the server's workspace root. |
| `cookieName` | `dsh_auth` | Session cookie name. |
| `sessionTtlHours` | `168` | Session lifetime in hours. |
| `publicPaths` | `[]` | Extra exact paths served without a session (e.g. a health check). |
| `trustProxy` | `false` | Honor `X-Forwarded-For`/`-Proto` from a trusted reverse proxy (sets `Secure` on cookies behind HTTPS). |
| `issuer` | `DSH` | Issuer name shown in authenticator apps. |

## First run

Open `http://127.0.0.1:<port>/` **on the machine**. The login page shows
*Create the administrator* (zh: 创建管理员账号); create the account, sign in,
then enable MFA from `POST /auth/mfa/setup` → scan the QR → `POST
/auth/mfa/confirm` and store the returned backup codes.

Or from the shell:

```sh
node scripts/admin.mjs .dsh-auth create-admin alice   # becomes the initial administrator
```

### 用户管理模块（仅初始管理员）

- 本机首次打开首页 → 创建管理员（该账号即**初始管理员**，store 中带
  `initial` 标记）。
- 初始管理员访问 `/admin/users` 打开用户管理面板：创建用户（可授予普通
  管理员角色）、删除用户、关闭指定用户的 MFA、全员登出。
- 其他管理员与普通用户访问 `/admin/users` 返回 403 页面；对应 API
  （`/auth/users*`、为他人关闭 MFA、全员登出）一律拒绝。
- 初始管理员不可删除，保证每个工作区始终存在唯一的管理主体。

```sh
node scripts/admin.mjs .dsh-auth list
node scripts/admin.mjs .dsh-auth disable-mfa bob   # administrator override
node scripts/admin.mjs .dsh-auth logout-all
```

## Control-plane endpoints

| Method & path | Auth | Purpose |
| --- | --- | --- |
| `GET /login` | public | Login page (bootstrap mode when no account exists and the request is loopback). |
| `POST /auth/bootstrap` | loopback + empty store | Create the first administrator. |
| `POST /auth/login` | public | Password login; responds `{mfaRequired:true}` when MFA is on, then accepts `otp` (TOTP or backup code). |
| `POST /auth/logout` | session | Destroy the current session. |
| `GET /auth/session` | session | Current account, workspace id, MFA state. |
| `POST /auth/password` | session | Change own password (signs out all sessions). |
| `POST /auth/mfa/setup` · `GET /auth/mfa/qr.svg` · `POST /auth/mfa/confirm` | session | TOTP enrollment; confirm returns the 10 backup codes once. |
| `POST /auth/mfa/codes` | session + code | Regenerate the 10 backup codes. |
| `POST /auth/mfa/disable` | session (self: + password) · admin (any account) | Turn MFA off. |
| `GET /auth/users` · `POST /auth/users` · `POST /auth/users/delete` | admin | Account management. |
| `POST /auth/logout-all` | admin (`scope:"all"`) or self | Invalidate sessions. |
| `GET /admin/users` | initial admin | User-management panel (403 page for every other session). |
| `GET /auth/health` | public | Liveness + workspace id + whether bootstrap is pending. |

All state-changing endpoints require `Content-Type: application/json`
(cross-site form posts cannot send it), and the session cookie is
`HttpOnly; SameSite=Lax` (+`Secure` behind a trusted HTTPS proxy).

## Development

```sh
pnpm install          # or rely on a profile that already resolves the deps
node tests/e2e.mjs          # 24-assertion gate/MFA integration test
node tests/e2e-admin.mjs    # 21-assertion initial-admin user-management test
```

`lib/qrcode.js`, `lib/totp.js`, and `lib/store.js` are dependency-free and
unit-testable in isolation. The e2e test boots `GatedWebServer` on an
OS-assigned port and exercises the gate, bootstrap, rate limiting headers,
gzip, TOTP enrollment/login, backup codes, MFA disable, and WebSocket upgrade
gating.

## Security notes

- scrypt parameters are per-user-recorded (`scrypt$N$r$p$salt$hash`), so they
  can be raised later without invalidating old hashes.
- Failed logins persist and lock with exponential backoff: 5 failures lock
  for 15 min, doubling per further 5, capped at 24 h. Successful login clears
  the counter.
- The signing secret lives in `<dataDir>/secret.key` (0600). Deleting it
  invalidates every cookie (sessions in the store remain but stop verifying).
- Unknown user logins burn comparable scrypt time to foil user enumeration
  and timing analysis.

---

<a id="中文"></a>
## 中文

# dsh-plugin-auth-gate 登录门禁与工作区用户隔离

一个把 DeepSeek Harness Web 界面整体置于登录门禁之后的 bundle：

- **登录门禁** — 所有 HTTP 路由（含 SPA fallback 与 `/api`）与所有
  WebSocket 升级都要求有效会话；未登录浏览器 302 到 `/login?next=…`，API
  返回 `401` JSON。密码使用 **scrypt**（N=16384、每用户随机盐、常数时间
  比较）。按（客户端 IP，用户名）滑动窗口限速，5 次失败锁定 15 分钟并指数
  递增，跨重启持久化。**首个管理员仅限本机创建**（`/auth/bootstrap` 的
  loopback 检查），账号存在后该端点自动失效。
- **MFA 两步验证** — 标准 RFC 6238 TOTP（SHA-1、6 位、30 秒、±1 步漂移窗口），
  兼容 Google Authenticator、1Password、Authy、FreeOTP。绑定提供
  `otpauth://` 二维码（零依赖 QR 编码器，经 RFC 测试向量与真实解码器验证）
  与手动录入密钥，并签发 **10 个一次性备用码**（SHA-256 摘要存储，用后作
  废）。管理员可关闭任意账号的 MFA（接口或 `scripts/admin.mjs`）；自助
  关闭需验证账号密码。
- **会话与权限** — Cookie 只携带 `sid + HMAC-SHA256(工作区密钥, sid)`，会话
  行存于工作区存储，改密 / 登出 / 全端登出 / 过期 / 删除账号立即生效。
  **工作区会话隔离** — 账号、会话、MFA 密钥、锁定计数、签名密钥都位于
  `<工作区>/.dsh-auth`，会话绑定工作区 id：为工作区 A 签发的 Cookie 无法
  访问工作区 B。
- **界面与性能** — 登录页跟随 DSH 浅色 / 深色主题（`prefers-color-scheme`
  自动 + `dsh_theme` Cookie 手动切换）与中英文语言（`Accept-Language` 自动 +
  手动切换）。远程响应自动 gzip（bundle patch 保持传输层
  `compression: gzip`）；所有鉴权接口 `Cache-Control: no-store`，边缘缓存
  可安全缓存登录页静态资源。

安装与配置见上文英文文档；首个管理员在本机打开首页即可创建，或用
`node scripts/admin.mjs .dsh-auth create-admin <name>`。
