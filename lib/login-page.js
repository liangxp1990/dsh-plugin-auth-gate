/**
 * The login page: one self-contained HTML document with no external fetches.
 * It follows the DSH surface's two themes (auto via prefers-color-scheme, with
 * an explicit light/dark toggle persisted in the dsh_theme cookie) and both
 * languages (zh/en, auto from Accept-Language with a manual switch). Mode,
 * locale, and theme are rendered server-side so the first paint is correct.
 * @module dsh-plugin-auth-gate/login-page
 */

export const LOGIN_PAGE_CACHE = { noStore: true };

const STYLE = `
:root { color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --text:#1a1d21; --muted:#6b7177; --line:#e3e5e8; --accent:#4d6bfe; --accent-text:#fff; --danger:#d92d20; }
@media (prefers-color-scheme: dark) { :root:not([data-theme='light']) { --bg:#141517; --card:#1e2023; --text:#ececee; --muted:#9aa0a6; --line:#33363a; --accent:#6b83ff; --accent-text:#0d0e10; } }
:root[data-theme='dark'] { --bg:#141517; --card:#1e2023; --text:#ececee; --muted:#9aa0a6; --line:#33363a; --accent:#6b83ff; --accent-text:#0d0e10; }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:var(--bg); color:var(--text); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif; }
.card { width:min(380px,calc(100vw - 32px)); background:var(--card); border:1px solid var(--line); border-radius:14px; padding:32px 28px 24px; box-shadow:0 8px 30px rgba(0,0,0,.06); }
.brand { font-weight:700; font-size:17px; margin-bottom:4px; }
.note { color:var(--muted); font-size:13px; margin:0 0 6px; }
.lock { text-align:center; }
label { display:block; font-size:13px; color:var(--muted); margin:14px 0 4px; }
input { width:100%; padding:10px 12px; font:inherit; color:var(--text); background:var(--bg); border:1px solid var(--line); border-radius:8px; outline:none; }
input:focus { border-color:var(--accent); }
button.primary { width:100%; margin-top:20px; padding:11px 12px; font:inherit; font-weight:600; color:var(--accent-text); background:var(--accent); border:0; border-radius:8px; cursor:pointer; }
button.primary:disabled { opacity:.6; cursor:default; }
.bar { display:flex; justify-content:space-between; margin-top:18px; font-size:12px; }
.bar button { background:none; border:0; color:var(--muted); cursor:pointer; font:inherit; }
.bar button:hover { color:var(--text); }
.error { color:var(--danger); font-size:13px; min-height:18px; margin-top:12px; }
.hidden { display:none; }
footer { color:var(--muted); font-size:12px; text-align:center; margin-top:16px; }
`;

const CLIENT_SCRIPT = `
(function () {
  var A = window.__AUTH__;
  var LOCALE = A.locale;
  var THEMES = ["auto", "light", "dark"];

  function $(id) { return document.getElementById(id); }
  function show(el) { el.classList.remove("hidden"); }
  function hide(el) { el.classList.add("hidden"); }
  function text(el, value) { el.textContent = value; }
  function i18n() { return window.__I18N__[LOCALE]; }
  function setCookie(name, value) { document.cookie = name + "=" + value + "; Path=/; Max-Age=31536000; SameSite=Lax"; }

  function applyTheme(theme) {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    text($("theme"), i18n().theme[THEMES.indexOf(theme)]);
  }

  function applyLocale(locale) {
    LOCALE = locale;
    document.documentElement.lang = locale;
    text($("lang"), i18n().lang);
    applyTheme(A.theme);
    if (A.mode === "bootstrap-remote") {
      text($("locked-heading"), i18n().remoteHeading);
      text($("locked-note"), i18n().remoteNote);
      text($("note"), i18n().note);
      show($("locked"));
      hide($("form"));
      return;
    }
    show($("form"));
    var bootstrap = A.mode === "bootstrap";
    text($("heading"), bootstrap ? i18n().bootstrap : i18n().heading);
    text($("note"), bootstrap ? i18n().bootstrapNote : i18n().note);
    text($("username-label"), i18n().username);
    text($("password-label"), i18n().password);
    text($("password2-label"), i18n().confirm);
    text($("otp-label"), i18n().otp);
    text($("otp-hint"), i18n().otpHint);
    text($("footer"), i18n().footer);
    text($("submit"), bootstrap ? i18n().create : i18n().signIn);
    if (bootstrap) { show($("password2-label")); show($("password2")); }
  }

  function fail(message) { text($("error"), message); }

  async function post(path, payload) {
    var response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload || {})
    });
    var value = null;
    try { value = await response.json(); } catch (error) {}
    return { status: response.status, value: value };
  }

  $("form").addEventListener("submit", async function (event) {
    event.preventDefault();
    text($("error"), "");
    var bootstrap = A.mode === "bootstrap";
    var username = $("username").value.trim();
    var password = $("password").value;
    if (bootstrap && password !== $("password2").value) { fail(i18n().mismatch); return; }
    $("submit").disabled = true;
    try {
      var result = await post(bootstrap ? "/auth/bootstrap" : "/auth/login", { username: username, password: password });
      if (result.status === 200 && result.value && result.value.mfaRequired) {
        $("submit").disabled = false;
        show($("otp-label")); show($("otp")); show($("otp-hint"));
        $("otp").focus();
        text($("submit"), i18n().verify);
        return;
      }
      if (result.status === 200) { location.replace(A.next); return; }
      fail(result.value && result.value.error ? result.value.error : "HTTP " + result.status);
    } catch (error) { fail(String(error)); }
    $("submit").disabled = false;
  });

  $("otp").addEventListener("keydown", async function (event) {
    if (event.key !== "Enter") return;
    event.preventDefault();
    var result = await post("/auth/login", {
      username: $("username").value.trim(),
      password: $("password").value,
      otp: $("otp").value.trim()
    });
    if (result.status === 200) location.replace(A.next);
    else fail(result.value && result.value.error ? result.value.error : "HTTP " + result.status);
  });

  $("theme").addEventListener("click", function () {
    A.theme = THEMES[(THEMES.indexOf(A.theme) + 1) % THEMES.length];
    setCookie("dsh_theme", A.theme);
    applyTheme(A.theme);
  });

  $("lang").addEventListener("click", function () {
    LOCALE = LOCALE === "zh" ? "en" : "zh";
    setCookie("dsh_locale", LOCALE);
    applyLocale(LOCALE);
  });

  applyLocale(A.locale);
  $("username").focus();
})();
`;

const I18N = {
  en: {
    heading: 'Sign in',
    bootstrap: 'Create the administrator',
    note: 'Sign in to this DeepSeek Harness workspace.',
    bootstrapNote: 'This workspace has no account yet. The first administrator can only be created from this machine (localhost).',
    username: 'Username',
    password: 'Password',
    confirm: 'Confirm password',
    otp: '2-step code',
    otpHint: '6-digit code from your authenticator app, or a backup code',
    signIn: 'Sign in',
    create: 'Create administrator',
    verify: 'Verify',
    remoteHeading: 'Setup locked',
    remoteNote: 'The first administrator can only be created on the machine running DeepSeek Harness. Open this page locally.',
    mismatch: 'Passwords do not match.',
    theme: ['Theme: auto', 'Theme: light', 'Theme: dark'],
    lang: '中文',
    footer: 'DeepSeek Harness · workspace-scoped accounts'
  },
  zh: {
    heading: '登录',
    bootstrap: '创建管理员账号',
    note: '登录到此 DeepSeek Harness 工作区。',
    bootstrapNote: '该工作区还没有账号。首个管理员仅能在本机（localhost）创建。',
    username: '用户名',
    password: '密码',
    confirm: '确认密码',
    otp: '两步验证码',
    otpHint: '认证器 App 中的 6 位动态码，或备用码',
    signIn: '登录',
    create: '创建管理员',
    verify: '验证',
    remoteHeading: '初始化已锁定',
    remoteNote: '首个管理员仅能在运行 DeepSeek Harness 的本机创建，请在本地打开此页面。',
    mismatch: '两次输入的密码不一致。',
    theme: ['主题：自动', '主题：浅色', '主题：深色'],
    lang: 'English',
    footer: 'DeepSeek Harness · 账号按工作区隔离'
  }
};

/** Render the page for one request. */
export function renderLoginPage({ mode = 'login', locale = 'en', theme = 'auto', next = '/' } = {}) {
  const safeNext = typeof next === 'string' && next.startsWith('/') && !next.startsWith('//') ? next : '/';
  const auth = { mode, locale: locale === 'zh' ? 'zh' : 'en', theme: theme === 'light' || theme === 'dark' ? theme : 'auto', next: safeNext };
  return '<!doctype html>\n<html lang="' + auth.locale + '">\n<head>\n' +
    '<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    '<meta name="color-scheme" content="light dark">\n' +
    '<title>DeepSeek Harness</title>\n' +
    '<style>' + STYLE + '</style>\n</head>\n<body>\n' +
    '<main class="card">\n' +
    '  <div class="brand">DeepSeek Harness</div>\n' +
    '  <p class="note" id="note"></p>\n' +
    '  <form id="form" class="hidden">\n' +
    '    <h2 style="margin:0 0 8px;font-size:18px" id="heading"></h2>\n' +
    '    <label id="username-label" for="username"></label>\n' +
    '    <input id="username" autocomplete="username" required>\n' +
    '    <label id="password-label" for="password"></label>\n' +
    '    <input id="password" type="password" autocomplete="current-password" required>\n' +
    '    <label id="password2-label" for="password2" class="hidden"></label>\n' +
    '    <input id="password2" type="password" autocomplete="new-password" class="hidden">\n' +
    '    <label id="otp-label" for="otp" class="hidden"></label>\n' +
    '    <input id="otp" class="hidden" inputmode="numeric" autocomplete="one-time-code">\n' +
    '    <p class="note hidden" id="otp-hint"></p>\n' +
    '    <div class="error" id="error" role="alert"></div>\n' +
    '    <button class="primary" id="submit" type="submit"></button>\n' +
    '  </form>\n' +
    '  <div id="locked" class="lock hidden">\n' +
    '    <h2 style="font-size:18px" id="locked-heading"></h2>\n' +
    '    <p class="note" id="locked-note"></p>\n' +
    '  </div>\n' +
    '  <div class="bar">\n' +
    '    <button type="button" id="theme"></button>\n' +
    '    <button type="button" id="lang"></button>\n' +
    '  </div>\n' +
    '</main>\n' +
    '<footer id="footer"></footer>\n' +
    '<script>window.__I18N__ = ' + JSON.stringify(I18N).replaceAll('<', '\\u003c') + ';<\/script>\n' +
    '<script>window.__AUTH__ = ' + JSON.stringify(auth).replaceAll('<', '\\u003c') + ';<\/script>\n' +
    '<script>' + CLIENT_SCRIPT + '<\/script>\n' +
    '</body>\n</html>\n';
}
