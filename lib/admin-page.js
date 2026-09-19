/**
 * The user-management page — the admin module template. Only the initial
 * administrator (the account created by first-entry bootstrap) reaches
 * "manage" mode; everyone else receives "forbidden" mode, and anonymous
 * visitors are redirected to /login by the gate before this renderer runs.
 * Shares the login page's theme (light/dark/auto) and locale (zh/en) system.
 * @module dsh-plugin-auth-gate/admin-page
 */

const STYLE = `
:root { color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --text:#1a1d21; --muted:#6b7177; --line:#e3e5e8; --accent:#4d6bfe; --accent-text:#fff; --danger:#d92d20; --ok:#067647; }
@media (prefers-color-scheme: dark) { :root:not([data-theme='light']) { --bg:#141517; --card:#1e2023; --text:#ececee; --muted:#9aa0a6; --line:#33363a; --accent:#6b83ff; --accent-text:#0d0e10; } }
:root[data-theme='dark'] { --bg:#141517; --card:#1e2023; --text:#ececee; --muted:#9aa0a6; --line:#33363a; --accent:#6b83ff; --accent-text:#0d0e10; }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; background:var(--bg); color:var(--text); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif; }
.wrap { max-width:760px; margin:0 auto; padding:40px 20px; }
header { display:flex; align-items:center; justify-content:space-between; margin-bottom:22px; }
h1 { font-size:20px; margin:0; }
.bar { display:flex; gap:10px; font-size:12px; }
.bar button { background:none; border:0; color:var(--muted); cursor:pointer; font:inherit; }
.bar button:hover { color:var(--text); }
.panel { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; margin-bottom:18px; }
.panel h2 { font-size:15px; margin:0 0 12px; }
.rowline { display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end; }
.field { display:flex; flex-direction:column; gap:4px; }
.field label { font-size:12px; color:var(--muted); }
.field input { padding:8px 10px; font:inherit; color:var(--text); background:var(--bg); border:1px solid var(--line); border-radius:8px; outline:none; min-width:150px; }
.field input:focus { border-color:var(--accent); }
button.act { padding:8px 14px; font:inherit; font-weight:600; color:var(--accent-text); background:var(--accent); border:0; border-radius:8px; cursor:pointer; }
button.act:disabled { opacity:.6; cursor:default; }
table { width:100%; border-collapse:collapse; font-size:14px; }
th { text-align:left; color:var(--muted); font-size:12px; font-weight:600; padding:6px 8px; border-bottom:1px solid var(--line); }
td { padding:8px; border-bottom:1px solid var(--line); }
tr:last-child td { border-bottom:0; }
.tag { display:inline-block; font-size:11px; padding:1px 8px; border-radius:99px; border:1px solid var(--line); color:var(--muted); margin-right:4px; }
.tag.owner { color:var(--accent); border-color:var(--accent); }
.tag.admin { color:var(--ok); border-color:var(--ok); }
button.mini { background:none; border:1px solid var(--line); color:var(--muted); font:inherit; font-size:12px; border-radius:8px; padding:4px 10px; cursor:pointer; margin-left:6px; }
button.mini:hover { color:var(--text); border-color:var(--muted); }
button.mini.danger:hover { color:var(--danger); border-color:var(--danger); }
.error { color:var(--danger); font-size:13px; min-height:16px; margin-top:10px; }
.hidden { display:none; }
footer { color:var(--muted); font-size:12px; margin-top:26px; }
a { color:inherit; }
`;

const CLIENT_SCRIPT = `
(function () {
  var A = window.__AUTH__;
  var THEMES = ["auto", "light", "dark"];

  function $(id) { return document.getElementById(id); }
  function text(el, value) { el.textContent = value; }
  function i18n() { return window.__I18N__[A.locale]; }
  function setCookie(name, value) { document.cookie = name + "=" + value + "; Path=/; Max-Age=31536000; SameSite=Lax"; }
  function applyTheme(theme) {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    text($("theme"), i18n().theme[THEMES.indexOf(theme)]);
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

  async function refresh() {
    var response = await fetch("/auth/users");
    if (response.status === 401) { location.replace("/login?next=%2Fadmin%2Fusers"); return; }
    var value = await response.json();
    var body = $("rows");
    body.textContent = "";
    (value.users || []).forEach(function (user) {
      var tr = document.createElement("tr");

      var name = document.createElement("td");
      name.appendChild(document.createTextNode(user.name + " "));
      if (user.initial) { var o = document.createElement("span"); o.className = "tag owner"; o.textContent = i18n().owner; name.appendChild(o); }
      else if (user.admin) { var a = document.createElement("span"); a.className = "tag admin"; a.textContent = i18n().admin; name.appendChild(a); }
      tr.appendChild(name);

      var mfa = document.createElement("td");
      mfa.textContent = user.mfa ? i18n().mfaOn + " (" + user.backupCodesRemaining + ")" : i18n().mfaOff;
      tr.appendChild(mfa);

      var created = document.createElement("td");
      created.textContent = (user.createdAt || "").slice(0, 10);
      tr.appendChild(created);

      var ops = document.createElement("td");
      if (user.mfa && user.name !== A.user) {
        var off = document.createElement("button");
        off.className = "mini danger";
        off.textContent = i18n().disableMfa;
        off.addEventListener("click", async function () {
          var result = await post("/auth/mfa/disable", { username: user.name });
          if (result.status !== 200) fail(result.value && result.value.error || "HTTP " + result.status);
          refresh();
        });
        ops.appendChild(off);
      }
      if (!user.initial && user.name !== A.user) {
        var del = document.createElement("button");
        del.className = "mini danger";
        del.textContent = i18n().del;
        del.addEventListener("click", async function () {
          var result = await post("/auth/users/delete", { username: user.name });
          if (result.status !== 200) fail(result.value && result.value.error || "HTTP " + result.status);
          refresh();
        });
        ops.appendChild(del);
      }
      tr.appendChild(ops);
      body.appendChild(tr);
    });
    text($("count"), i18n().count.replace("{n}", String((value.users || []).length)));
  }

  $("create").addEventListener("submit", async function (event) {
    event.preventDefault();
    text($("error"), "");
    var username = $("new-username").value.trim();
    var password = $("new-password").value;
    if (password.length < 8) { fail(i18n().shortPassword); return; }
    var result = await post("/auth/users", { username: username, password: password, admin: $("new-admin").checked });
    if (result.status === 200) {
      $("new-username").value = ""; $("new-password").value = ""; $("new-admin").checked = false;
      refresh();
    } else {
      fail(result.value && result.value.error || "HTTP " + result.status);
    }
  });

  $("logout-all").addEventListener("click", async function () {
    await post("/auth/logout-all", { scope: "all" });
    location.replace("/login?next=%2Fadmin%2Fusers");
  });

  $("theme").addEventListener("click", function () {
    A.theme = THEMES[(THEMES.indexOf(A.theme) + 1) % THEMES.length];
    setCookie("dsh_theme", A.theme);
    applyTheme(A.theme);
  });

  $("lang").addEventListener("click", function () {
    A.locale = A.locale === "zh" ? "en" : "zh";
    setCookie("dsh_locale", A.locale);
    location.reload();
  });

  applyTheme(A.theme);
  if (A.mode === "manage") refresh();
})();
`;

const I18N = {
  en: {
    title: 'User management',
    note: 'Accounts are stored in this workspace only.',
    username: 'Username', password: 'Password', created: 'Created', mfa: 'MFA', actions: '',
    create: 'Create user', makeAdmin: 'grant admin', shortPassword: 'Password must be at least 8 characters.',
    owner: 'initial admin', admin: 'admin', mfaOn: 'on', mfaOff: 'off',
    del: 'Delete', disableMfa: 'Disable MFA', count: '{n} account(s)',
    logoutAll: 'Sign out everyone', back: 'Back to app',
    forbiddenTitle: 'Not available',
    forbiddenNote: 'User management belongs to the initial administrator ({name}) only. You are signed in as another account.',
    theme: ['Theme: auto', 'Theme: light', 'Theme: dark'],
    lang: '中文',
    footer: 'DeepSeek Harness · workspace-scoped accounts'
  },
  zh: {
    title: '用户管理',
    note: '账号仅存储于当前工作区。',
    username: '用户名', password: '密码', created: '创建时间', mfa: '两步验证', actions: '',
    create: '创建用户', makeAdmin: '授予管理员', shortPassword: '密码至少 8 个字符。',
    owner: '初始管理员', admin: '管理员', mfaOn: '已开启', mfaOff: '未开启',
    del: '删除', disableMfa: '关闭 MFA', count: '共 {n} 个账号',
    logoutAll: '全员登出', back: '返回应用',
    forbiddenTitle: '无权访问',
    forbiddenNote: '用户管理仅限初始管理员（{name}）。你当前登录的是其他账号。',
    theme: ['主题：自动', '主题：浅色', '主题：深色'],
    lang: 'English',
    footer: 'DeepSeek Harness · 账号按工作区隔离'
  }
};

/** Render the page; mode is 'manage' (initial admin) or 'forbidden'. */
export function renderAdminPage({ mode = 'forbidden', locale = 'en', theme = 'auto', user = '', initialAdmin = '' } = {}) {
  const safeUser = String(user).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
  const safeInitial = String(initialAdmin).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
  const auth = {
    mode: mode === 'manage' ? 'manage' : 'forbidden',
    locale: locale === 'zh' ? 'zh' : 'en',
    theme: theme === 'light' || theme === 'dark' ? theme : 'auto',
    user: safeUser
  };
  return '<!doctype html>\n<html lang="' + auth.locale + '">\n<head>\n' +
    '<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    '<meta name="color-scheme" content="light dark">\n' +
    '<title>DeepSeek Harness · ' + (auth.locale === 'zh' ? '用户管理' : 'Users') + '</title>\n' +
    '<style>' + STYLE + '</style>\n</head>\n<body>\n' +
    '<div class="wrap">\n' +
    '<header><h1>' + (auth.locale === 'zh' ? '用户管理' : 'User management') + '</h1>' +
    '<div class="bar"><button type="button" id="theme"></button><button type="button" id="lang"></button></div></header>\n' +
    '<p class="error hidden" id="forbidden"></p>\n' +
    '<section id="panel" class="' + (mode === 'manage' ? '' : 'hidden') + '">\n' +
    '<form id="create" class="panel">\n' +
    '<h2>' + (auth.locale === 'zh' ? '创建用户' : 'Create user') + '</h2>\n' +
    '<div class="rowline">\n' +
    '<span class="field"><label for="new-username">' + (auth.locale === 'zh' ? '用户名' : 'Username') + '</label>' +
    '<input id="new-username" autocomplete="off" required></span>\n' +
    '<span class="field"><label for="new-password">' + (auth.locale === 'zh' ? '密码（≥8 位）' : 'Password (≥8 chars)') + '</label>' +
    '<input id="new-password" type="password" autocomplete="new-password" required></span>\n' +
    '<span class="field"><label>&nbsp;</label><label style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="new-admin" style="min-width:0;width:auto"> ' +
    (auth.locale === 'zh' ? '授予管理员（仅普通管理权限）' : 'grant admin (ordinary role)') + '</label></span>\n' +
    '<button class="act" type="submit">' + (auth.locale === 'zh' ? '创建用户' : 'Create user') + '</button>\n' +
    '</div>\n' +
    '<div class="error" id="error" role="alert"></div>\n' +
    '</form>\n' +
    '<div class="panel">\n' +
    '<h2><span id="count"></span></h2>\n' +
    '<table><thead><tr>' +
    '<th>' + (auth.locale === 'zh' ? '用户名' : 'Username') + '</th>' +
    '<th>' + (auth.locale === 'zh' ? '两步验证' : 'MFA') + '</th>' +
    '<th>' + (auth.locale === 'zh' ? '创建时间' : 'Created') + '</th>' +
    '<th></th></tr></thead>\n<tbody id="rows"></tbody></table>\n' +
    '<p style="margin:14px 0 0"><button type="button" class="mini danger" id="logout-all">' +
    (auth.locale === 'zh' ? '全员登出' : 'Sign out everyone') + '</button>' +
    ' <a href="/" style="font-size:12px;color:var(--muted)">' + (auth.locale === 'zh' ? '返回应用' : 'Back to app') + '</a></p>\n' +
    '</div>\n' +
    '</section>\n' +
    '<footer>' + (auth.locale === 'zh' ? 'DeepSeek Harness · 账号按工作区隔离' : 'DeepSeek Harness · workspace-scoped accounts') + '</footer>\n' +
    '</div>\n' +
    '<script>window.__I18N__ = ' + JSON.stringify(I18N).replaceAll('<', '\\u003c') + ';<\/script>\n' +
    '<script>window.__AUTH__ = ' + JSON.stringify(auth).replaceAll('<', '\\u003c') + ';<\/script>\n' +
    '<script>window.__FORBIDDEN_NOTE__ = ' + JSON.stringify(auth.locale === 'zh'
      ? '用户管理仅限初始管理员（' + safeInitial + '）。你当前登录的是其他账号。'
      : 'User management belongs to the initial administrator (' + safeInitial + ') only. You are signed in as another account.').replaceAll('<', '\\u003c') + ';<\/script>\n' +
    '<script>' +
    'if (window.__AUTH__.mode === "forbidden") { var f = document.getElementById("forbidden"); f.textContent = window.__FORBIDDEN_NOTE__; f.classList.remove("hidden"); }' +
    '<\/script>\n' +
    '<script>' + CLIENT_SCRIPT + '<\/script>\n' +
    '</body>\n</html>\n';
}
