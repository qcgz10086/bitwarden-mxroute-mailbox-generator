(function () {
  var I18N = {
    zh: { title: "邮箱管理后台", login: "密码登录", set: "设置后台密码", reset: "重置后台密码", pwd: "密码", npwd: "新密码", loginBtn: "登录", setBtn: "设置并进入", resetBtn: "重置并进入", forgot: "忘记密码？", resetLink: "使用现有登录方式重置密码", back: "返回登录", empty: "请输入密码", loadFail: "加载失败", wrongPwd: "密码错误", turnstileFail: "人机验证未通过", tooShort: "密码太短（至少 8 位）", requestFail: "请求失败" },
    en: { title: "Mailbox Administration", login: "Password login", set: "Set admin password", reset: "Reset admin password", pwd: "Password", npwd: "New password", loginBtn: "Log in", setBtn: "Set and enter", resetBtn: "Reset and enter", forgot: "Forgot password?", resetLink: "Reset using the existing login", back: "Back to login", empty: "Enter a password", loadFail: "Failed to load", wrongPwd: "Wrong password", turnstileFail: "Verification failed", tooShort: "Password too short (min 8)", requestFail: "Request failed" }
  };
  var title = document.getElementById("title"), subtitle = document.getElementById("subtitle");
  var pwdLabelText = document.getElementById("pwd-label-text"), pwd = document.getElementById("pwd");
  var submit = document.getElementById("submit"), error = document.getElementById("error");
  var modeText = document.getElementById("mode-text"), modeToggle = document.getElementById("mode-toggle"), modeRow = document.getElementById("mode-row");
  var langBtn = document.getElementById("lang"), form = document.getElementById("auth-form");
  var lang = "zh", passwordSet = false, resetMode = false, siteKey = null, turnstileToken = null;

  function mode() { return resetMode ? "reset" : (passwordSet ? "login" : "set"); }
  function turnstileAvailable() { return typeof window.turnstile !== "undefined" && siteKey; }
  function setLang(next) { lang = next; langBtn.textContent = next === "zh" ? "EN" : "中文"; applyStrings(); }
  function applyStrings() {
    var s = I18N[lang], m = mode();
    title.textContent = s.title;
    subtitle.textContent = m === "login" ? s.login : (m === "set" ? s.set : s.reset);
    pwdLabelText.textContent = m === "login" ? s.pwd : s.npwd;
    pwd.setAttribute("autocomplete", m === "login" ? "current-password" : "new-password");
    submit.textContent = m === "login" ? s.loginBtn : (m === "set" ? s.setBtn : s.resetBtn);
    if (m === "login") { modeRow.style.display = ""; modeText.textContent = s.forgot; modeToggle.textContent = s.resetLink; }
    else if (m === "reset") { modeRow.style.display = ""; modeText.textContent = lang === "zh" ? "已有密码？" : "Have a password?"; modeToggle.textContent = s.back; }
    else { modeRow.style.display = "none"; }
  }
  langBtn.addEventListener("click", function () { setLang(lang === "zh" ? "en" : "zh"); });

  fetch("/api/auth/status", { headers: { Accept: "application/json" } }).then(function (r) { return r.json(); }).then(function (s) {
    if (s.authenticated) { window.location.replace("/"); return; }
    if (!s.enabled) { window.location.replace("/"); return; }
    siteKey = s.siteKey || null; passwordSet = !!s.passwordSet;
    if (turnstileAvailable()) {
      window.turnstile.render(form, { sitekey: siteKey, size: "invisible", callback: function (token) { turnstileToken = token; doSubmit(); } });
    }
    applyStrings();
  }).catch(function () { error.textContent = I18N[lang].loadFail; });

  modeToggle.addEventListener("click", function () { resetMode = !resetMode; applyStrings(); });

  function doSubmit() {
    var value = pwd.value.trim();
    if (!value) { error.textContent = I18N[lang].empty; return; }
    var m = mode();
    var path = m === "login" ? "/api/auth/login" : "/api/auth/reset";
    var body = m === "login" ? { password: value } : { newPassword: value };
    if (turnstileAvailable()) body.turnstileToken = turnstileToken;
    fetch(path, { method: "POST", headers: { "Content-Type": "application/json", Origin: window.location.origin }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
      .then(function (res) {
        if (res.status === 200) { window.location.replace("/"); return; }
        var map = { INVALID_PASSWORD: I18N[lang].wrongPwd, INVALID_TURNSTILE: I18N[lang].turnstileFail, INVALID_INPUT: I18N[lang].tooShort };
        error.textContent = map[res.body.error] || (res.body.error || I18N[lang].requestFail);
      }).catch(function () { error.textContent = I18N[lang].requestFail; });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (turnstileAvailable()) { window.turnstile.execute(form); return; }
    doSubmit();
  });
})();
