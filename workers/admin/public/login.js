(function () {
  var I18N = {
    zh: { title: "邮箱管理后台", login: "密码登录", set: "首次使用：请设置后台密码", pwd: "密码", loginBtn: "登录", goSet: "设置后台密码", forgot: "忘记密码？", resetLink: "使用现有登录方式重置", empty: "请输入密码", loadFail: "加载失败", wrongPwd: "密码错误", turnstileFail: "人机验证未通过", requestFail: "请求失败" },
    en: { title: "Mailbox Administration", login: "Password login", set: "First run: set the admin password", pwd: "Password", loginBtn: "Log in", goSet: "Set password", forgot: "Forgot password?", resetLink: "Reset using the existing login", empty: "Enter a password", loadFail: "Failed to load", wrongPwd: "Wrong password", turnstileFail: "Verification failed", requestFail: "Request failed" }
  };
  var title = document.getElementById("title"), subtitle = document.getElementById("subtitle");
  var pwdLabel = document.getElementById("pwd-label"), pwd = document.getElementById("pwd");
  var submit = document.getElementById("submit"), error = document.getElementById("error");
  var modeRow = document.getElementById("mode-row"), modeText = document.getElementById("mode-text"), modeLink = document.getElementById("mode-link");
  var langBtn = document.getElementById("lang"), form = document.getElementById("auth-form");
  var lang = "zh", passwordSet = false, siteKey = null, turnstileToken = null;

  function turnstileAvailable() { return typeof window.turnstile !== "undefined" && siteKey; }
  function setLang(next) { lang = next; langBtn.textContent = next === "zh" ? "EN" : "中文"; applyStrings(); }
  function applyStrings() {
    var s = I18N[lang];
    title.textContent = s.title;
    subtitle.textContent = passwordSet ? s.login : s.set;
    if (passwordSet) {
      pwdLabel.style.display = ""; submit.textContent = s.loginBtn;
      modeRow.style.display = ""; modeText.textContent = s.forgot; modeLink.textContent = s.resetLink;
    } else {
      pwdLabel.style.display = "none"; submit.textContent = s.goSet;
      modeRow.style.display = "none";
    }
  }
  langBtn.addEventListener("click", function () { setLang(lang === "zh" ? "en" : "zh"); });

  fetch("/api/auth/status", { headers: { Accept: "application/json" } }).then(function (r) { return r.json(); }).then(function (s) {
    if (s.authenticated) { window.location.replace("/"); return; }
    if (!s.enabled) { window.location.replace("/"); return; }
    siteKey = s.siteKey || null; passwordSet = !!s.passwordSet;
    if (passwordSet && turnstileAvailable()) {
      window.turnstile.render(form, { sitekey: siteKey, size: "invisible", callback: function (token) { turnstileToken = token; doLogin(); } });
    }
    applyStrings();
  }).catch(function () { error.textContent = I18N[lang].loadFail; });

  modeLink.addEventListener("click", function (e) { e.preventDefault(); window.location.assign("/reset"); });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (!passwordSet) { window.location.assign("/reset"); return; }
    if (turnstileAvailable()) { window.turnstile.execute(form); return; }
    doLogin();
  });

  function doLogin() {
    var value = pwd.value.trim();
    if (!value) { error.textContent = I18N[lang].empty; return; }
    var body = { password: value };
    if (turnstileAvailable()) body.turnstileToken = turnstileToken;
    fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json", Origin: window.location.origin }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
      .then(function (res) {
        if (res.status === 200) { window.location.replace("/"); return; }
        var map = { INVALID_PASSWORD: I18N[lang].wrongPwd, INVALID_TURNSTILE: I18N[lang].turnstileFail };
        error.textContent = map[res.body.error] || (res.body.error || I18N[lang].requestFail);
      }).catch(function () { error.textContent = I18N[lang].requestFail; });
  }
})();
