(function () {
  var I18N = {
    zh: { title: "重置后台密码", subtitle: "已通过现有登录方式验证身份", pwd: "新密码", btn: "重置并进入", empty: "请输入新密码", tooShort: "密码太短（至少 8 位）", turnstileFail: "人机验证未通过", requestFail: "请求失败", success: "密码已重置" },
    en: { title: "Reset admin password", subtitle: "Identity verified with the existing login", pwd: "New password", btn: "Reset and enter", empty: "Enter a new password", tooShort: "Password too short (min 8)", turnstileFail: "Verification failed", requestFail: "Request failed", success: "Password reset" }
  };
  var lang = "zh", siteKey = null, turnstileToken = null;
  var title = document.getElementById("title"), subtitle = document.getElementById("subtitle");
  var pwdLabelText = document.getElementById("pwd-label-text"), pwd = document.getElementById("pwd");
  var submit = document.getElementById("submit"), error = document.getElementById("error");
  var form = document.getElementById("auth-form");

  function applyStrings() {
    var s = I18N[lang];
    title.textContent = s.title; subtitle.textContent = s.subtitle;
    pwdLabelText.textContent = s.pwd; submit.textContent = s.btn;
  }
  function turnstileAvailable() { return typeof window.turnstile !== "undefined" && siteKey; }

  fetch("/api/auth/status", { headers: { Accept: "application/json" } }).then(function (r) { return r.json(); }).then(function (s) {
    siteKey = s.siteKey || null;
    if (turnstileAvailable()) {
      window.turnstile.render(form, { sitekey: siteKey, size: "invisible", callback: function (token) { turnstileToken = token; doReset(); } });
    }
  }).catch(function () { error.textContent = I18N[lang].requestFail; });

  function doReset() {
    var value = pwd.value.trim();
    if (!value) { error.textContent = I18N[lang].empty; return; }
    var body = { newPassword: value };
    if (turnstileAvailable()) body.turnstileToken = turnstileToken;
    fetch("/api/auth/reset", { method: "POST", headers: { "Content-Type": "application/json", Origin: window.location.origin }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
      .then(function (res) {
        if (res.status === 200) { window.location.replace("/"); return; }
        var map = { INVALID_TURNSTILE: I18N[lang].turnstileFail, INVALID_INPUT: I18N[lang].tooShort, UNAUTHORIZED: lang === "zh" ? "身份验证未通过" : "Identity verification failed" };
        error.textContent = map[res.body.error] || (res.body.error || I18N[lang].requestFail);
      }).catch(function () { error.textContent = I18N[lang].requestFail; });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (turnstileAvailable()) { window.turnstile.execute(form); return; }
    doReset();
  });
})();
