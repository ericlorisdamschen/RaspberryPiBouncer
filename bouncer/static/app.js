/* Bouncer dashboard. Plain JavaScript, no external libraries, no tracking. */
(function () {
  "use strict";

  var LANGS = ["en", "de", "fr"];
  var S = {
    lang: "en", t: {}, summary: null, range: "hours", pin: "", location: { lat: 49.61, lon: 6.13 },
    thisDevice: null, timer: null, afterCode: "dash", renameId: null, rules: null
  };

  // ---------- small helpers ----------
  function $(id) { return document.getElementById(id); }
  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "text") el.textContent = v;
      else if (k === "class") el.className = v;
      else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    });
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === null || c === undefined || c === false) continue;
      el.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
    }
    return el;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
  function svg(path, size) {
    var ns = "http://www.w3.org/2000/svg";
    var s = document.createElementNS(ns, "svg");
    s.setAttribute("width", size || 20); s.setAttribute("height", size || 20);
    s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("fill", "none");
    s.setAttribute("stroke", "currentColor"); s.setAttribute("stroke-width", "2");
    s.setAttribute("stroke-linecap", "round"); s.setAttribute("stroke-linejoin", "round");
    s.setAttribute("aria-hidden", "true");
    path.split("|").forEach(function (d) {
      var p = document.createElementNS(ns, "path"); p.setAttribute("d", d); s.appendChild(p);
    });
    return s;
  }
  var ICONS = {
    shield: "M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6z|M9 12l2 2 4-4",
    pause: "M8 5v14|M16 5v14",
    ads: "M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z|M5.6 5.6l12.8 12.8",
    scam: "M12 3l9 16H3z|M12 10v4|M12 17h.01",
    family: "M8 4a3 3 0 1 0 0 6a3 3 0 1 0 0-6z|M3 20c0-3 2.2-5.5 5-5.5s5 2.5 5 5.5|M17 7a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5z|M14 20c0-2.4 1.4-4.5 3-4.5s3.5 2.1 3.5 4.5",
    screen: "M3 4h18v12H3z|M8 20h8|M12 16v4",
    router: "M3 14h18v6H3z|M7 17h.01|M11 17h.01|M8 10a6 6 0 0 1 8 0|M5 7a10 10 0 0 1 14 0",
    del: "M21 5H9l-6 7 6 7h12z|M17 9l-5 6|M12 9l5 6"
  };

  function t(key, vars) {
    var s = S.t[key];
    if (s === undefined) s = key;
    if (vars) Object.keys(vars).forEach(function (k) { s = s.split("{" + k + "}").join(vars[k]); });
    return s;
  }
  function fmtNum(n) { return new Intl.NumberFormat(S.lang).format(n || 0); }
  function fmtTime(ts) {
    return new Intl.DateTimeFormat(S.lang, { hour: "2-digit", minute: "2-digit" }).format(new Date(ts * 1000));
  }
  function fmtDay(ts) {
    return new Intl.DateTimeFormat(S.lang, { weekday: "short" }).format(new Date(ts * 1000));
  }
  function fmtWhen(ts) {
    if (!ts) return t("sys.lists_never");
    var days = Math.round((ts * 1000 - Date.now()) / 86400000);
    var hours = Math.round((ts * 1000 - Date.now()) / 3600000);
    var rtf = new Intl.RelativeTimeFormat(S.lang, { numeric: "auto" });
    return Math.abs(hours) < 24 ? rtf.format(hours, "hour") : rtf.format(days, "day");
  }
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); }
    catch (e) { return null; }
  }
  function toast(msg) {
    var el = $("toast"); el.textContent = msg; el.classList.remove("hidden");
    clearTimeout(toast.t); toast.t = setTimeout(function () { el.classList.add("hidden"); }, 3500);
  }

  function api(path, body, method) {
    var opts = { method: method || (body !== undefined ? "POST" : "GET"), credentials: "same-origin", headers: {} };
    if (opts.method === "POST") {
      opts.headers["X-Bouncer"] = "1";
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body || {});
    }
    return fetch(path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (r.status === 401 && data.error === "login") { showLogin(); throw new Error("login"); }
        data._status = r.status; return data;
      });
    });
  }

  // ---------- language ----------
  function detectLang() {
    var saved = store("bouncer.lang");
    if (LANGS.indexOf(saved) >= 0) return saved;
    var nav = (navigator.languages || [navigator.language || "en"]);
    for (var i = 0; i < nav.length; i++) {
      var code = String(nav[i]).slice(0, 2).toLowerCase();
      if (LANGS.indexOf(code) >= 0) return code;
    }
    return "en";
  }
  function setLang(lang) {
    return fetch("/static/i18n/" + lang + ".json").then(function (r) { return r.json(); }).then(function (dict) {
      S.lang = lang; S.t = dict; store("bouncer.lang", lang);
      document.documentElement.lang = lang;
      applyI18n();
      if (S.summary) render();
    });
  }
  function applyI18n() {
    document.querySelectorAll("[data-i18n]").forEach(function (el) { el.textContent = t(el.getAttribute("data-i18n")); });
    document.querySelectorAll("[data-i18n-aria]").forEach(function (el) {
      el.setAttribute("aria-label", t(el.getAttribute("data-i18n-aria")));
    });
    document.querySelectorAll(".lang-switch").forEach(function (box) {
      clear(box);
      LANGS.forEach(function (l) {
        box.appendChild(h("button", { type: "button", "aria-pressed": String(l === S.lang), lang: l,
          onclick: function () { setLang(l); } }, l.toUpperCase()));
      });
    });
    $("guide-link").setAttribute("href", "/static/guides/bouncer-router-guide-" + S.lang + ".pdf");
    renderKeypad();
  }

  // ---------- dark mode that follows sunrise and sunset ----------
  function sunTimes(date, lat, lon) {
    var noon = new Date(date.getTime()); noon.setHours(12, 0, 0, 0);
    var rad = Math.PI / 180, jd = noon.getTime() / 86400000 + 2440587.5;
    var n = Math.round(jd - 2451545.0 + 0.0008), js = n - lon / 360;
    var M = (357.5291 + 0.98560028 * js) % 360;
    var C = 1.9148 * Math.sin(M * rad) + 0.02 * Math.sin(2 * M * rad) + 0.0003 * Math.sin(3 * M * rad);
    var L = (M + C + 180 + 102.9372) % 360;
    var jt = 2451545 + js + 0.0053 * Math.sin(M * rad) - 0.0069 * Math.sin(2 * L * rad);
    var dec = Math.asin(Math.sin(L * rad) * Math.sin(23.4397 * rad));
    var cosw = (Math.sin(-0.833 * rad) - Math.sin(lat * rad) * Math.sin(dec)) / (Math.cos(lat * rad) * Math.cos(dec));
    var w = Math.acos(Math.max(-1, Math.min(1, cosw))) / rad;
    function toMs(j) { return (j - 2440587.5) * 86400000; }
    return { rise: toMs(jt - w / 360), set: toMs(jt + w / 360) };
  }
  function autoTheme() {
    var now = Date.now(), st = sunTimes(new Date(), S.location.lat, S.location.lon);
    var dark = now < st.rise || now > st.set;
    var next = now < st.rise ? st.rise : (now < st.set ? st.set : sunTimes(new Date(now + 86400000), S.location.lat, S.location.lon).rise);
    return { dark: dark, next: next };
  }
  function applyTheme() {
    var auto = autoTheme(), dark = auto.dark, ov = null;
    try { ov = JSON.parse(store("bouncer.theme") || "null"); } catch (e) { ov = null; }
    if (ov && ov.until > Date.now()) dark = ov.mode === "dark";
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
  }
  function toggleTheme() {
    var dark = document.documentElement.getAttribute("data-theme") !== "dark";
    store("bouncer.theme", JSON.stringify({ mode: dark ? "dark" : "light", until: autoTheme().next }));
    applyTheme();
  }

  // ---------- screens ----------
  function show(id) {
    ["screen-login", "screen-setpin", "screen-recover", "screen-code", "screen-dash"].forEach(function (s) {
      $(s).classList.toggle("hidden", s !== id);
    });
    if (id !== "screen-dash") stopPolling();
    window.scrollTo(0, 0);
  }
  function refreshState() {
    return api("/api/state").then(function (st) {
      if (st.location) S.location = st.location;
      applyTheme();
      if (st.step === "login") showLogin(st);
      else if (st.step === "need_pin" || st.step === "change") showSetPin();
      else showDash();
    }).catch(function () { toast(t("offline")); });
  }

  // ---------- PIN entry ----------
  function renderKeypad() {
    var pad = $("keypad"); if (!pad) return;
    clear(pad);
    ["1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "del"].forEach(function (k) {
      if (k === "") { pad.appendChild(h("span")); return; }
      if (k === "del") {
        var b = h("button", { type: "button", class: "plain", "aria-label": t("login.delete"), onclick: function () { pinKey("del"); } });
        b.appendChild(svg(ICONS.del, 28)); pad.appendChild(b); return;
      }
      pad.appendChild(h("button", { type: "button", onclick: function () { pinKey(k); } }, k));
    });
  }
  function renderDots() {
    var dots = $("login-dots").children;
    for (var i = 0; i < 4; i++) dots[i].classList.toggle("on", i < S.pin.length);
    $("login-dots").setAttribute("aria-label", t("login.dots", { n: S.pin.length }));
  }
  function showLogin(st) {
    S.pin = ""; renderDots(); show("screen-login");
    var msg = $("login-msg"); msg.textContent = ""; msg.className = "msg";
    if (st && st.locked_until) { msg.textContent = t("login.locked", { time: fmtTime(st.locked_until) }); msg.className = "msg bad"; }
  }
  function pinKey(k) {
    if (k === "del") { S.pin = S.pin.slice(0, -1); renderDots(); return; }
    if (S.pin.length >= 4) return;
    S.pin += k; renderDots();
    if (S.pin.length === 4) {
      var pin = S.pin;
      api("/api/login", { pin: pin }).then(function (r) {
        var msg = $("login-msg");
        if (r.ok) { msg.textContent = ""; r.change ? showSetPin() : showDash(); return; }
        S.pin = ""; renderDots();
        var dots = $("login-dots"); dots.classList.remove("shake"); void dots.offsetWidth; dots.classList.add("shake");
        msg.className = "msg bad";
        msg.textContent = r.reason === "locked" ? t("login.locked", { time: fmtTime(r.locked_until) }) : t("login.wrong", { n: r.tries_left });
      });
    }
  }
  document.addEventListener("keydown", function (e) {
    if ($("screen-login").classList.contains("hidden")) return;
    if (/^[0-9]$/.test(e.key)) pinKey(e.key);
    else if (e.key === "Backspace") pinKey("del");
  });

  // ---------- choose PIN / recovery ----------
  function showSetPin() {
    $("np1").value = ""; $("np2").value = ""; $("setpin-msg").textContent = "";
    show("screen-setpin"); $("np1").focus();
  }
  function pinError(reason) {
    return t({ weak: "setpin.weak", same: "setpin.same", invalid: "setpin.invalid", mismatch: "setpin.mismatch",
      wrong: "recover.wrong" }[reason] || "error");
  }
  $("form-setpin").addEventListener("submit", function (e) {
    e.preventDefault();
    var a = $("np1").value, b = $("np2").value, msg = $("setpin-msg");
    msg.className = "msg bad";
    if (!/^\d{4}$/.test(a)) { msg.textContent = pinError("invalid"); return; }
    if (a !== b) { msg.textContent = pinError("mismatch"); return; }
    api("/api/setup-pin", { pin: a }).then(function (r) {
      if (!r.ok) { msg.textContent = pinError(r.reason); return; }
      showCode(r.recovery, "dash");
    });
  });
  $("btn-forgot").addEventListener("click", function () {
    ["rc", "rp1", "rp2"].forEach(function (id) { $(id).value = ""; });
    $("recover-msg").textContent = ""; show("screen-recover");
  });
  $("btn-back-login").addEventListener("click", function () { showLogin(); });
  $("form-recover").addEventListener("submit", function (e) {
    e.preventDefault();
    var a = $("rp1").value, b = $("rp2").value, msg = $("recover-msg");
    msg.className = "msg bad";
    if (!/^\d{4}$/.test(a)) { msg.textContent = pinError("invalid"); return; }
    if (a !== b) { msg.textContent = pinError("mismatch"); return; }
    api("/api/recover", { code: $("rc").value, pin: a }).then(function (r) {
      if (!r.ok) {
        msg.textContent = r.reason === "locked" ? t("login.locked", { time: fmtTime(r.locked_until) }) : pinError(r.reason);
        return;
      }
      showCode(r.recovery, "dash");
    });
  });
  function showCode(code, after) {
    S.afterCode = after;
    $("recovery-code").textContent = code;
    $("mail-code").setAttribute("href", "mailto:?subject=" + encodeURIComponent(t("code.mail_subject")) +
      "&body=" + encodeURIComponent(t("code.mail_body", { code: code })));
    show("screen-code");
  }
  $("btn-code-done").addEventListener("click", function () { $("recovery-code").textContent = ""; showDash(); });

  // ---------- dashboard ----------
  function showDash() {
    show("screen-dash");
    load();
    checkThisDevice();
    startPolling();
  }
  function startPolling() {
    stopPolling();
    S.timer = setInterval(function () { if (!document.hidden) load(); }, 10000);
    S.devTimer = setInterval(checkThisDevice, 60000);
  }
  function stopPolling() { clearInterval(S.timer); clearInterval(S.devTimer); }
  function load() {
    return api("/api/summary").then(function (d) {
      if (d._status === 403 && d.error === "change_pin") { showSetPin(); return; }
      if (d._status !== 200) return;
      S.summary = d; render();
    }).catch(function (e) { if (e.message !== "login") toast(t("offline")); });
  }
  function checkThisDevice() {
    S.thisDevice = "checking";
    var img = new Image(), done = false;
    var finish = function (ok) { if (done) return; done = true; S.thisDevice = ok; if (S.summary) renderStatus(); };
    img.onload = function () { finish(true); };
    img.onerror = function () { finish(false); };
    setTimeout(function () { finish(false); }, 5000);
    img.src = "http://protected.bouncer.home.arpa/check.gif?t=" + Date.now();
  }

  function render() {
    renderStatus(); renderNotice(); renderNumbers(); renderShields(); renderChart();
    renderSpeed(); renderDevices(); renderRecent(); renderSystem(); renderAdvanced();
  }

  function pill(kind, text) { return h("span", { class: "pill " + (kind || "") }, h("span", { class: "dot" }), text); }

  function renderStatus() {
    var d = S.summary, el = clear($("status")), paused = d.paused_until > 0;
    var inactive = !paused && d.network && d.network.level === "red";
    var addr = d.addresses || {};
    $("brand-sub").textContent = addr.ipv4 ? "bouncer.local · " + addr.ipv4 : "bouncer.local";
    el.className = "card status " + (paused ? "paused" : inactive ? "inactive" : "on");
    var badge = h("div", { class: "badge" }); badge.appendChild(svg(paused ? ICONS.pause : inactive ? ICONS.scam : ICONS.shield, 28));
    var text = h("div", null,
      h("h1", { text: paused ? t("status.paused", { time: fmtTime(d.paused_until) }) : inactive ? t("status.not_active") : t("status.on") }),
      h("p", { class: "muted", text: paused ? t("status.paused_text") : inactive ? t("status.not_active_text") : t("status.on_text") }));
    if (!paused) {
      var pills = h("div", { class: "pills" }), n = d.network || {};
      if (n.ipv4 === "address_mode") pills.appendChild(pill("", t("pill.address_mode")));
      else if (n.proxied) pills.appendChild(pill("", t("pill.router_forwards")));
      else if (n.ipv4 === "ok") pills.appendChild(pill("", t("pill.router_ok")));
      else if (n.ipv4 === "partial") pills.appendChild(pill("warn", t("pill.router_secondary")));
      else if (n.ipv4 === "other") pills.appendChild(pill(n.level === "red" ? "bad" : "warn", t("pill.router_not_set")));
      else pills.appendChild(pill("grey", t("pill.router_unknown")));
      if (n.issues && n.issues.indexOf("ipv6_bypass") >= 0) pills.appendChild(pill("warn", t("pill.ipv6")));
      var prot = (d.devices || []).filter(function (x) { return x.protected && !x.router; }).length;
      if (prot) pills.appendChild(pill("", prot === 1 ? t("pill.device_one") : t("pill.devices", { n: prot })));
      if (n.unprotected) pills.appendChild(pill("warn", t("pill.unprotected", { n: n.unprotected })));
      if (S.thisDevice === "checking" || S.thisDevice === null) pills.appendChild(pill("grey", t("pill.this_checking")));
      else pills.appendChild(pill(S.thisDevice ? "" : "warn", S.thisDevice ? t("pill.this_ok") : t("pill.this_bad")));
      text.appendChild(pills);
    }
    el.appendChild(h("div", { class: "main" }, badge, text));
    var actions = h("div", { class: "actions" });
    if (paused) {
      actions.appendChild(h("button", { type: "button", class: "btn primary big", onclick: function () { pause("resume"); } }, t("status.resume")));
    } else {
      actions.appendChild(h("span", { class: "muted", text: t("status.pause") }));
      actions.appendChild(h("div", { class: "pause-btns" },
        h("button", { type: "button", class: "btn", onclick: function () { pause(5); } }, t("status.min5")),
        h("button", { type: "button", class: "btn", onclick: function () { pause(30); } }, t("status.min30")),
        h("button", { type: "button", class: "btn", onclick: function () { pause("tomorrow"); } }, t("status.tomorrow"))));
    }
    el.appendChild(actions);
  }
  function pause(what) {
    var body = what === "resume" || what === "tomorrow" ? { mode: what } : { mode: "minutes", minutes: what };
    api("/api/pause", body).then(load);
  }

  function addrLine(label, value) {
    return h("li", null, label + " ", h("span", { class: "addr", text: value }));
  }
  function renderNotice() {
    var d = S.summary, n = d.network || {}, issues = n.issues || [], el = clear($("network-notice"));
    var addr = d.addresses || {}, kind = null;
    el.className = "notice";
    if (issues.indexOf("router_not_set") >= 0) {
      kind = "bad";
      el.appendChild(h("h2", { text: t("notice.not_set_title") }));
      el.appendChild(h("p", { text: t("notice.not_set_text") }));
      var ol = h("ol", null, h("li", { text: t("notice.step1") }), addrLine(t("notice.step2"), addr.ipv4 || "?"),
        h("li", { text: t("notice.step3") }));
      el.appendChild(ol);
    } else if (issues.indexOf("not_seen_yet") >= 0) {
      el.appendChild(h("h2", { text: t("notice.waiting_title") }));
      el.appendChild(h("p", { text: t("notice.waiting_text") }));
      kind = "warn";
    } else if (issues.indexOf("router_secondary") >= 0) {
      el.appendChild(h("h2", { text: t("notice.secondary_title") }));
      el.appendChild(h("p", { text: t("notice.secondary_text") }));
      kind = "warn";
    } else if (issues.indexOf("ipv6_bypass") >= 0) {
      el.appendChild(h("h2", { text: t("notice.ipv6_title") }));
      el.appendChild(h("p", null, t("notice.ipv6_text") + " ", h("span", { class: "addr", text: addr.ipv6 || "?" })));
      kind = "warn";
    } else if (issues.indexOf("router_forwards") >= 0) {
      el.appendChild(h("h2", { text: t("notice.forward_title") }));
      el.appendChild(h("p", { text: t("notice.forward_text") }));
      kind = "warn";
    } else if (issues.indexOf("devices_unprotected") >= 0) {
      el.appendChild(h("h2", { text: t("notice.unprotected_title") }));
      el.appendChild(h("p", { text: t("notice.unprotected_text") }));
      kind = "warn";
    }
    if (kind && kind !== "warn" || issues.indexOf("ipv6_bypass") >= 0 || issues.indexOf("router_secondary") >= 0) {
      el.appendChild(h("a", { href: "/static/guides/bouncer-router-guide-" + S.lang + ".pdf", download: true, text: t("notice.guide") }));
    }
    if (kind === "bad") el.classList.add("bad");
    el.classList.toggle("hidden", !kind || d.paused_until > 0);
  }

  function renderNumbers() {
    var td = S.summary.today;
    $("n-blocked").textContent = fmtNum(td.blocked);
    $("n-share").textContent = (td.share || 0) + "%";
    $("n-share-hint").textContent = t("num.share_hint", { n: td.share || 0 });
    $("n-total").textContent = fmtNum(td.total);
    $("n-saved").textContent = "≈ " + new Intl.NumberFormat(S.lang, { maximumFractionDigits: td.data_saved_mb < 10 ? 1 : 0 }).format(td.data_saved_mb || 0) + " MB";
  }

  function renderShields() {
    var p = S.summary.protection, el = clear($("shields"));
    ["ads", "scam", "family"].forEach(function (key) {
      var on = !!p[key], ico = h("div", { class: "ico" }); ico.appendChild(svg(ICONS[key], 22));
      var stat = on ? (key === "family" && !p.counts.family ? t("prot.on") : t("prot.today", { n: fmtNum(p.counts[key]) })) : t("prot.off");
      el.appendChild(h("div", { class: "shield" },
        h("div", { class: "info" }, ico, h("div", null, h("div", { class: "title", text: t("prot." + key) }),
          h("div", { class: "muted", text: t("prot." + key + "_text") }), h("div", { class: "stat-line num", text: stat }))),
        h("button", { type: "button", class: "switch", role: "switch", "aria-checked": String(on), "aria-label": t("prot." + key),
          onclick: function () { var b = {}; b[key] = !on; api("/api/protection", b).then(load); } }, h("span"))));
    });
  }

  function renderChart() {
    var c = S.summary.chart, data = S.range === "hours" ? c.hours : c.days;
    $("chart-title").textContent = S.range === "hours" ? t("chart.title24") : t("chart.title7");
    document.querySelectorAll("#chart-range button").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-range") === S.range));
    });
    var max = 1, sb = 0, sa = 0;
    data.forEach(function (x) { max = Math.max(max, x.blocked + x.allowed); sb += x.blocked; sa += x.allowed; });
    var bars = clear($("bars"));
    bars.setAttribute("aria-label", t("chart.aria", { b: fmtNum(sb), a: fmtNum(sa) }));
    data.forEach(function (x) {
      var a = h("div", { class: "a" }), b = h("div", { class: "b" });
      a.style.height = (100 * x.allowed / max) + "%"; b.style.height = (100 * x.blocked / max) + "%";
      var title = (S.range === "hours" ? fmtTime(x.start) : fmtDay(x.start)) + ": " + fmtNum(x.blocked) + " / " + fmtNum(x.allowed);
      bars.appendChild(h("div", { class: "bar", title: title }, a, b));
    });
    var axis = clear($("axis"));
    if (S.range === "hours") {
      [0, 6, 12, 18].forEach(function (i) { axis.appendChild(h("span", { text: fmtTime(data[i].start) })); });
      axis.appendChild(h("span", { text: t("chart.now") }));
    } else {
      data.forEach(function (x, i) { axis.appendChild(h("span", { text: i === data.length - 1 ? t("chart.today") : fmtDay(x.start) })); });
    }
  }

  function meter(label, secs, pct, color) {
    var bar = h("div"); bar.style.width = pct + "%"; bar.style.background = color;
    return h("div", { class: "meter" }, h("div", { class: "top" }, h("span", { text: label }), h("b", { text: secs.toFixed(1) + " s" })),
      h("div", { class: "track" }, bar));
  }
  function renderSpeed() {
    var sp = S.summary.speed, body = clear($("speed-body")), running = S.summary.speed_running;
    $("btn-speed").disabled = running;
    $("btn-speed").textContent = running ? t("speed.running") : t("speed.run");
    if (sp && sp.ok) {
      body.appendChild(h("p", { class: "speed-big" }, t("speed.result_pre") + " ", h("strong", { text: t("speed.result_pct", { pct: sp.faster_pct }) }), " " + t("speed.result_post")));
      var cs = getComputedStyle(document.documentElement);
      body.appendChild(meter(t("speed.without"), sp.without_s, 100, cs.getPropertyValue("--allowed")));
      body.appendChild(meter(t("speed.with"), sp.with_s, sp.without_s ? Math.max(4, 100 * sp.with_s / sp.without_s) : 100, cs.getPropertyValue("--ok-dot")));
      body.appendChild(h("p", { class: "muted", text: t("speed.saved", { mb: sp.saved_mb_per_page }) }));
      $("speed-note").textContent = t("speed.last", { time: new Intl.DateTimeFormat(S.lang, { dateStyle: "medium", timeStyle: "short" }).format(new Date(sp.finished * 1000)) });
    } else {
      body.appendChild(h("p", { class: "muted", text: t("speed.never") }));
      $("speed-note").textContent = "";
    }
  }
  $("btn-speed").addEventListener("click", function () {
    api("/api/speedcheck", {}).then(function () {
      S.summary.speed_running = true; renderSpeed();
      var poll = setInterval(function () { load().then(function () { if (!S.summary.speed_running) clearInterval(poll); }); }, 5000);
    });
  });

  function devName(dev) {
    if (dev.router) return t("dev.router");
    return dev.name || t("dev.unnamed", { ip: dev.ip || dev.id });
  }
  function renderDevices() {
    var list = S.summary.devices || [], el = clear($("devices")), sel = $("fix-device"), prev = sel.value;
    if (!list.length) el.appendChild(h("p", { class: "empty", text: t("dev.none") }));
    list.forEach(function (dev) {
      var ico = h("div", { class: "dev-ico" }); ico.appendChild(svg(dev.router ? ICONS.router : ICONS.screen, 20));
      var nameLine = h("div", { class: "name-line" }, h("span", { class: "name", text: devName(dev) }));
      if (dev.protected === true) nameLine.appendChild(h("span", { class: "tag ok", text: t("dev.protected") }));
      else if (dev.protected === false) nameLine.appendChild(h("span", { class: "tag warn", text: t("dev.not_protected") }));
      if (dev.this) nameLine.appendChild(h("span", { class: "tag grey", text: t("dev.this") }));
      el.appendChild(h("div", { class: "list-row" },
        h("div", { class: "l" }, ico, h("div", { class: "l2" }, nameLine,
          h("div", { class: "muted", text: t("dev.requests", { n: fmtNum(dev.requests), b: fmtNum(dev.blocked) }) }))),
        dev.router ? null : h("button", { type: "button", class: "btn link", "aria-label": t("dev.rename") + ": " + devName(dev),
          onclick: function () { openRename(dev); } }, t("dev.rename_short"))));
    });
    clear(sel);
    list.filter(function (d) { return d.protected; }).forEach(function (dev) {
      sel.appendChild(h("option", { value: dev.id }, devName(dev) + (dev.this ? " (" + t("dev.this") + ")" : "")));
    });
    if (prev && Array.prototype.some.call(sel.options, function (o) { return o.value === prev; })) sel.value = prev;
    $("btn-fix").disabled = !sel.options.length;
  }
  function openRename(dev) {
    S.renameId = dev.id; $("rename-input").value = dev.name || "";
    $("dlg-rename").showModal();
  }
  $("dlg-rename").addEventListener("close", function () {
    if ($("dlg-rename").returnValue === "ok") api("/api/rename", { id: S.renameId, name: $("rename-input").value }).then(load);
  });
  $("btn-fix").addEventListener("click", function () {
    var res = $("fix-result");
    api("/api/fix", { id: $("fix-device").value }).then(function (r) {
      res.className = "result " + (r.count ? "ok" : "bad");
      res.textContent = r.count ? t("fix.done", { n: r.count }) : t("fix.nothing");
      load();
    });
  });

  function renderRecent() {
    var list = S.summary.recent || [], el = clear($("recent"));
    if (!list.length) el.appendChild(h("p", { class: "empty", text: t("recent.none") }));
    list.slice(0, 12).forEach(function (r) {
      var cls = r.cat === "scam" ? "scam" : "ad";
      el.appendChild(h("div", { class: "list-row" },
        h("div", { class: "l2" }, h("div", { class: "name", text: r.device || t("dev.unnamed", { ip: r.ip || "?" }) }),
          h("div", { class: "muted num", text: fmtTime(r.ts) })),
        h("span", { class: "tag " + cls, text: t("recent." + (r.cat || "ads")) })));
    });
  }

  function renderSystem() {
    var sys = S.summary.system, v = S.summary.version;
    var sw = $("sys-software"), failed = sys.update.last_result === "rolled_back" || sys.update.last_result === "invalid_release";
    sw.className = failed ? "warnline" : "okline";
    sw.textContent = failed ? t("sys.update_failed") + " (" + v + ")" : t("sys.up_to_date", { v: v });
    var total = (sys.lists.counts.ads || 0) + (sys.lists.counts.scam || 0) + (sys.lists.counts.fake || 0);
    $("sys-lists").textContent = t("sys.lists_value", { n: fmtNum(total) });
    $("sys-lists-hint").textContent = sys.lists.updating ? t("sys.lists_updating") : t("sys.lists_hint", { when: fmtWhen(sys.lists.updated) });
  }
  $("restore-file").addEventListener("change", function (e) {
    var f = e.target.files[0]; if (!f) return;
    f.text().then(function (txt) {
      var data; try { data = JSON.parse(txt); } catch (err) { toast(t("sys.restore_failed")); return; }
      api("/api/restore", data).then(function (r) { toast(r.ok ? t("sys.restored") : t("sys.restore_failed")); load(); });
    });
    e.target.value = "";
  });
  $("restore-label").addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("restore-file").click(); } });
  $("btn-faq").addEventListener("click", function () { $("dlg-faq").showModal(); });

  // ---------- advanced ----------
  function renderAdvanced() {
    var d = S.summary, a = d.addresses || {}, el = clear($("adv-addresses"));
    el.appendChild(h("div", { text: t("adv.ipv4") + ": " + (a.ipv4 || "–") }));
    el.appendChild(h("div", { text: t("adv.ipv6") + ": " + (a.ipv6 || "–") }));
    var am = d.system.address_mode;
    $("am-state").textContent = am ? t("adv.am_on") : t("adv.am_off");
    $("btn-am").textContent = am ? t("adv.am_disable") : t("adv.am_enable");
    $("btn-reset-fixes").textContent = t("adv.reset_fixes", { n: d.system.fixes });
    $("btn-reset-fixes").disabled = !d.system.fixes;
    var upKey = { encrypted: "adv.upstream_encrypted", plain: "adv.upstream_plain", none: "adv.upstream_none" }[d.system.upstream];
    $("adv-upstream").textContent = upKey ? t(upKey) : "";
    if ($("advanced").open && S.rules === null) loadRules();
  }
  $("advanced").addEventListener("toggle", function () { if ($("advanced").open) loadRules(); });
  function loadRules() {
    api("/api/rules").then(function (r) { S.rules = r; renderRules(); });
  }
  function renderRules() {
    var el = clear($("rules"));
    ["allow", "block"].forEach(function (kind) {
      (S.rules[kind] || []).forEach(function (dom) {
        el.appendChild(h("span", { class: "tag " + (kind === "allow" ? "ok" : "ad") }, dom + " · " + t(kind === "allow" ? "adv.allowed_tag" : "adv.blocked_tag"),
          h("button", { type: "button", "aria-label": t("adv.remove", { d: dom }), onclick: function () {
            api("/api/rules", { list: kind, domain: dom, remove: true }).then(loadRules);
          } }, "×")));
      });
    });
  }
  $("form-rule").addEventListener("submit", function (e) {
    e.preventDefault();
    var kind = e.submitter ? e.submitter.getAttribute("data-list") : "allow", dom = $("rule-domain").value.trim();
    if (!dom) return;
    api("/api/rules", { list: kind, domain: dom }).then(function (r) {
      if (r.ok) { $("rule-domain").value = ""; loadRules(); } else toast(t("error"));
    });
  });
  $("btn-reset-fixes").addEventListener("click", function () { api("/api/reset-fixes", {}).then(function () { toast(t("adv.fixes_reset")); load(); }); });

  function confirmBox(title, text, okLabel, cb) {
    $("confirm-title").textContent = title; $("confirm-text").textContent = text; $("confirm-ok").textContent = okLabel;
    var dlg = $("dlg-confirm");
    dlg.onclose = function () { if (dlg.returnValue === "ok") cb(); };
    dlg.showModal();
  }
  $("btn-am").addEventListener("click", function () {
    var am = S.summary.system.address_mode, res = $("am-result");
    confirmBox(t(am ? "adv.am_disable_title" : "adv.am_confirm_title"), t(am ? "adv.am_disable_text" : "adv.am_confirm_text"),
      t(am ? "adv.am_disable" : "adv.am_enable"), function () {
        res.textContent = "…"; res.className = "result";
        api("/api/address-mode", { enabled: !am }).then(function (r) {
          res.className = "result " + (r.ok ? "ok" : "bad");
          res.textContent = r.ok ? (am ? t("adv.am_off") : t("adv.am_on")) : t(r.reason === "router_dhcp_on" ? "adv.am_router_dhcp" : "adv.am_error");
          load();
        });
      });
  });
  $("btn-change-pin").addEventListener("click", function () {
    $("cp-old").value = ""; $("cp-new").value = ""; $("cp-msg").textContent = ""; $("dlg-pin").showModal();
  });
  $("form-change-pin").addEventListener("submit", function (e) {
    if (e.submitter && e.submitter.value === "cancel") return;
    e.preventDefault();
    api("/api/change-pin", { old: $("cp-old").value, pin: $("cp-new").value }).then(function (r) {
      if (r.ok) { $("dlg-pin").close(); toast(t("pin.changed")); return; }
      $("cp-msg").textContent = r.reason === "wrong" || r.reason === "locked" ? t("pin.wrong") : pinError(r.reason);
    });
  });
  $("btn-new-code").addEventListener("click", function () {
    api("/api/new-recovery", {}).then(function (r) { if (r.ok) showCode(r.recovery, "dash"); });
  });
  $("btn-update-lists").addEventListener("click", function () { api("/api/update-lists", {}).then(function () { toast(t("sys.lists_updating")); load(); }); });
  $("btn-clear-history").addEventListener("click", function () {
    confirmBox(t("adv.clear_title"), t("adv.clear_confirm"), t("adv.clear_history"), function () {
      api("/api/clear-history", {}).then(function () { toast(t("adv.cleared")); load(); });
    });
  });

  // ---------- header ----------
  $("btn-lock").addEventListener("click", function () { api("/api/logout", {}).then(function () { S.summary = null; showLogin(); }); });
  $("btn-theme").addEventListener("click", toggleTheme);
  document.querySelectorAll("#chart-range button").forEach(function (b) {
    b.addEventListener("click", function () { S.range = b.getAttribute("data-range"); renderChart(); });
  });
  document.addEventListener("visibilitychange", function () { if (!document.hidden && !$("screen-dash").classList.contains("hidden")) load(); });
  setInterval(applyTheme, 60000);

  // ---------- start ----------
  applyTheme();
  setLang(detectLang()).then(refreshState);
})();
