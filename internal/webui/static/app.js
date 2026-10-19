"use strict";

const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let view = null;
let timer = null;
// Inside the pfSense GUI (`meshgate pfsense install`) calls go through its
// meshgate_api.php proxy, and the pfSense login replaces meshgate's own.
const BASE = document.documentElement.dataset.api || "";
if (BASE) document.getElementById("logout").classList.add("hidden");

// Inside the Android app the dashboard is bundled in the APK and talks to
// whichever server answers, through the app (window.MeshgateApp).
const bridge = window.MeshgateApp;
const bridgeWait = {};
let bridgeSeq = 0;
window.__meshgateReply = (id, status, body) => {
  const f = bridgeWait[id];
  delete bridgeWait[id];
  if (f) f(status, body);
};
function viaApp(path, body) {
  return new Promise((resolve) => {
    const id = ++bridgeSeq;
    bridgeWait[id] = (status, text) => resolve({ status, text });
    bridge.request(id, body === undefined ? "GET" : "POST", path, body === undefined ? "" : JSON.stringify(body));
  });
}

async function api(path, body) {
  let status, data;
  if (bridge) {
    const r = await viaApp(path, body);
    status = r.status;
    try { data = JSON.parse(r.text); } catch { data = {}; }
  } else {
    const opts = body === undefined ? {} : {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Meshgate": "1" },
      body: JSON.stringify(body),
    };
    // On pfSense the path travels as ?p=…, so its own query must be encoded.
    const res = await fetch(BASE ? BASE + encodeURIComponent(path) : path, opts);
    status = res.status;
    data = await res.json().catch(() => ({}));
  }
  if (status === 401 && path !== "/auth/login") { showLogin(); throw new Error("login required"); }
  if (status < 200 || status >= 300) throw new Error(data.error || "request failed (" + status + ")");
  return data;
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.add("hidden"), 3500);
}

function showLogin() {
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  clearInterval(timer);
}

async function start() {
  const me = await api("/auth/me");
  if (!me.ok) return showLogin();
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  await refresh();
  clearInterval(timer);
  timer = setInterval(() => refresh().catch(() => {}), 4000);
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api("/auth/login", { username: f.get("username"), password: f.get("password") });
    $("#login-error").textContent = "";
    start();
  } catch (err) { $("#login-error").textContent = err.message; }
});
$("#logout").addEventListener("click", async () => { await api("/auth/logout", {}); showLogin(); });

$("#tabs").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-tab]");
  if (!b) return;
  document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll("main > section").forEach((s) => s.classList.toggle("hidden", s.id !== "tab-" + b.dataset.tab));
  clearInterval(trafficTimer);
  if (b.dataset.tab === "changelog") renderChangelog().catch((err) => toast(err.message));
  if (b.dataset.tab === "traffic") {
    loadHistory().catch((err) => { $("#hist-info").textContent = err.message; });
    refreshTraffic().catch((err) => toast(err.message));
    trafficTimer = setInterval(() => refreshTraffic().catch(() => {}), 3000);
  }
});

// ---------- changelog ----------

// The changelog of the version this node runs: "## " starts a version,
// "+" added (green), "-" removed (red), "~" changed or fixed (yellow).
async function renderChangelog() {
  const { text } = await api("/api/changelog");
  const code = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
  $("#changelog").innerHTML = text.split("\n").map((l) => {
    if (l.startsWith("## ")) return `<h3>${code(l.slice(3))}</h3>`;
    const kind = { "+": "add", "-": "del", "~": "chg" }[l[0]];
    if (kind && l[1] === " ") return `<div class="cl cl-${kind}"><b>${esc(l[0])}</b><span>${code(l.slice(2))}</span></div>`;
    if (l.startsWith("# ") || !l.trim()) return "";
    return `<p class="hint">${code(l)}</p>`;
  }).join("");
}

// ---------- traffic history ----------

// Chosen period, series and visible lines are remembered per browser.
const histPref = (() => { try { return JSON.parse(localStorage.getItem("meshgate-hist")) || {}; } catch { return {}; } })();
const saveHistPref = () => { try { localStorage.setItem("meshgate-hist", JSON.stringify(histPref)); } catch {} };
let hist = null, histRange = histPref.range || "1d", histPts = [], histHover = -1;
const histShow = { in: true, out: true, peak: true, ...(histPref.show || {}) };
const bps = (bytes) => {
  const b = bytes * 8, u = ["bps", "kbps", "Mbps", "Gbps"];
  const i = Math.min(3, Math.max(0, Math.floor(Math.log10(Math.max(b, 1)) / 3)));
  return (b / 1000 ** i).toFixed(i && b / 1000 ** i < 10 ? 1 : 0) + " " + u[i];
};

document.querySelectorAll("#hist-range button").forEach((x) => x.classList.toggle("active", x.dataset.r === histRange));
document.querySelectorAll("#hist-legend button").forEach((x) => x.setAttribute("aria-pressed", histShow[x.dataset.s]));
$("#hist-range").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-r]");
  if (!b) return;
  histRange = histPref.range = b.dataset.r;
  saveHistPref();
  document.querySelectorAll("#hist-range button").forEach((x) => x.classList.toggle("active", x === b));
  loadHistory().catch((err) => { $("#hist-info").textContent = err.message; });
});
$("#hist-series").addEventListener("change", (e) => { histPref.series = e.target.value; saveHistPref(); drawHistory(); });
$("#hist-legend").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-s]");
  if (!b) return;
  histShow[b.dataset.s] = !histShow[b.dataset.s];
  histPref.show = histShow;
  saveHistPref();
  b.setAttribute("aria-pressed", histShow[b.dataset.s]);
  drawHistory();
});
new ResizeObserver(() => drawHistory()).observe($("#hist-chart"));

async function loadHistory() {
  const chart = $("#hist-chart");
  chart.classList.add("loading"); // keep the old picture while the new one loads
  if (!hist) $("#hist-info").textContent = "Loading…";
  try {
    hist = await api("/api/history?range=" + histRange);
  } finally {
    chart.classList.remove("loading");
  }
  const groups = histGroups(hist);
  const sel = $("#hist-series"), keep = sel.value || histPref.series;
  let html = "", section = "";
  for (const g of groups) {
    if (g.section !== section) {
      if (section) html += "</optgroup>";
      if (g.section) html += `<optgroup label="${esc(g.section)}">`;
      section = g.section;
    }
    html += `<option value="${esc(g.value)}">${esc(g.label)}</option>`;
  }
  sel.innerHTML = html + (section ? "</optgroup>" : "");
  if (groups.some((g) => g.value === keep)) sel.value = keep;
  hist.groups = Object.fromEntries(groups.map((g) => [g.value, g]));
  drawHistory();
}

// histLabels: what each series is (forward, https/http site, device link),
// from the log server (which also knows deleted ones) and the current config.
function histLabels(h) {
  const node = (id) => view.nodes.find((n) => n.value.id === id)?.value;
  const target = (x) => x.target_ip || node(x.target_node)?.mesh_ip || "";
  const L = { ...(h.labels || {}) };
  for (const { value: f } of view.forwards || []) {
    L["f:" + f.id] = { ...L["f:" + f.id], kind: "forward", name: f.name, proto: f.proto,
      port: f.listen_end > f.listen_port ? `${f.listen_port}-${f.listen_end}` : String(f.listen_port),
      target_ip: target(f), target_port: String(f.target_port), target_node: nodeName(f.target_node), node: nodeName(f.edge_node) };
  }
  for (const { value: r } of view.routes || []) {
    for (const [p, kind, port] of [["r:", "https", "443"], ["h:", "http", "80"]]) {
      L[p + r.id] = { ...L[p + r.id], kind, hostname: r.hostname, port, target_ip: target(r),
        target_port: String(r.target_port), target_node: nodeName(r.target_node), node: nodeName(r.edge_node) };
    }
  }
  for (const k of Object.keys(h.series || {})) {
    if (k.startsWith("d:") && !L[k]) { const [peer, by] = k.slice(2).split("@"); L[k] = { kind: "link", peer: nodeName(peer), node: nodeName(by) }; }
  }
  return L;
}

// seriesName: one line describing a series.
function seriesName(k, l = {}) {
  const tgt = l.target_ip ? ` → ${l.target_ip}${l.target_port ? ":" + l.target_port : ""}` : "";
  if (k.startsWith("f:")) return `${l.name || "forward"} (${l.proto || "?"} ${l.port || "?"}${tgt})`;
  if (k.startsWith("r:") || k.startsWith("h:")) return `${k[0] === "r" ? "https" : "http"}://${l.hostname || "?"}${tgt}`;
  if (k.startsWith("d:")) return `${l.peer || "?"} ↔ ${l.node || "?"}`;
  return k;
}

// histGroups: every choice of "Show", each the series it adds up.
function histGroups(h) {
  const L = histLabels(h), live = new Set(Object.keys(L));
  const keys = [...new Set([...Object.keys(h.series || {}), ...[...live].filter((k) => !k.startsWith("d:"))])].sort();
  const current = new Set([...(view.forwards || []).map((x) => "f:" + x.value.id),
    ...(view.routes || []).flatMap((x) => ["r:" + x.value.id, "h:" + x.value.id])]);
  const gone = (k) => (current.has(k) || k.startsWith("d:") ? "" : " (deleted)");
  const out = [{ value: "all", label: "Everything (all forwards and sites)", keys: keys.filter((k) => !k.startsWith("d:")), section: "" }];
  const add = (section, value, label, ks) => out.push({ section, value, label, keys: ks });
  const by = (f) => { const m = {}; for (const k of keys) { const v = f(k); if (v) (m[v] ||= []).push(k); } return m; };
  const ips = by((k) => !k.startsWith("d:") && L[k]?.target_ip);
  for (const ip of Object.keys(ips).sort()) add("Per target IP", "ip:" + ip, ip, ips[ip]);
  const ports = by((k) => (k.startsWith("f:") || k.startsWith("r:") || k.startsWith("h:")) && L[k]?.port && `${L[k].port}`);
  for (const p of Object.keys(ports).sort((a, b) => parseInt(a, 10) - parseInt(b, 10))) add("Per public port", "port:" + p, "Port " + p, ports[p]);
  const nodes = by((k) => k.startsWith("d:") && L[k]?.node);
  for (const n of Object.keys(nodes).sort()) add("Per node (all its WireGuard links)", "node:" + n, n, nodes[n]);
  for (const k of keys.filter((k) => k.startsWith("f:"))) add("Port forwards", k, seriesName(k, L[k]) + gone(k), [k]);
  for (const k of keys.filter((k) => k.startsWith("r:") || k.startsWith("h:"))) add("Sites (HTTPS and HTTP)", k, seriesName(k, L[k]) + gone(k), [k]);
  for (const k of keys.filter((k) => k.startsWith("d:"))) add("Device links", k, seriesName(k, L[k]), [k]);
  out.labels = L;
  return out;
}

// niceStep: 1, 2 or 5 times a power of ten, so the axis reads 0 / 5 / 10 / 15 Mbps.
const niceStep = (max, n) => {
  const raw = max / n, p = 10 ** Math.floor(Math.log10(raw));
  return [1, 2, 2.5, 5, 10].map((m) => m * p).find((s) => s >= raw);
};

function drawHistory() {
  const chart = $("#hist-chart");
  if (!hist || chart.offsetParent === null) return;
  const keys = hist.groups?.[$("#hist-series").value]?.keys || [];
  // Per time step: [start, avg in, avg out, peak in, peak out, bytes in, bytes out]
  // (stored as bytes; speeds are bytes per step / step).
  const n = Math.round((hist.to - hist.from) / hist.step);
  const pts = Array.from({ length: n }, (_, i) => [hist.from + i * hist.step, 0, 0, 0, 0, 0, 0]);
  let any = false;
  for (const k of keys) {
    for (const b of (hist.series || {})[k] || []) {
      const i = Math.round((b[0] - hist.from) / hist.step);
      if (i < 0 || i >= n) continue;
      pts[i][5] += b[1]; pts[i][6] += b[2]; pts[i][3] += b[3]; pts[i][4] += b[4];
      any = true;
    }
  }
  for (const p of pts) { p[1] = p[5] / hist.step; p[2] = p[6] / hist.step; }
  histPts = pts;

  const W = Math.max(280, chart.clientWidth), H = W < 500 ? 200 : 260;
  const L = 62, R = 10, T = 12, B = 24;
  const cols = [histShow.in && 1, histShow.out && 2, histShow.peak && histShow.in && 3, histShow.peak && histShow.out && 4].filter(Boolean);
  const top = Math.max(1, ...pts.flatMap((p) => cols.map((j) => p[j])));
  const step = niceStep(top * 8, W < 500 ? 3 : 4) / 8, max = Math.ceil(top / step) * step;
  const x = (i) => L + (n > 1 ? i / (n - 1) : 0.5) * (W - L - R);
  const y = (v) => H - B - (v / max) * (H - B - T);
  const path = (j) => pts.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p[j]).toFixed(1)}`).join("");
  const area = (j) => `${path(j)}L${x(n - 1).toFixed(1)},${y(0)}L${x(0).toFixed(1)},${y(0)}Z`;

  let grid = "";
  for (let v = 0; v <= max + step / 2; v += step) {
    grid += `<line class="${v ? "grid" : "base"}" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/>
      <text x="${L - 8}" y="${y(v) + 4}" text-anchor="end">${v ? bps(v) : "0"}</text>`;
  }
  const short = hist.step < 3600, week = hist.range === "1w";
  const fmtTick = (t) => {
    const d = new Date(t * 1000);
    if (short) return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    if (week) return d.toLocaleDateString([], { weekday: "short", day: "numeric" });
    return d.toLocaleDateString([], { month: "short", day: "numeric" });
  };
  const nt = Math.max(3, Math.min(7, Math.floor((W - L) / 100)));
  let ticks = "";
  for (let k = 0; k < nt; k++) {
    const i = Math.round((k / (nt - 1)) * (n - 1));
    const anchor = k === 0 ? "start" : k === nt - 1 ? "end" : "middle";
    ticks += `<text x="${x(i)}" y="${H - 6}" text-anchor="${anchor}">${fmtTick(pts[i][0])}</text>`;
  }

  const layer = (j, color) => (histShow[j === 1 ? "in" : "out"] ? `
    <path d="${area(j)}" fill="url(#g${j})"/>
    ${histShow.peak ? `<path d="${path(j + 2)}" fill="none" stroke="${color}" stroke-opacity=".55" stroke-width="1" stroke-dasharray="3 3"/>` : ""}
    <path d="${path(j)}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/>` : "");
  const grad = (j, color) => `<linearGradient id="g${j}" x1="0" x2="0" y1="0" y2="1">
    <stop offset="0" stop-color="${color}" stop-opacity=".28"/><stop offset="1" stop-color="${color}" stop-opacity=".02"/></linearGradient>`;
  chart.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="Traffic history">
    <defs>${grad(1, "var(--s-in)")}${grad(2, "var(--s-out)")}</defs>
    ${grid}${ticks}${layer(1, "var(--s-in)")}${layer(2, "var(--s-out)")}
    <g id="hist-hover" visibility="hidden"><line class="cross" y1="${T}" y2="${H - B}"/>
      <circle class="dot" r="4.5" fill="var(--s-in)"/><circle class="dot" r="4.5" fill="var(--s-out)"/></g>
    <rect x="${L}" y="0" width="${W - L - R}" height="${H - B}" fill="transparent" id="hist-hit"/></svg>
    <div class="hist-tip" hidden></div>${any ? "" : `<div class="hist-empty">No traffic recorded in this period</div>`}`;

  const hit = $("#hist-hit");
  const at = (e) => {
    const r = hit.getBoundingClientRect();
    return Math.max(0, Math.min(n - 1, Math.round(((e.clientX - r.left) / r.width) * (n - 1))));
  };
  hit.addEventListener("pointermove", (e) => showHistTip(at(e)));
  hit.addEventListener("pointerdown", (e) => showHistTip(at(e)));
  hit.addEventListener("pointerleave", (e) => { if (e.pointerType === "mouse") showHistTip(-1); });
  chart.onkeydown = (e) => {
    const d = { ArrowLeft: -1, ArrowRight: 1, Home: -1e9, End: 1e9 }[e.key];
    if (d === undefined) { if (e.key === "Escape") showHistTip(-1); return; }
    e.preventDefault();
    showHistTip(Math.max(0, Math.min(n - 1, (histHover < 0 ? n - 1 : histHover) + d)));
  };
  chart.onblur = () => showHistTip(-1);
  drawHistory.geo = { x, y, W, L, R };
  if (histHover >= 0 && histHover < n) showHistTip(histHover);

  const sum = (j) => pts.reduce((s, p) => s + p[j + 4], 0);
  const peak = Math.max(0, ...pts.map((p) => Math.max(p[3], p[4])));
  const peakAt = pts.find((p) => Math.max(p[3], p[4]) === peak);
  const tile = (v, l) => `<div><b>${esc(v)}</b><span>${esc(l)}</span></div>`;
  $("#hist-stats").innerHTML = tile(bytes(sum(1)), "to target (in)") + tile(bytes(sum(2)), "from target (out)")
    + tile(peak ? bps(peak) : "–", peak ? "peak, " + fmtWhen(peakAt[0]) : "peak")
    + tile(bps((sum(1) + sum(2)) / (hist.to - hist.from)), "average, both ways");
  $("#hist-info").textContent = `${keys.length ? "" : "Nothing recorded yet for this · "}Stored on ${hist.server} · one point every ${
    hist.step >= 3600 ? hist.step / 3600 + " h" : hist.step / 60 + " min"}`;
}

// ---------- traffic history download ----------

const ymd = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
const localTime = (t) => { const d = new Date(t * 1000); return `${ymd(d)} ${d.toTimeString().slice(0, 5)}`; };
const exportSteps = [[300, "5 minutes"], [900, "15 minutes"], [3600, "1 hour"], [86400, "1 day"]];
const MAX_EXPORT = 9000; // points per series, same limit as the server

function downloadDialog() {
  const today = new Date(), sel = $("#hist-series");
  const shown = sel.selectedOptions[0]?.textContent || "Everything";
  openDialog("Download traffic history", `<div class="form-grid">
    <div class="full"><div class="chips" id="dl-presets">
      <button type="button" data-p="today">Today</button><button type="button" data-p="yesterday">Yesterday</button>
      <button type="button" data-p="7d">Last 7 days</button><button type="button" data-p="month">This month</button>
      <button type="button" data-p="lastmonth">Last month</button><button type="button" data-p="30d">Last 30 days</button>
      <button type="button" data-p="year">This year</button><button type="button" data-p="365d">Last 365 days</button></div></div>
    <label>From (day) <input type="date" name="from" value="${ymd(today)}" required></label>
    <label>To (day, included) <input type="date" name="to" value="${ymd(today)}" required></label>
    <label>Detail <select name="step">${exportSteps.map(([v, l]) => `<option value="${v}">${l}</option>`).join("")}</select></label>
    <label>Format <select name="format"><option value="csv">CSV (Excel, Sheets)</option><option value="json">JSON</option><option value="txt">Text table</option></select></label>
    <label class="full">What <select name="what"><option value="shown">${esc(shown)} (as in the graph)</option>
      <option value="each">Every series separately</option></select></label>
    <p class="hint full" id="dl-hint"></p></div>`,
  async (fd) => {
    const from = new Date(fd.get("from") + "T00:00").getTime() / 1000;
    const to = new Date(fd.get("to") + "T00:00").getTime() / 1000 + 86400;
    const step = +fd.get("step");
    if (!(to > from)) throw new Error("The end day must be on or after the start day.");
    const h = await api(`/api/history?from=${Math.floor(from)}&to=${Math.floor(to)}&step=${step}`);
    const fmt = fd.get("format"), each = fd.get("what") === "each";
    const text = histExport(h, each ? null : sel.value, fmt);
    const what = each ? "every-series" : (sel.selectedOptions[0]?.textContent || "traffic").replace(/[^a-zA-Z0-9.@-]+/g, "_").slice(0, 60);
    saveFile(`meshgate-traffic-${what}-${fd.get("from")}_${fd.get("to")}.${fmt}`,
      { csv: "text/csv", json: "application/json", txt: "text/plain" }[fmt], text);
  }, { ok: "Download", done: "", reload: false });

  const f = $("#dialog-form");
  const fit = () => { // the finest detail that fits the period, and a hint
    const days = (new Date(f.to.value) - new Date(f.from.value)) / 864e5 + 1;
    const ok = (s) => (days * 86400) / s <= MAX_EXPORT;
    [...f.step.options].forEach((o) => { o.disabled = !ok(+o.value); });
    if (f.step.selectedOptions[0]?.disabled) f.step.value = exportSteps.find(([s]) => ok(s))?.[0] ?? 86400;
    $("#dl-hint").textContent = days > 0
      ? `${days} day${days > 1 ? "s" : ""} · ${Math.ceil((days * 86400) / f.step.value).toLocaleString()} rows per series. Exact bytes in and out per row, totals at the end, peaks in bytes per second, times in this device's time zone.`
      : "The end day must be on or after the start day.";
  };
  f.from.onchange = f.to.onchange = f.step.onchange = fit;
  $("#dl-presets").onclick = (e) => {
    const p = e.target.closest("button[data-p]")?.dataset.p;
    if (!p) return;
    const d = (y, m, day) => ymd(new Date(y, m, day)), y = today.getFullYear(), m = today.getMonth(), day = today.getDate();
    const [a, b] = {
      today: [d(y, m, day), d(y, m, day)], yesterday: [d(y, m, day - 1), d(y, m, day - 1)],
      "7d": [d(y, m, day - 6), d(y, m, day)], month: [d(y, m, 1), d(y, m, day)],
      lastmonth: [d(y, m - 1, 1), d(y, m, 0)], "30d": [d(y, m, day - 29), d(y, m, day)],
      year: [d(y, 0, 1), d(y, m, day)], "365d": [d(y, m, day - 364), d(y, m, day)],
    }[p];
    f.from.value = a; f.to.value = b;
    f.step.value = 300; // finest that fits
    fit();
  };
  fit();
}

// histExport turns a history answer into the chosen file: one row per series
// and time step (steps without traffic included as zeros), amounts in exact
// bytes, and totals per series and overall.
function histExport(h, choice, fmt) {
  const groups = histGroups(h), L = groups.labels;
  let series; // [{name, keys, label}]
  if (choice === null) {
    series = Object.keys(h.series || {}).sort().map((k) => ({ key: k, name: seriesName(k, L[k]), keys: [k], label: L[k] || {} }));
  } else {
    const g = groups.find((x) => x.value === choice) || groups[0];
    series = [{ key: g.value, name: g.label, keys: g.keys, label: g.keys.length === 1 ? L[g.keys[0]] || {} : {} }];
  }
  const n = Math.round((h.to - h.from) / h.step);
  const labelCols = ["kind", "name", "hostname", "proto", "port", "target_ip", "target_port", "target_node", "node", "peer"];
  for (const sr of series) {
    const pts = Array.from({ length: n }, (_, i) => [h.from + i * h.step, 0, 0, 0, 0]);
    for (const k of sr.keys) for (const b of h.series[k] || []) {
      const i = Math.round((b[0] - h.from) / h.step);
      if (i >= 0 && i < n) for (let j = 1; j < 5; j++) pts[i][j] += b[j];
    }
    sr.rows = pts.map((p) => ({ time: localTime(p[0]), unix: p[0], bytes_in: Math.round(p[1]), bytes_out: Math.round(p[2]),
      bytes_total: Math.round(p[1] + p[2]), peak_in_bytes_per_sec: Math.round(p[3]), peak_out_bytes_per_sec: Math.round(p[4]) }));
    sr.total = sr.rows.reduce((t, r) => ({ bytes_in: t.bytes_in + r.bytes_in, bytes_out: t.bytes_out + r.bytes_out,
      bytes_total: t.bytes_total + r.bytes_total, peak_in_bytes_per_sec: Math.max(t.peak_in_bytes_per_sec, r.peak_in_bytes_per_sec),
      peak_out_bytes_per_sec: Math.max(t.peak_out_bytes_per_sec, r.peak_out_bytes_per_sec) }),
    { bytes_in: 0, bytes_out: 0, bytes_total: 0, peak_in_bytes_per_sec: 0, peak_out_bytes_per_sec: 0 });
  }
  // Totals over several series: forwards and sites apart from device links,
  // since a forward's traffic also crosses a link (adding them would count it twice).
  const sums = {};
  for (const sr of series) {
    const g = sr.key.startsWith("d:") || sr.key.startsWith("node:") ? "All device links" : "All forwards and sites";
    const t = (sums[g] ||= { bytes_in: 0, bytes_out: 0, bytes_total: 0 });
    for (const k in t) t[k] += sr.total[k];
  }
  const grand = series.length > 1 ? sums : {};
  const period = `${localTime(h.from)} to ${localTime(h.to)}`;
  const every = exportSteps.find(([s]) => s === h.step)?.[1] || h.step + " seconds";

  if (fmt === "json") {
    return JSON.stringify({ from: h.from, to: h.to, period, step_seconds: h.step, stored_on: h.server, units: "bytes",
      totals: grand, series: series.map((sr) => ({ series: sr.name, key: sr.key, ...sr.label, total: sr.total, rows: sr.rows })) }, null, 2);
  }
  const amounts = ["bytes_in", "bytes_out", "bytes_total", "peak_in_bytes_per_sec", "peak_out_bytes_per_sec"];
  if (fmt === "csv") {
    const cols = ["time", "unix", "series", ...labelCols, ...amounts];
    const q = (v) => (v === undefined ? "" : typeof v === "string" && /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
    const line = (r) => cols.map((c) => q(r[c])).join(",");
    const lines = [cols.join(",")];
    for (const sr of series) for (const r of sr.rows) lines.push(line({ ...sr.label, ...r, series: sr.name }));
    for (const sr of series) lines.push(line({ ...sr.label, ...sr.total, time: "TOTAL", series: sr.name }));
    for (const [g, t] of Object.entries(grand)) lines.push(line({ ...t, time: "TOTAL", series: g }));
    return lines.join("\r\n") + "\r\n";
  }
  // Text: a table per series, exact bytes plus a readable total.
  const out = [`meshgate traffic history · ${period} · one row per ${every} · stored on ${h.server}`,
    "Amounts in bytes; peaks in bytes per second.", ""];
  const head = ["Time", "Bytes in", "Bytes out", "Bytes total", "Peak in B/s", "Peak out B/s"];
  const num = (v) => v.toLocaleString("en-US");
  for (const sr of series) {
    const l = sr.label, info = [l.node && "measured on " + l.node, l.target_node && "target node " + l.target_node].filter(Boolean).join(", ");
    const table = [head, ...sr.rows.map((r) => [r.time, ...amounts.map((c) => num(r[c]))]), ["TOTAL", ...amounts.map((c) => num(sr.total[c]))]];
    const w = head.map((_, i) => Math.max(...table.map((r) => String(r[i]).length)));
    out.push(`== ${sr.name}${info ? " (" + info + ")" : ""}`);
    out.push(`   total ${num(sr.total.bytes_total)} bytes (${bytes(sr.total.bytes_total)}): ${num(sr.total.bytes_in)} in, ${num(sr.total.bytes_out)} out`);
    for (const r of table) out.push(r.map((v, i) => (i ? String(v).padStart(w[i]) : String(v).padEnd(w[i]))).join("  "));
    out.push("");
  }
  for (const [g, t] of Object.entries(grand)) out.push(`== ${g}: ${num(t.bytes_total)} bytes (${bytes(t.bytes_total)}): ${num(t.bytes_in)} in, ${num(t.bytes_out)} out`);
  return out.join("\n");
}

// saveFile hands a file to the browser, or to Android's "save as" in the app.
function saveFile(name, mime, text) {
  if (bridge?.save) return bridge.save(name, mime, text);
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  toast("Downloaded " + name);
}

$("#hist-download").addEventListener("click", () => { if (view) downloadDialog(); });

const fmtWhen = (t) => new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

function showHistTip(i) {
  histHover = i;
  const g = $("#hist-hover"), tip = document.querySelector("#hist-chart .hist-tip");
  if (!g || !tip) return;
  if (i < 0) { g.setAttribute("visibility", "hidden"); tip.hidden = true; return; }
  const { x, y, W } = drawHistory.geo, p = histPts[i];
  const [line, dIn, dOut] = g.children;
  line.setAttribute("x1", x(i)); line.setAttribute("x2", x(i));
  dIn.setAttribute("cx", x(i)); dIn.setAttribute("cy", y(p[1])); dIn.setAttribute("visibility", histShow.in ? "inherit" : "hidden");
  dOut.setAttribute("cx", x(i)); dOut.setAttribute("cy", y(p[2])); dOut.setAttribute("visibility", histShow.out ? "inherit" : "hidden");
  g.setAttribute("visibility", "visible");

  // Built with textContent: nothing from the data is parsed as HTML.
  tip.replaceChildren();
  const el = (tag, cls, text, parent = tip) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    parent.appendChild(e);
    return e;
  };
  const end = new Date((p[0] + hist.step) * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  el("div", "t", fmtWhen(p[0]) + " – " + end);
  for (const [j, name, color] of [[1, "In", "var(--s-in)"], [2, "Out", "var(--s-out)"]]) {
    if (!histShow[j === 1 ? "in" : "out"]) continue;
    const r = el("div", "r");
    el("i", "", undefined, r).style.color = color;
    el("span", "", name, r);
    el("b", "", bps(p[j]), r);
    el("div", "sub", `peak ${bps(p[j + 2])} · ${bytes(p[j + 4])}`);
  }
  tip.hidden = false;
  const left = x(i) + 14, wTip = tip.offsetWidth;
  tip.style.left = (left + wTip > W ? Math.max(0, x(i) - 14 - wTip) : left) + "px";
}

// ---------- traffic ----------

let trafficTimer = null;
const rate = (b) => (b >= 1 ? bytes(Math.round(b)) + "/s" : "–");
const empty = (cols, text) => `<tr><td colspan="${cols}" class="empty">${text}</td></tr>`;

async function refreshTraffic() {
  if (!view) return;
  const reports = await api("/api/traffic");
  const fwd = {}, routes = {}, rules = {}, recent = [], devices = [];
  const add = (m, id, r) => {
    const t = (m[id] ||= { in: 0, out: 0, in_rate: 0, out_rate: 0, requests: 0, errors: 0, req_rate: 0 });
    for (const k in t) t[k] += r[k] || 0;
  };
  for (const t of reports) {
    for (const [id, r] of Object.entries(t.forwards || {})) add(fwd, id, r);
    for (const [id, r] of Object.entries(t.routes || {})) add(routes, id, r);
    for (const [id, n] of Object.entries(t.acls || {})) rules[id] = (rules[id] || 0) + n;
    for (const [id, r] of Object.entries(t.peers || {})) devices.push({ by: t.node, peer: id, ...r });
    recent.push(...(t.recent || []));
  }
  const node = (id) => view.nodes.find((n) => n.value.id === id)?.value;
  const targetIP = (x) => x.target_ip || node(x.target_node)?.mesh_ip || "?";
  const speed = (r) => (r.in_rate || 0) + (r.out_rate || 0);

  // By target IP: forwards and HTTPS routes to the same machine add up.
  const ips = {};
  const ipAdd = (ip, label, r) => {
    const t = (ips[ip] ||= { ip, uses: [], in: 0, out: 0, in_rate: 0, out_rate: 0 });
    t.uses.push(label);
    for (const k of ["in", "out", "in_rate", "out_rate"]) t[k] += r[k] || 0;
  };
  (view.forwards || []).forEach(({ value: f }) => ipAdd(targetIP(f), `${f.name} (${f.proto} ${f.listen_port})`, fwd[f.id] || {}));
  (view.routes || []).forEach(({ value: r }) => ipAdd(targetIP(r), r.hostname, routes[r.id] || {}));
  const ipRows = Object.values(ips).sort((a, b) => speed(b) - speed(a) || b.in + b.out - (a.in + a.out));
  const top = Math.max(...ipRows.map(speed), 0);
  $("#traffic-ips").innerHTML = `<tr><th>Target IP</th><th>Used by</th><th>To it</th><th>From it</th><th>Total</th></tr>` +
    (ipRows.map((t) => `<tr><td class="mono"><b class="${top > 0 && speed(t) === top ? "busy" : ""}">${esc(t.ip)}</b>${top > 0 && speed(t) === top ? ' <span class="chip">busiest</span>' : ""}</td>
      <td>${esc(t.uses.join(", "))}</td><td>${rate(t.in_rate)}</td><td>${rate(t.out_rate)}</td>
      <td>${bytes(t.in + t.out)}</td></tr>`).join("") || empty(5, "No forwards or HTTPS routes yet"));

  $("#traffic-forwards").innerHTML = `<tr><th>Forward</th><th>Public</th><th>Target</th><th>To target</th><th>From target</th><th>Total in / out</th></tr>` +
    ((view.forwards || []).map(({ value: f }) => {
      const r = fwd[f.id] || {};
      return `<tr><td><b>${esc(f.name)}</b>${f.enabled ? "" : ' <span class="chip">off</span>'}</td>
        <td class="mono">${esc(nodeName(f.edge_node))}:${f.listen_port}${f.listen_end ? "-" + f.listen_end : ""}/${esc(f.proto)}</td>
        <td class="mono">${esc(targetIP(f))}:${f.target_port}</td><td>${rate(r.in_rate)}</td><td>${rate(r.out_rate)}</td>
        <td>${bytes(r.in || 0)} / ${bytes(r.out || 0)}</td></tr>`;
    }).join("") || empty(6, "No port forwards yet"));

  $("#traffic-routes").innerHTML = `<tr><th>Hostname</th><th>Requests/min</th><th>Requests</th><th>Errors</th><th>Speed</th><th>Total</th></tr>` +
    ((view.routes || []).map(({ value: rt }) => {
      const r = routes[rt.id] || {};
      return `<tr><td><b>${esc(rt.hostname)}</b></td><td>${Math.round((r.req_rate || 0) * 60)}</td><td>${r.requests || 0}</td>
        <td>${r.errors ? `<span class="busy">${r.errors}</span>` : 0}</td><td>${rate(speed(r))}</td><td>${bytes((r.in || 0) + (r.out || 0))}</td></tr>`;
    }).join("") || empty(6, "No HTTPS routes yet"));

  recent.sort((a, b) => b.time - a.time);
  $("#traffic-recent").innerHTML = `<tr><th>Time</th><th>Visitor</th><th>Request</th><th>Status</th><th>Size</th><th>Took</th></tr>` +
    (recent.slice(0, 30).map((q) => `<tr><td>${new Date(q.time * 1000).toLocaleTimeString()}</td><td class="mono">${esc(q.client)}</td>
      <td class="mono">${esc(q.method)} ${esc(q.host)}${esc(q.path)}</td><td>${q.status >= 500 ? `<span class="busy">${q.status}</span>` : q.status}</td>
      <td>${bytes(q.bytes)}</td><td>${q.ms} ms</td></tr>`).join("") || empty(6, "No HTTPS requests yet"));

  // A link between two servers is measured at both ends: keep one row.
  const links = {};
  for (const d of devices) {
    const k = [d.by, d.peer].sort().join("|");
    if (!links[k] || d.in + d.out > links[k].in + links[k].out) links[k] = d;
  }
  devices.length = 0;
  devices.push(...Object.values(links));
  devices.sort((a, b) => speed(b) - speed(a) || b.in + b.out - (a.in + a.out));
  $("#traffic-devices").innerHTML = `<tr><th>Device</th><th>Link</th><th>Received</th><th>Sent</th><th>Total</th></tr>` +
    (devices.map((d) => `<tr><td><b>${esc(nodeName(d.peer))}</b></td><td>${esc(nodeName(d.peer))} ↔ ${esc(nodeName(d.by))}</td>
      <td>${rate(d.out_rate)}</td><td>${rate(d.in_rate)}</td><td>${bytes(d.in + d.out)}</td></tr>`).join("") || empty(5, "No traffic yet"));

  $("#traffic-rules").innerHTML = `<tr><th>Rule</th><th>Enforced on</th><th>Connections allowed</th></tr>` +
    ((view.acls || []).map(({ value: a }) => `<tr><td><b>${esc(a.name)}</b></td><td>${esc(nodeName(a.node))}</td><td>${rules[a.id] || 0}</td></tr>`).join("")
      || empty(3, "No access rules yet"));
  labelTables();
}

// ---------- rendering ----------

// newer(cur, latest): whether release latest (vX.Y.Z) is newer than cur.
function newer(cur, latest) {
  const p = (v) => /^v?(\d+)\.(\d+)\.(\d+)$/.exec(v || "")?.slice(1).map(Number);
  const a = p(cur), b = p(latest);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return b[i] > a[i];
  return false;
}

const nodeName = (id) => view.nodes.find((n) => n.value.id === id)?.value.name || id;
const servers = () => view.nodes.filter((n) => n.value.kind === "server").map((n) => n.value);
const relays = () => servers().filter((n) => n.relay && (n.endpoints || []).length);
const exits = () => servers().filter((n) => n.exit);

function ago(ts) {
  const t = new Date(ts).getTime();
  if (!t || t < 0 || new Date(ts).getFullYear() < 2000) return null;
  return Math.max(0, Math.round((Date.now() - t) / 1000));
}
function agoText(s) {
  if (s === null) return "never";
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  return Math.round(s / 3600) + "h ago";
}
function bytes(n) {
  if (!n) return "0";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return (n / 1024 ** i).toFixed(i ? 1 : 0) + " " + u[i];
}
const localChip = (it) => (it.local ? ' <span class="chip local" title="Only applied on this node">local</span>' : "");

async function refresh() {
  view = await api("/api/view");
  const rt = view.runtime || {};
  const w = rt.warnings || [];
  $("#warnings").innerHTML = w.length ? `<div class="warn-box"><ul>${w.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>` : "";
  const self = view.nodes.find((n) => n.value.id === view.self_id)?.value;
  $("#viewpoint").innerHTML = self
    ? `Live connection data as seen from <b>${esc(self.name)}</b> (${esc(self.mesh_ip)})` +
      (rt.home_relay ? ` · preferred relay: <b>${esc(nodeName(rt.home_relay))}</b>` : "") +
      (rt.userspace ? " · userspace WireGuard" : "")
    : "";
  renderNodes(rt);
  renderForwards();
  renderRoutes();
  renderACLs();
  renderExitRoutes();
  renderTokens();
  const sel = $("#static-relay");
  const cur = sel.value;
  sel.innerHTML = relays().map((r) => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join("");
  if (cur) sel.value = cur;
  const nf = $("#network-form");
  if (document.activeElement?.form !== nf) nf.acme_email.value = view.network.acme_email || "";
  const hf = $("#history-form");
  if (document.activeElement?.form !== hf) {
    hf.log_server.innerHTML = '<option value="">Automatic (first VPS relay)</option>' + servers()
      .map((n) => `<option value="${esc(n.id)}" ${n.id === view.network.log_server ? "selected" : ""}>${esc(n.name)}</option>`).join("");
    hf.log_days.value = view.network.log_days || "";
  }
  renderTools();
  labelTables();
}

// On phones every table row is shown as a card (see app.css); label each
// cell with its column name so the cards stay readable.
function labelTables() {
  document.querySelectorAll("main table").forEach((t) => {
    const heads = [...t.querySelectorAll("th")].map((th) => th.textContent);
    t.querySelectorAll("tr").forEach((tr) => {
      tr.classList.toggle("head", !!tr.querySelector("th"));
      [...tr.children].forEach((td, i) => { if (td.tagName === "TD") td.dataset.label = heads[i] || ""; });
    });
  });
}

function renderNodes(rt) {
  const rows = view.nodes.map((it) => {
    const n = it.value;
    const p = (rt.peers || {})[n.id];
    let state = "", path = "", hs = "";
    if (n.id === view.self_id) {
      state = '<span class="dot ok"></span>this node';
    } else if (p) {
      const s = ago(p.last_handshake);
      const cls = s === null ? "down" : s < 180 ? "ok" : "stale";
      state = `<span class="dot ${cls}"></span>${s === null ? "no handshake" : s < 180 ? "online" : "idle"}`;
      hs = agoText(s);
      path = p.path === "direct" ? "direct" : p.path ? "via " + esc(nodeName(p.path.replace(/^via /, ""))) : "";
    }
    const roles = [n.kind, n.relay ? "relay" : "", n.exit ? "exit node" : "", n.webui ? "web ui" : "",
      n.test_port ? "test :" + n.test_port : "",
      n.exit_via ? "internet via " + nodeName(n.exit_via) + (n.exit_only ? " only" : "") : "",
      (n.exits_allowed || []).length ? "may use: " + (n.exits_allowed.includes("*") ? "any exit" : n.exits_allowed.map(nodeName).join(", ")) : "",
      (n.lan_exits || []).length ? `LAN exit: ${n.lan_exits.length} → ${nodeName(n.lan_exits[0].via)}` : ""].filter(Boolean).map((r) => `<span class="chip">${esc(r)}</span>`).join(" ");
    const st = view.statuses?.[n.id] || {}, latest = rt.latest || "";
    const isPhone = st.os === "android" || st.os === "ios";
    const outdated = latest && newer(st.version, latest);
    const version = `<span class="mono">${esc(st.version || "?")}</span>` + (outdated
      ? ` <span class="chip local">${isPhone ? "update in the app" : "update available"}</span>` : "");
    const updBtn = outdated && !isPhone && n.kind !== "static" ? `<button class="small" data-update="${esc(n.id)}">Update</button>` : "";
    return `<tr>
      <td><b>${esc(n.name)}</b>${localChip(it)}</td><td>${roles}</td><td>${version}</td><td class="mono">${esc(n.mesh_ip)}</td>
      <td>${state}</td><td>${path}</td><td>${hs}</td>
      <td class="mono">${esc(p?.endpoint || "")}</td>
      <td>${p ? bytes(p.rx_bytes) + " / " + bytes(p.tx_bytes) : ""}</td>
      <td class="mono wrap">${esc((n.routes || []).join(", "))}${(n.routes || []).length ? ({ restricted: ' <span class="chip local">restricted</span>', firewall: ' <span class="chip local">pfSense rules</span>' }[n.lan_policy] || ' <span class="chip">open</span>') : ""}</td>
      <td class="actions">${updBtn}<button class="small" data-edit-node="${esc(n.id)}">Edit</button>
        ${n.id !== view.self_id ? `<button class="small danger" data-del="node:${esc(n.id)}">Remove</button>` : ""}</td></tr>`;
  });
  const latest = rt.latest || "";
  const behind = view.nodes.filter(({ value: n }) => {
    const st = view.statuses?.[n.id] || {};
    return latest && newer(st.version, latest) && st.os !== "android" && st.os !== "ios" && n.kind !== "static";
  });
  $("#updates").innerHTML = latest
    ? (behind.length ? `Release <b>${esc(latest)}</b> is out; ${behind.length} node${behind.length > 1 ? "s" : ""} can update.
        <button class="small" id="update-all">Update all</button>` : `All nodes run the latest release (${esc(latest)}) or newer.`)
    : "";
  $("#nodes").innerHTML = `<tr><th>Name</th><th>Role</th><th>Version</th><th>Mesh IP</th><th>State</th><th>Path</th><th>Handshake</th><th>Endpoint</th><th>Rx / Tx</th><th>Shared subnets / policy</th><th></th></tr>` + rows.join("");
}

function renderForwards() {
  const rows = (view.forwards || []).map((it) => {
    const f = it.value;
    const port = f.listen_end > f.listen_port ? `${f.listen_port}-${f.listen_end}` : f.listen_port;
    const target = `${esc(f.target_ip || nodeName(f.target_node))}:${f.target_port}`;
    return `<tr><td><b>${esc(f.name)}</b>${localChip(it)}</td><td>${esc(f.proto)}</td>
      <td>${esc(nodeName(f.edge_node))}:${port}</td><td>→ ${esc(nodeName(f.target_node))} <span class="mono">${target}</span></td>
      <td>${f.preserve_client_ip ? "real IPs" : "masqueraded"}</td><td>${f.enabled ? '<span class="dot ok"></span>on' : '<span class="dot down"></span>off <span class="hint">(port blocked)</span>'}</td>
      <td class="actions"><button class="small" data-toggle="forward:${esc(f.id)}:${f.enabled ? 0 : 1}">${f.enabled ? "Disable" : "Enable"}</button>
      <button class="small" data-edit-fwd="${esc(f.id)}">Edit</button>
      ${it.local ? `<button class="small" data-clear="forward:${esc(f.id)}">Use cluster value</button>` : ""}
      <button class="small danger" data-del="forward:${esc(f.id)}">Delete</button></td></tr>`;
  });
  $("#forwards").innerHTML = `<tr><th>Name</th><th>Proto</th><th>Public (edge)</th><th>Target</th><th>Client IP</th><th>State</th><th></th></tr>` +
    (rows.join("") || '<tr><td colspan="7" class="empty">No forwards yet</td></tr>');
}

function renderRoutes() {
  const rows = (view.routes || []).map((it) => {
    const r = it.value;
    return `<tr><td><b>${esc(r.hostname)}</b>${localChip(it)}</td><td>${esc(nodeName(r.edge_node))}</td>
      <td>→ ${esc(nodeName(r.target_node))} <span class="mono">${r.target_tls ? "https" : "http"}://${esc(r.target_ip || "mesh")}:${r.target_port}</span></td>
      <td>${r.force_https ? "HTTPS only" : "HTTP + HTTPS"}</td><td>${r.enabled ? "on" : '<span class="chip">off</span>'}</td>
      <td class="actions"><button class="small" data-toggle="httproute:${esc(r.id)}:${r.enabled ? 0 : 1}">${r.enabled ? "Disable" : "Enable"}</button>
      <button class="small" data-edit-route="${esc(r.id)}">Edit</button>
      <button class="small danger" data-del="httproute:${esc(r.id)}">Delete</button></td></tr>`;
  });
  $("#routes").innerHTML = `<tr><th>Hostname</th><th>Edge</th><th>Target</th><th>Mode</th><th>State</th><th></th></tr>` +
    (rows.join("") || '<tr><td colspan="6" class="empty">No HTTPS routes yet</td></tr>');
}

function aclTarget(a) {
  if (a.to === "self") return "this node";
  const lans = view.statuses?.[a.node]?.lans || [];
  const lan = lans.find((l) => l.cidr === a.to);
  return lan ? `${a.to} (${lan.iface})` : a.to;
}

function renderExitRoutes() {
  const rows = (view.exit_routes || []).map((it) => {
    const r = it.value;
    return `<tr><td><b>${esc(r.name)}</b>${localChip(it)}</td><td class="mono">${esc(r.src)}</td><td>${esc(nodeName(r.router))}</td>
      <td>${esc(nodeName(r.via))}</td><td>${r.exit_only ? "yes" : "no"}</td>
      <td>${r.enabled ? '<span class="dot ok"></span>on' : '<span class="chip">off</span>'}</td>
      <td class="actions"><button class="small" data-toggle="exitroute:${esc(r.id)}:${r.enabled ? 0 : 1}">${r.enabled ? "Disable" : "Enable"}</button>
      <button class="small" data-edit-exit="${esc(r.id)}">Edit</button>
      <button class="small danger" data-del="exitroute:${esc(r.id)}">Delete</button></td></tr>`;
  });
  $("#exitroutes").innerHTML = `<tr><th>Name</th><th>Device IP / subnet</th><th>Router</th><th>Exit node</th><th>Exit only</th><th>State</th><th></th></tr>` +
    (rows.join("") || '<tr><td colspan="7" class="empty">No exit routes yet</td></tr>');
}

function exitRouteDialog(it) {
  const r = it?.value || { enabled: true, via: exits()[0]?.id };
  const routerOpts = `<option value="">Automatic (the router sharing that IP's subnet)</option>` +
    servers().filter((n) => (n.routes || []).length).map((n) => `<option value="${esc(n.id)}" ${n.id === r.router ? "selected" : ""}>${esc(n.name)} — ${esc((n.routes || []).join(", "))}</option>`).join("");
  const exitOpts = exits().map((x) => `<option value="${esc(x.id)}" ${x.id === r.via ? "selected" : ""}>${esc(x.name)}</option>`).join("");
  openDialog(it ? "Edit exit route" : "New exit route", `<div class="form-grid">
    <label class="full">Name <input name="name" value="${esc(r.name)}" placeholder="gaming-vm" required></label>
    <label>Device IP or subnet <input name="src" value="${esc(r.src)}" placeholder="192.168.200.11 or 192.168.20.0/24" required></label>
    <label>Exit node <select name="via">${exitOpts || '<option value="">(tick "Exit node" on a VPS first)</option>'}</select></label>
    <label class="full">Router <select name="router">${routerOpts}</select></label>
    <label class="inline full"><input type="checkbox" name="exit_only" ${r.exit_only ? "checked" : ""}> Exit only: if no exit node is reachable, this device gets no internet (instead of your normal connection)</label>
    <label class="inline full"><input type="checkbox" name="enabled" ${r.enabled ? "checked" : ""}> Enabled</label>
    ${scopeField(it?.local)}</div>`,
  async (fd) => {
    await api("/api/exitroute", { scope: fd.get("scope"), exit_route: {
      id: r.id || "", name: fd.get("name"), src: fd.get("src").trim(), router: fd.get("router"), via: fd.get("via"),
      exit_only: fd.get("exit_only") === "on", enabled: fd.get("enabled") === "on" } });
  });
}

function renderACLs() {
  const rows = (view.acls || []).map((it) => {
    const a = it.value;
    const enforcing = view.nodes.find((n) => n.value.id === a.node)?.value;
    const from = (a.from || []).length ? a.from.map(nodeName).join(", ") : "any device";
    const policy = enforcing?.lan_policy === "restricted" ? ""
      : enforcing?.lan_policy === "firewall" ? ' <span class="chip" title="This node uses its pfSense firewall rules instead">pfSense rules</span>'
      : ' <span class="chip" title="This node\'s LAN policy is open, so the rule has no effect yet">policy open</span>';
    return `<tr><td><b>${esc(a.name)}</b>${localChip(it)}</td><td>${esc(nodeName(a.node))}${policy}</td><td>${esc(from)}</td>
      <td class="mono">${esc(aclTarget(a))}</td><td>${a.proto === "both" ? "tcp+udp" : esc(a.proto)}${a.ports ? " " + esc(a.ports) : ""}</td>
      <td>${a.enabled ? "on" : '<span class="chip">off</span>'}</td>
      <td class="actions"><button class="small" data-toggle="acl:${esc(a.id)}:${a.enabled ? 0 : 1}">${a.enabled ? "Disable" : "Enable"}</button>
      <button class="small" data-edit-acl="${esc(a.id)}">Edit</button>
      ${it.local ? `<button class="small" data-clear="acl:${esc(a.id)}">Use cluster value</button>` : ""}
      <button class="small danger" data-del="acl:${esc(a.id)}">Delete</button></td></tr>`;
  });
  $("#acls").innerHTML = `<tr><th>Name</th><th>Enforced on</th><th>From</th><th>To</th><th>Allow</th><th>State</th><th></th></tr>` +
    (rows.join("") || '<tr><td colspan="7" class="empty">No rules yet</td></tr>');
}

function aclDialog(it) {
  const a = it?.value || { proto: "tcp", enabled: true, to: "", from: [], node: servers().find((n) => (n.routes || []).length)?.id };
  const devices = view.nodes.map((n) => n.value).filter((n) => n.id !== a.node);
  const targets = (nodeID) => {
    const lans = view.statuses?.[nodeID]?.lans || [];
    return `<option value="self">this node itself</option>` +
      lans.map((l) => `<option value="${esc(l.cidr)}">${esc(l.cidr)} — ${esc(l.iface)}</option>`).join("") +
      `<option value="custom">a host or other subnet…</option>`;
  };
  openDialog(it ? "Edit access rule" : "New access rule", `<div class="form-grid">
    <label class="full">Name <input name="name" value="${esc(a.name)}" placeholder="laptop to NAS web"></label>
    <label class="full">Enforced on (the node that routes into the LAN, e.g. pfSense) <select name="node" id="acl-node">${nodeOptions(servers(), a.node)}</select></label>
    <div class="full"><label>From (none ticked = any device)</label>
      ${devices.map((d) => `<label class="inline"><input type="checkbox" name="from" value="${esc(d.id)}" ${(a.from || []).includes(d.id) ? "checked" : ""}> ${esc(d.name)} <span class="mono">${esc(d.mesh_ip)}</span></label>`).join("")}</div>
    <label>To <select name="to_pick" id="acl-to">${targets(a.node)}</select></label>
    <label>Host IP or subnet <input name="to_custom" id="acl-custom" placeholder="192.168.20.15 or 192.168.30.0/24"></label>
    <label>Protocol <select name="proto">${[["tcp", "tcp"], ["udp", "udp"], ["both", "tcp + udp"], ["icmp", "icmp (ping)"], ["any", "any"]]
      .map(([v, l]) => `<option value="${v}" ${v === a.proto ? "selected" : ""}>${l}</option>`).join("")}</select></label>
    <label>Ports (tcp/udp; empty = all) <input name="ports" value="${esc(a.ports)}" placeholder="443 or 80,443 or 8000-8100"></label>
    <label class="inline full"><input type="checkbox" name="enabled" ${a.enabled ? "checked" : ""}> Enabled</label>
    ${scopeField(it?.local)}</div>`,
  async (fd) => {
    const pick = fd.get("to_pick");
    const to = pick === "custom" ? fd.get("to_custom").trim() : pick;
    await api("/api/acl", { scope: fd.get("scope"), acl: {
      id: a.id || "", name: fd.get("name"), node: fd.get("node"), from: fd.getAll("from"), to,
      proto: fd.get("proto"), ports: fd.get("ports").trim(), enabled: fd.get("enabled") === "on" } });
  });
  const toSel = $("#acl-to"), custom = $("#acl-custom");
  const sync = () => { custom.disabled = toSel.value !== "custom"; };
  const preset = [...toSel.options].some((o) => o.value === a.to);
  toSel.value = !a.to ? "self" : preset ? a.to : "custom";
  if (toSel.value === "custom") custom.value = a.to;
  sync();
  toSel.addEventListener("change", sync);
  $("#acl-node").addEventListener("change", (e) => { toSel.innerHTML = targets(e.target.value); sync(); });
}

function renderTokens() {
  const rows = (view.tokens || []).map((t) => `<tr><td class="mono">${esc(t.id)}</td><td>${esc(t.kind)}</td><td>${esc(t.note)}</td>
    <td>${t.uses_left < 0 ? "unlimited" : t.uses_left}</td><td>${t.expires_at ? new Date(t.expires_at * 1000).toLocaleString() : "never"}</td>
    <td class="actions"><button class="small danger" data-del="token:${esc(t.id)}">Revoke</button></td></tr>`);
  $("#tokens").innerHTML = `<tr><th>ID</th><th>Type</th><th>Note</th><th>Uses left</th><th>Expires</th><th></th></tr>` +
    (rows.join("") || '<tr><td colspan="6" class="empty">No tokens</td></tr>');
}

// ---------- dialogs ----------

const nodeOptions = (list, sel) => list.map((n) => `<option value="${esc(n.id)}" ${n.id === sel ? "selected" : ""}>${esc(n.name)}</option>`).join("");
const scopeField = (local) => `<div class="full"><label class="inline"><input type="radio" name="scope" value="cluster" ${local ? "" : "checked"}> Apply on all nodes</label>
  <label class="inline"><input type="radio" name="scope" value="local" ${local ? "checked" : ""}> Only on this node (${esc(nodeName(view.self_id))})</label></div>`;

function openDialog(title, inner, onSubmit, { ok = "Save", done = "Saved", reload = true } = {}) {
  const d = $("#dialog"), f = $("#dialog-form");
  f.innerHTML = `<h2>${esc(title)}</h2>${inner}<p class="error" id="dialog-error"></p>
    <div class="dialog-actions"><button value="cancel" class="ghost" formnovalidate>Cancel</button><button value="ok" id="dialog-ok">${esc(ok)}</button></div>`;
  f.onsubmit = async (e) => {
    if (e.submitter?.value !== "ok") return;
    e.preventDefault();
    try { await onSubmit(new FormData(f), f); d.close(); if (reload) refresh(); if (done) toast(done); }
    catch (err) { $("#dialog-error").textContent = err.message; }
  };
  d.showModal();
}

function forwardDialog(it) {
  const f = it?.value || { proto: "tcp", enabled: true, edge_node: relays()[0]?.id };
  const edges = servers();
  openDialog(it ? "Edit forward" : "New forward", `<div class="form-grid">
    <label class="full">Name <input name="name" value="${esc(f.name)}" placeholder="minecraft" required></label>
    <label>Protocol <select name="proto">${["tcp", "udp", "both"].map((p) => `<option ${p === f.proto ? "selected" : ""}>${p}</option>`).join("")}</select></label>
    <label>Edge (public) node <select name="edge_node">${nodeOptions(edges, f.edge_node)}</select></label>
    <label>Public port <input name="listen_port" type="number" min="1" max="65535" value="${f.listen_port || ""}" required></label>
    <label>…to port (range, optional) <input name="listen_end" type="number" min="0" max="65535" value="${f.listen_end || ""}"></label>
    <label>Target node <select name="target_node">${nodeOptions(edges, f.target_node)}</select></label>
    <label>Target port <input name="target_port" type="number" min="1" max="65535" value="${f.target_port || ""}" required></label>
    <label class="full">Target LAN IP (optional — a device behind the target node) <input name="target_ip" value="${esc(f.target_ip)}" placeholder="leave empty if the game runs on the target node"></label>
    <label class="inline full"><input type="checkbox" name="preserve_client_ip" ${f.preserve_client_ip ? "checked" : ""}> Show players' real IPs to the server (service must run on the target node itself)</label>
    <label class="inline full"><input type="checkbox" name="enabled" ${f.enabled ? "checked" : ""}> Enabled</label>
    ${scopeField(it?.local)}</div>`,
  async (fd) => {
    const num = (k) => parseInt(fd.get(k) || "0", 10) || 0;
    await api("/api/forward", { scope: fd.get("scope"), forward: {
      id: f.id || "", name: fd.get("name"), proto: fd.get("proto"), edge_node: fd.get("edge_node"),
      listen_port: num("listen_port"), listen_end: num("listen_end"), target_node: fd.get("target_node"),
      target_ip: fd.get("target_ip").trim(), target_port: num("target_port"),
      preserve_client_ip: fd.get("preserve_client_ip") === "on", enabled: fd.get("enabled") === "on" } });
  });
}

function routeDialog(it) {
  const r = it?.value || { force_https: true, enabled: true, edge_node: relays()[0]?.id };
  const edges = servers();
  openDialog(it ? "Edit HTTPS route" : "New HTTPS route", `<div class="form-grid">
    <label class="full">Hostname <input name="hostname" value="${esc(r.hostname)}" placeholder="jellyfin.example.com" required></label>
    <label>Edge (public) node <select name="edge_node">${nodeOptions(edges, r.edge_node)}</select></label>
    <label>Target node <select name="target_node">${nodeOptions(edges, r.target_node)}</select></label>
    <label>Target LAN IP (optional) <input name="target_ip" value="${esc(r.target_ip)}"></label>
    <label>Target port <input name="target_port" type="number" min="1" max="65535" value="${r.target_port || ""}" required></label>
    <label class="inline full"><input type="checkbox" name="target_tls" ${r.target_tls ? "checked" : ""}> Backend uses HTTPS</label>
    <label class="inline full"><input type="checkbox" name="force_https" ${r.force_https ? "checked" : ""}> Redirect HTTP to HTTPS</label>
    <label class="inline full"><input type="checkbox" name="enabled" ${r.enabled ? "checked" : ""}> Enabled</label>
    ${scopeField(it?.local)}</div>`,
  async (fd) => {
    await api("/api/route", { scope: fd.get("scope"), route: {
      id: r.id || "", hostname: fd.get("hostname"), edge_node: fd.get("edge_node"), target_node: fd.get("target_node"),
      target_ip: fd.get("target_ip").trim(), target_port: parseInt(fd.get("target_port"), 10) || 0,
      target_tls: fd.get("target_tls") === "on", force_https: fd.get("force_https") === "on", enabled: fd.get("enabled") === "on" } });
  });
}

function nodeDialog(it) {
  const n = it.value;
  const exitOptions = `<option value="">Its own connection</option>` + exits().filter((x) => x.id !== n.id)
    .map((x) => `<option value="${esc(x.id)}" ${n.exit_via === x.id ? "selected" : ""}>Through ${esc(x.name)}</option>`).join("");
  const relayField = n.kind === "static"
    ? `<label class="full">Connects through relay <select name="via_relay">${nodeOptions(relays(), n.via_relay)}</select></label>`
    : n.kind === "client"
    ? `<fieldset class="full lan-exit"><legend>May use exit nodes (the device picks among these in its app)</legend>
         <label class="inline"><input type="checkbox" name="exits_any" ${(n.exits_allowed || []).includes("*") ? "checked" : ""}> Any exit node, including ones added later</label>
         ${exits().filter((x) => x.id !== n.id).map((x) => `<label class="inline"><input type="checkbox" name="exits_allowed" value="${esc(x.id)}"
           ${(n.exits_allowed || []).includes(x.id) ? "checked" : ""}> ${esc(x.name)}</label>`).join("") || '<p class="hint">No exit nodes yet: tick "Exit node" on a VPS first.</p>'}
       </fieldset>
       <label class="full">Default: internet traffic away from home <select name="exit_via">${exitOptions}</select></label>
       <label class="inline full"><input type="checkbox" name="exit_only" ${n.exit_only ? "checked" : ""}> Exit only: if no exit node is reachable, block internet instead of using the device's own connection</label>
       <p class="hint full">Through an exit node, websites see that node's IP instead of the device's network. If it goes down, the device moves to another exit node automatically; <i>Exit only</i> decides what happens when none is left. At home the device uses your own connection. Supported in the phone app.</p>`
    : `<label class="full">Endpoints (host:port, one per line — public IP/DNS, LAN IP, router port-forward)
        <textarea name="endpoints" rows="3">${esc((n.endpoints || []).join("\n"))}</textarea></label>
       <label class="full">Shared LAN subnets (one per line) <textarea name="routes" rows="2">${esc((n.routes || []).join("\n"))}</textarea></label>
       <label class="inline full"><input type="checkbox" name="relay" ${n.relay ? "checked" : ""}> Relay (public endpoint reachable from anywhere)</label>
       <label class="inline full"><input type="checkbox" name="exit" ${n.exit ? "checked" : ""}> Exit node (devices you pick send their internet traffic out through this node)</label>
       ${(n.lan_exits || []).length ? `<fieldset class="full lan-exit"><legend>Older LAN exit list: please move these to the Exit routes tab, then clear them here</legend>
         <label>IPs or subnets behind this router, one per line (e.g. 192.168.1.205, 192.168.20.0/24 for a VLAN)
           <textarea name="lan_exit_src" rows="3">${esc((n.lan_exits || []).map((e) => e.src).join("\n"))}</textarea></label>
         <label>Through <select name="lan_exit_via">${exits().filter((x) => x.id !== n.id)
           .map((x) => `<option value="${esc(x.id)}" ${(n.lan_exits || [])[0]?.via === x.id ? "selected" : ""}>${esc(x.name)}</option>`).join("")
           || '<option value="">(no exit node yet — tick "Exit node" on a VPS first)</option>'}</select></label>
         <label class="inline"><input type="checkbox" name="exit_only" ${n.exit_only ? "checked" : ""}> Exit only: if no exit node is reachable, block their internet instead of using your normal connection</label>
         <p class="hint">Their internet traffic leaves through the exit (websites see its IP); if it goes down they move to
           another exit node automatically. Your LAN and mesh stay reachable.</p></fieldset>` : `<p class="hint full">To send LAN devices' internet through an exit node, use the <b>Exit routes</b> tab.</p>`}
       <label class="inline full"><input type="checkbox" name="iptables" ${n.iptables_off ? "" : "checked"}> Add iptables allow rules for this node's forwards, relaying and exits (needed with ufw or Docker; Linux)</label>
       <label class="inline full"><input type="checkbox" name="app_admin" ${n.app_admin_off ? "" : "checked"}> Phone app may manage the mesh through this node</label>
       <label class="full">Test service port (TCP+UDP, empty = off; see Tools) <input name="test_port" type="number" min="1" max="65535" value="${n.test_port || ""}" placeholder="off"></label>
       <label class="full">LAN policy — who may reach this node and its subnets through the mesh
         <select name="lan_policy">
           <option value="open" ${!["restricted", "firewall"].includes(n.lan_policy) ? "selected" : ""}>Open: any mesh device</option>
           <option value="restricted" ${n.lan_policy === "restricted" ? "selected" : ""}>Restricted: only what access rules allow</option>
           <option value="firewall" ${n.lan_policy === "firewall" ? "selected" : ""}>pfSense rules: Firewall → Rules → MESHGATE decides</option>
         </select></label>`;
  openDialog("Edit " + n.name, `<div class="form-grid"><label class="full">Name <input name="name" value="${esc(n.name)}" required></label>${relayField}${scopeField(it.local)}</div>`,
    async (fd) => {
      const lines = (k) => (fd.get(k) || "").split("\n").map((s) => s.trim()).filter(Boolean);
      const patch = { name: fd.get("name") };
      if (n.kind === "static") patch.via_relay = fd.get("via_relay");
      else if (n.kind === "client") {
        const allowed = fd.get("exits_any") === "on" ? ["*"] : fd.getAll("exits_allowed");
        if (fd.get("exit_via") && !allowed.includes("*") && !allowed.includes(fd.get("exit_via"))) allowed.push(fd.get("exit_via"));
        Object.assign(patch, { exit_via: fd.get("exit_via"), exit_only: fd.get("exit_only") === "on", exits_allowed: allowed });
      }
      else Object.assign(patch, { endpoints: lines("endpoints"), routes: lines("routes"), relay: fd.get("relay") === "on",
        exit: fd.get("exit") === "on", lan_policy: fd.get("lan_policy"), test_port: parseInt(fd.get("test_port"), 10) || 0, app_admin: fd.get("app_admin") === "on", iptables: fd.get("iptables") === "on",
        lan_exits: lines("lan_exit_src").map((src) => ({ src, via: fd.get("lan_exit_via") })), exit_only: fd.get("exit_only") === "on" });
      await api("/api/node", { id: n.id, patch, scope: fd.get("scope") });
    });
}

document.addEventListener("click", async (e) => {
  const t = e.target.closest("button");
  if (!t || !view) return;
  if (t.id === "fwd-new") return forwardDialog();
  if (t.id === "route-new") return routeDialog();
  if (t.id === "acl-new") return aclDialog();
  if (t.dataset.editAcl) return aclDialog(view.acls.find((x) => x.value.id === t.dataset.editAcl));
  if (t.id === "exit-new") return exitRouteDialog();
  if (t.dataset.editExit) return exitRouteDialog(view.exit_routes.find((x) => x.value.id === t.dataset.editExit));
  if (t.dataset.editFwd) return forwardDialog(view.forwards.find((x) => x.value.id === t.dataset.editFwd));
  if (t.dataset.editRoute) return routeDialog(view.routes.find((x) => x.value.id === t.dataset.editRoute));
  if (t.dataset.editNode) return nodeDialog(view.nodes.find((x) => x.value.id === t.dataset.editNode));
  if (t.dataset.update || t.id === "update-all") {
    const latest = view.runtime?.latest || "";
    const ids = t.dataset.update ? [t.dataset.update] : view.nodes.filter(({ value: n }) => {
      const st = view.statuses?.[n.id] || {};
      return newer(st.version, latest) && st.os !== "android" && st.os !== "ios" && n.kind !== "static";
    }).map((x) => x.value.id).sort((a) => (a === view.self_id ? 1 : -1)); // this node last: it restarts
    t.disabled = true;
    for (const id of ids) {
      try { const r = await api("/api/update", { node: id }); toast(r.message); } catch (err) { toast(nodeName(id) + ": " + err.message); }
    }
    return;
  }
  if (t.dataset.toggle) {
    const [kind, id, on] = t.dataset.toggle.split(":");
    try { await api("/api/toggle", { kind, id, enabled: on === "1" }); refresh(); toast(on === "1" ? "Enabled" : "Disabled"); } catch (err) { toast(err.message); }
    return;
  }
  if (t.dataset.clear) {
    const [kind, id] = t.dataset.clear.split(":");
    try { await api("/api/clear-local", { kind, id }); refresh(); } catch (err) { toast(err.message); }
  }
  if (t.dataset.del) {
    const [kind, id] = t.dataset.del.split(":");
    if (!confirm(`Delete this ${{ httproute: "route", acl: "rule", exitroute: "exit route" }[kind] || kind}? This applies to all nodes.`)) return;
    try { await api("/api/delete", { kind, id, scope: "cluster" }); refresh(); toast("Deleted"); } catch (err) { toast(err.message); }
  }
});

// ---------- device onboarding ----------

async function qrImg(text) {
  const { png } = await api("/api/qr", { text });
  return `<img alt="QR code" src="${png}">`;
}

$("#token-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const { token } = await api("/api/token", {
      kind: f.get("kind"), uses: parseInt(f.get("uses"), 10) || 1, ttl_hours: parseInt(f.get("ttl_hours"), 10) || 0, note: f.get("note"),
    });
    const url = "https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh";
    const ps1 = "https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.ps1";
    if (f.get("kind") === "server") {
      $("#token-out").innerHTML = `<div class="out">
        <p class="hint"><b>Linux server</b>: run in a shell</p>
        <textarea readonly rows="3">curl -fsSL ${url} | sudo sh -s -- join ${esc(token)}</textarea>
        <p class="hint"><b>pfSense</b>: paste into Diagnostics → Command Prompt → Execute Shell Command.
          No SSH needed; it installs, joins and starts meshgate. pfSense nodes start with the LAN locked down
          (add access rules for what mesh devices may reach).</p>
        <textarea readonly rows="3">fetch -qo - ${url} | sh -s -- join ${esc(token)}</textarea>
        <p class="hint"><b>Windows</b> (PowerShell as Administrator). Windows servers can host a game behind a VPS forward but cannot share their LAN.</p>
        <textarea readonly rows="3">& ([scriptblock]::Create((irm ${ps1}))) join ${esc(token)}</textarea>
        <p class="hint">Token only:</p><textarea readonly rows="2">${esc(token)}</textarea></div>`;
    } else {
      $("#token-out").innerHTML = `<div class="out">${await qrImg(token)}<p class="hint">Phone: scan with the meshgate app.</p>
        <p class="hint"><b>Linux laptop</b></p><textarea readonly rows="2">curl -fsSL ${url} | sudo sh -s -- join ${esc(token)} --kind client</textarea>
        <p class="hint"><b>Windows PC</b> (PowerShell as Administrator)</p><textarea readonly rows="2">& ([scriptblock]::Create((irm ${ps1}))) join ${esc(token)} --kind client</textarea>
        <p class="hint">Token only:</p><textarea readonly>${esc(token)}</textarea></div>`;
    }
    refresh();
  } catch (err) { toast(err.message); }
});

$("#static-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const dev = await api("/api/static-device", { name: f.get("name"), relay: f.get("relay") });
    const blob = URL.createObjectURL(new Blob([dev.config], { type: "text/plain" }));
    $("#static-out").innerHTML = `<div class="out"><p class="hint">Scan with the WireGuard app. The private key is shown only once.</p>
      ${await qrImg(dev.config)}<textarea readonly>${esc(dev.config)}</textarea>
      <p><a download="${esc(dev.node.name)}.conf" href="${blob}">Download .conf</a></p></div>`;
    refresh();
  } catch (err) { toast(err.message); }
});

// Tools tab: checks run on the node serving the dashboard.
function diagPortField() {
  const k = $("#diag-form").kind.value;
  $("#diag-port").classList.toggle("hidden", k !== "tcp" && k !== "udp");
  $("#diag-target").classList.toggle("hidden", k === "myip");
}
$("#diag-form").kind.addEventListener("change", diagPortField);
diagPortField();
$("#diag-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target, out = $("#diag-out"), btn = $("#diag-run");
  btn.disabled = true; btn.textContent = "Running…";
  out.classList.remove("hidden", "bad"); out.textContent = "Running…";
  try {
    const r = await api("/api/diag", { kind: f.kind.value, target: f.target.value.trim(), port: parseInt(f.port.value, 10) || 0 });
    out.textContent = r.output; out.classList.toggle("bad", !r.ok);
  } catch (err) { out.textContent = err.message; out.classList.add("bad"); }
  btn.disabled = false; btn.textContent = "Run";
});

// Quick-pick targets for the Tools tab: mesh devices, servers' public
// addresses, both ends of every port forward, and HTTPS sites.
function diagPicks() {
  const groups = { "Mesh devices": [], "Public addresses": [], "Port forwards (from outside)": [], "Port forwards (target)": [], "HTTPS sites": [] };
  const node = (id) => view.nodes.find((n) => n.value.id === id)?.value;
  const publicHost = (n) => (n?.endpoints || []).map((e) => e.replace(/:\d+$/, "")).find((h) => !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(h));
  const l4 = (p) => (p === "udp" ? "udp" : "tcp");
  view.nodes.forEach(({ value: n }) => {
    if (n.mesh_ip) groups["Mesh devices"].push({ label: `${n.name} — ${n.mesh_ip}`, target: n.mesh_ip });
    const pub = n.kind === "server" && publicHost(n);
    if (pub) groups["Public addresses"].push({ label: `${n.name} public — ${pub}`, target: pub });
  });
  (view.forwards || []).forEach(({ value: f }) => {
    const pub = publicHost(node(f.edge_node));
    if (pub) groups["Port forwards (from outside)"].push({ label: `${f.name} — ${pub}:${f.listen_port}/${f.proto}`, target: pub, port: f.listen_port, kind: l4(f.proto) });
    const ip = f.target_ip || node(f.target_node)?.mesh_ip;
    if (ip) groups["Port forwards (target)"].push({ label: `${f.name} target — ${ip}:${f.target_port}`, target: ip, port: f.target_port, kind: l4(f.proto) });
  });
  (view.routes || []).forEach(({ value: r }) => groups["HTTPS sites"].push({ label: r.hostname, target: "https://" + r.hostname + "/", kind: "http" }));
  return groups;
}

function renderPicks() {
  const groups = diagPicks(), sel = $("#diag-pick"), keep = sel.value;
  const all = [];
  sel.innerHTML = '<option value="">— choose a device, forward or site, or type below —</option>' +
    Object.entries(groups).filter(([, l]) => l.length).map(([g, l]) => `<optgroup label="${esc(g)}">` +
      l.map((p) => { all.push(p); return `<option value="${esc(JSON.stringify(p))}">${esc(p.label)}</option>`; }).join("") + "</optgroup>").join("");
  sel.value = keep;
  $("#diag-targets").innerHTML = [...new Map(all.map((p) => [p.target, p])).values()]
    .map((p) => `<option value="${esc(p.target)}">${esc(p.label)}</option>`).join("");
}

$("#diag-pick").addEventListener("change", (e) => {
  if (!e.target.value) return;
  const p = JSON.parse(e.target.value), f = $("#diag-form");
  const kind = f.kind.value;
  // Forwards switch to their TCP/UDP check, sites to HTTP; a device keeps the
  // current check unless it needs a URL or no target at all.
  if (p.kind) f.kind.value = p.kind;
  else if (kind === "http" || kind === "myip") f.kind.value = "ping";
  f.target.value = f.kind.value === "http" && !p.target.startsWith("http") ? "http://" + p.target + (p.port ? ":" + p.port : "") + "/" : p.target;
  if (p.port) f.port.value = p.port;
  diagPortField();
});

function renderTools() {
  renderPicks();
  const self = view.nodes.find((n) => n.value.id === view.self_id)?.value;
  if (self) $("#diag-from").textContent = `Runs from ${self.name} (${self.mesh_ip}), the node serving this page.`;
  const on = servers().filter((n) => n.test_port);
  $("#test-nodes").innerHTML = on.length
    ? "<p><b>On now:</b> " + on.map((n) => `${esc(n.name)} → <code>${esc(n.mesh_ip)}:${n.test_port}</code>`).join(", ") + "</p>"
    : '<p class="hint">Off on every node.</p>';
}

$("#history-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api("/api/history-settings", { log_server: f.get("log_server"), log_days: parseInt(f.get("log_days"), 10) || 0 });
    toast("Saved"); refresh();
  } catch (err) { toast(err.message); }
});

$("#network-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try { await api("/api/network", { acme_email: new FormData(e.target).get("acme_email") }); toast("Saved"); } catch (err) { toast(err.message); }
});
$("#admin-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try { await api("/api/admin", { username: f.get("username"), password: f.get("password") }); e.target.reset(); toast("Saved"); } catch (err) { toast(err.message); }
});

start().catch(() => showLogin());
