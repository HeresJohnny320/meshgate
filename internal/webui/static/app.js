"use strict";

const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let view = null;
let timer = null;
// Inside the pfSense GUI (`meshgate pfsense install`) calls go through its
// meshgate_api.php proxy, and the pfSense login replaces meshgate's own.
const BASE = document.documentElement.dataset.api || "";
if (BASE) document.getElementById("logout").classList.add("hidden");

async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Meshgate": "1" },
    body: JSON.stringify(body),
  };
  const res = await fetch(BASE + path, opts);
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { showLogin(); throw new Error("login required"); }
  if (!res.ok) throw new Error(data.error || res.statusText);
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
});

// ---------- rendering ----------

const nodeName = (id) => view.nodes.find((n) => n.value.id === id)?.value.name || id;
const servers = () => view.nodes.filter((n) => n.value.kind === "server").map((n) => n.value);
const relays = () => servers().filter((n) => n.relay && (n.endpoints || []).length);

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
  renderTokens();
  const sel = $("#static-relay");
  const cur = sel.value;
  sel.innerHTML = relays().map((r) => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join("");
  if (cur) sel.value = cur;
  const nf = $("#network-form");
  if (document.activeElement?.form !== nf) nf.acme_email.value = view.network.acme_email || "";
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
    const roles = [n.kind, n.relay ? "relay" : "", n.webui ? "web ui" : ""].filter(Boolean).map((r) => `<span class="chip">${r}</span>`).join(" ");
    return `<tr>
      <td><b>${esc(n.name)}</b>${localChip(it)}</td><td>${roles}</td><td class="mono">${esc(n.mesh_ip)}</td>
      <td>${state}</td><td>${path}</td><td>${hs}</td>
      <td class="mono">${esc(p?.endpoint || "")}</td>
      <td>${p ? bytes(p.rx_bytes) + " / " + bytes(p.tx_bytes) : ""}</td>
      <td class="mono">${esc((n.routes || []).join(", "))}${(n.routes || []).length ? ({ restricted: ' <span class="chip local">restricted</span>', firewall: ' <span class="chip local">pfSense rules</span>' }[n.lan_policy] || ' <span class="chip">open</span>') : ""}</td>
      <td class="actions">${n.kind === "server" || n.kind === "static" ? `<button class="small" data-edit-node="${esc(n.id)}">Edit</button>` : ""}
        ${n.id !== view.self_id ? `<button class="small danger" data-del="node:${esc(n.id)}">Remove</button>` : ""}</td></tr>`;
  });
  $("#nodes").innerHTML = `<tr><th>Name</th><th>Role</th><th>Mesh IP</th><th>State</th><th>Path</th><th>Handshake</th><th>Endpoint</th><th>Rx / Tx</th><th>Shared subnets / policy</th><th></th></tr>` + rows.join("");
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

function renderACLs() {
  const rows = (view.acls || []).map((it) => {
    const a = it.value;
    const enforcing = view.nodes.find((n) => n.value.id === a.node)?.value;
    const from = (a.from || []).length ? a.from.map(nodeName).join(", ") : "any device";
    const policy = enforcing?.lan_policy === "restricted" ? ""
      : enforcing?.lan_policy === "firewall" ? ' <span class="chip" title="This node uses its pfSense firewall rules instead">pfSense rules</span>'
      : ' <span class="chip" title="This node\'s LAN policy is open, so the rule has no effect yet">policy open</span>';
    return `<tr><td><b>${esc(a.name)}</b>${localChip(it)}</td><td>${esc(nodeName(a.node))}${policy}</td><td>${esc(from)}</td>
      <td class="mono">${esc(aclTarget(a))}</td><td>${esc(a.proto)}${a.ports ? " " + esc(a.ports) : ""}</td>
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
    <label>Protocol <select name="proto">${["tcp", "udp", "icmp", "any"].map((p) => `<option ${p === a.proto ? "selected" : ""}>${p}</option>`).join("")}</select></label>
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

function openDialog(title, inner, onSubmit) {
  const d = $("#dialog"), f = $("#dialog-form");
  f.innerHTML = `<h2>${esc(title)}</h2>${inner}<p class="error" id="dialog-error"></p>
    <div class="dialog-actions"><button value="cancel" class="ghost" formnovalidate>Cancel</button><button value="ok" id="dialog-ok">Save</button></div>`;
  f.onsubmit = async (e) => {
    if (e.submitter?.value !== "ok") return;
    e.preventDefault();
    try { await onSubmit(new FormData(f), f); d.close(); refresh(); toast("Saved"); }
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
  const relayField = n.kind === "static"
    ? `<label class="full">Connects through relay <select name="via_relay">${nodeOptions(relays(), n.via_relay)}</select></label>`
    : `<label class="full">Endpoints (host:port, one per line — public IP/DNS, LAN IP, router port-forward)
        <textarea name="endpoints" rows="3">${esc((n.endpoints || []).join("\n"))}</textarea></label>
       <label class="full">Shared LAN subnets (one per line) <textarea name="routes" rows="2">${esc((n.routes || []).join("\n"))}</textarea></label>
       <label class="inline full"><input type="checkbox" name="relay" ${n.relay ? "checked" : ""}> Relay (public endpoint reachable from anywhere)</label>
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
      else Object.assign(patch, { endpoints: lines("endpoints"), routes: lines("routes"), relay: fd.get("relay") === "on", lan_policy: fd.get("lan_policy") });
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
  if (t.dataset.editFwd) return forwardDialog(view.forwards.find((x) => x.value.id === t.dataset.editFwd));
  if (t.dataset.editRoute) return routeDialog(view.routes.find((x) => x.value.id === t.dataset.editRoute));
  if (t.dataset.editNode) return nodeDialog(view.nodes.find((x) => x.value.id === t.dataset.editNode));
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
    if (!confirm(`Delete this ${{ httproute: "route", acl: "rule" }[kind] || kind}? This applies to all nodes.`)) return;
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
