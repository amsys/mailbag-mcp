// app.js: the setup page. Text goes in through textContent only.
// The token comes once from the URL fragment, then lives in sessionStorage.
"use strict";
const $ = (id) => document.getElementById(id);
const SECTIONS = ["provider", "access", "gmail", "outlook", "form", "result", "clients", "daemon", "checks"];
let presets = {}, preset = null, lastForm = null, job = null;

function token() {
  const m = /(?:^|[#&])k=([^&]+)/.exec(location.hash);
  if (m) {
    sessionStorage.setItem("mailbag-token", decodeURIComponent(m[1]));
    history.replaceState(null, "", location.pathname + location.search);
  }
  return sessionStorage.getItem("mailbag-token") || "";
}
const TOKEN = token();

async function api(method, path, body) {
  const opt = { method, headers: { "X-Mailbag-Setup": TOKEN } };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || "HTTP " + r.status);
  return data;
}

function el(tag, text, attrs) {
  const e = document.createElement(tag);
  if (text) e.textContent = text;
  Object.assign(e, attrs || {});
  return e;
}
function show(...ids) { SECTIONS.forEach((s) => { $(s).hidden = !ids.includes(s); }); }
function fail(id, err) { const e = $(id); e.textContent = err.message; e.className = "msg err"; }
function openTab(url) { window.open(url, "_blank", "noopener,noreferrer"); }
// The answer to the file-store question of the CLI (review M3).
function fileStore() { return $("f-filestore").checked; }

async function refresh() {
  try {
    const s = await api("GET", "/api/state");
    const f = $("facts");
    f.replaceChildren();
    [["mailbag-mcp", s.cli_path + " " + s.cli_version], ["setup", s.setup_version],
     ["accounts.toml", s.config_path || ""], ["secret store", s.secrets || "none"]].forEach(([k, v]) => {
      f.append(el("dt", k), el("dd", v));
    });
    const ul = $("accounts");
    ul.replaceChildren();
    (s.accounts || []).forEach((a) => ul.append(el("li", a.alias + " (" + a.provider + ", " + a.access + ") " + a.email)));
    const b = $("banner");
    b.hidden = s.versions_match !== false;
    if (!b.hidden) b.textContent = "The setup version and the mailbag-mcp version differ.";
  } catch (e) { $("banner").hidden = false; $("banner").textContent = e.message; }
}

async function poll(id, sink, after) {
  after = after || 0;
  for (;;) {
    const j = await api("GET", "/api/jobs/" + id + "?after=" + after);
    if (j.lines && j.lines.length) sink(j.lines);
    after = j.next;
    if (j.done) return j.exit;
    await new Promise((r) => setTimeout(r, 500));
  }
}
function linkify(box, line) {
  const m = /https?:\/\/\S+/.exec(line);
  if (!m) { box.append(document.createTextNode(line + "\n")); return; }
  box.append(document.createTextNode(line.slice(0, m.index)));
  box.append(el("a", m[0], { href: m[0], target: "_blank", rel: "noopener noreferrer" }));
  box.append(document.createTextNode(line.slice(m.index + m[0].length) + "\n"));
}
async function runJob(method, path, body, box) {
  box.replaceChildren();
  const r = await api(method, path, body);
  job = r.job;
  const code = await poll(r.job, (ls) => ls.forEach((l) => linkify(box, l)));
  job = null;
  return code;
}

function pickProvider() {
  const c = $("cards");
  c.replaceChildren();
  Object.entries(presets).forEach(([key, p]) => {
    c.append(el("button", p.label, { onclick: () => choose(key) }));
  });
  show("provider");
}

function choose(key) {
  preset = presets[key];
  const pw = preset.provider === "imap" || preset.provider === "jmap";
  $("pw-fields").hidden = !pw;
  $("f-imap").parentElement.hidden = preset.provider !== "imap";
  $("f-smtp").parentElement.hidden = preset.provider !== "imap";
  $("f-jmap").parentElement.hidden = preset.provider !== "jmap";
  $("f-imap").value = preset.imap || "";
  $("f-smtp").value = preset.smtp || "";
  $("f-jmap").value = preset.session_url || "";
  const h = $("f-help");
  h.replaceChildren();
  if (preset.help_url) h.append(el("a", preset.help, { href: preset.help_url, target: "_blank", rel: "noopener noreferrer" }));
  const need = preset.provider === "gmail" ? "gmail" : preset.provider === "outlook" ? "outlook" : null;
  show("access", "form", ...(need ? [need] : []));
  if (need === "gmail") gmailSteps();
  if (need === "outlook") outlookSteps();
}

const GSTEPS = [
  ["Make a project", "https://console.cloud.google.com/projectcreate"],
  ["Turn on the Gmail API", "https://console.cloud.google.com/apis/library/gmail.googleapis.com"],
  ["Add yourself as a test user", "https://console.cloud.google.com/auth/audience"],
  ["Make a Desktop app client, then Download JSON", "https://console.cloud.google.com/auth/clients/create"],
];
function gmailSteps() {
  const ol = $("gmail-steps");
  ol.replaceChildren();
  GSTEPS.forEach(([t, u]) => {
    const li = el("li", t + " ");
    li.append(el("button", "Open", { onclick: () => openTab(u) }));
    const done = el("input", "", { type: "checkbox" });
    const lab = el("label", " Done");
    lab.prepend(done);
    li.append(lab);
    ol.append(li);
  });
  ol.append(el("li", "Drop the downloaded file below."));
}
async function sendGoogle(file) {
  $("gmsg").className = "msg";
  try {
    const text = await file.text();
    const doc = JSON.parse(text);
    if (doc.web) throw new Error("This is a Web client. Make a Desktop app client.");
    if (!doc.installed) throw new Error("The file has no installed key. Make a Desktop app client.");
    await api("POST", "/api/oauth/google?use_file_store=" + fileStore(), doc);
    $("gmsg").textContent = "Google client saved.";
  } catch (e) { fail("gmsg", e); }
}

const OVALS = ["Platform: Mobile and desktop applications", "Redirect URI: http://localhost",
  "Allow public client flows: on", "Permission: IMAP.AccessAsUser.All", "Permission: SMTP.Send",
  "Permission: offline_access"];
function outlookSteps() {
  const ul = $("outlook-vals");
  ul.replaceChildren();
  OVALS.forEach((v) => {
    const li = el("li", v + " ");
    li.append(el("button", "Copy", { onclick: () => navigator.clipboard.writeText(v.split(": ").slice(1).join(": ")) }));
    ul.append(li);
  });
}
async function sendMS() {
  const id = $("msid").value.trim();
  $("mmsg").className = "msg";
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    fail("mmsg", new Error("The client id must be a GUID."));
    return;
  }
  try { await api("POST", "/api/oauth/microsoft", { client_id: id, use_file_store: fileStore() }); $("mmsg").textContent = "Client id saved."; }
  catch (e) { fail("mmsg", e); }
}

async function signIn() {
  const pw = preset.provider === "imap" || preset.provider === "jmap";
  const body = {
    alias: $("f-alias").value.trim(), provider: preset.provider, email: $("f-email").value.trim(),
    access: document.querySelector("input[name=access]:checked").value,
    use_file_store: fileStore(),
  };
  if (pw) {
    body.username = $("f-user").value.trim();
    body.imap = $("f-imap").value.trim();
    body.smtp = $("f-smtp").value.trim();
    body.session_url = $("f-jmap").value.trim();
    body.secret = $("f-secret").value;
    if (preset.provider === "jmap") body.bearer = true;
  }
  lastForm = Object.assign({}, body, { secret: undefined });
  $("f-secret").value = "";
  show("result");
  $("b-retry").hidden = true;
  $("b-cancel").hidden = false;
  $("signin-note").hidden = pw;
  try {
    const code = await runJob("POST", "/api/accounts", body, $("out"));
    $("out").append(document.createTextNode(code === 0 ? "\nDone.\n" : "\nFailed (exit " + code + ").\n"));
    $("b-retry").hidden = code === 0;
  } catch (e) { $("out").textContent = e.message; $("b-retry").hidden = false; }
  $("b-cancel").hidden = true;
  $("signin-note").hidden = true;
  refresh();
}
function retry() {
  show("access", "form");
  $("signin-note").hidden = true;
  if (!lastForm) return;
  $("f-alias").value = lastForm.alias;
  $("f-email").value = lastForm.email;
  $("f-user").value = lastForm.username || "";
  $("f-imap").value = lastForm.imap || "";
  $("f-smtp").value = lastForm.smtp || "";
  $("f-jmap").value = lastForm.session_url || "";
  const radio = document.querySelector("input[name=access][value=" + lastForm.access + "]");
  if (radio) radio.checked = true;
}

function clientBox(c) {
  const d = el("div");
  d.append(el("h3", c.label), el("p", c.path));
  if (!c.present) { d.append(el("p", "Not found on this computer.")); return d; }
  if (c.error) { d.append(el("p", c.error, { className: "msg err" })); return d; }
  if (c.same) d.append(el("p", "mailbag is set with this mailbag-mcp. No change is necessary."));
  if (c.running) d.append(el("p", "The Claude app runs. Quit it, then apply.", { className: "msg err" }));
  const pair = el("div", "", { className: "pair" });
  pair.append(el("pre", c.before || "(no entry)"), el("pre", c.after));
  d.append(pair, el("button", "Apply", { onclick: async () => {
    if (c.current && !c.same && !confirm("mailbag is set to another path. Replace it?\n\n" + c.current)) return;
    try {
      const ap = await api("POST", "/api/clients/" + encodeURIComponent(c.name), {});
      d.append(el("p", !ap.changed ? "No change was necessary." : ap.backup ? "Applied. Backup: " + ap.backup : "Applied."));
    } catch (e) { d.append(el("p", e.message, { className: "msg err" })); }
  } }));
  return d;
}
async function loadClients() {
  show("clients");
  const box = $("client-list");
  box.replaceChildren();
  try { (await api("GET", "/api/clients")).forEach((c) => box.append(clientBox(c))); }
  catch (e) { box.append(el("p", e.message, { className: "msg err" })); }
}

async function main() {
  try { presets = await (await fetch("/presets.json")).json(); } catch (e) { presets = {}; }
  $("b-add").onclick = pickProvider;
  $("b-clients").onclick = loadClients;
  $("b-checks").onclick = async () => { show("checks"); try { await runJob("POST", "/api/doctor", {}, $("doctor")); } catch (e) { $("doctor").textContent = e.message; } };
  $("b-msid").onclick = sendMS;
  $("b-signin").onclick = signIn;
  $("b-retry").onclick = retry;
  $("b-cancel").onclick = () => { if (job) api("POST", "/api/jobs/" + job + "/cancel", {}).catch(() => {}); };
  $("b-daemon").onclick = () => show("daemon");
  $("b-service").onclick = async () => { show("daemon", "result"); try { await runJob("POST", "/api/service", {}, $("out")); } catch (e) { $("out").textContent = e.message; } };
  $("gfile").onchange = (e) => e.target.files[0] && sendGoogle(e.target.files[0]);
  const drop = $("drop");
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add("over"); };
  drop.ondragleave = () => drop.classList.remove("over");
  drop.ondrop = (e) => { e.preventDefault(); drop.classList.remove("over"); if (e.dataTransfer.files[0]) sendGoogle(e.dataTransfer.files[0]); };
  $("b-finish").onclick = async () => { try { await api("POST", "/api/finish", {}); } catch (e) { /* the server stops */ } $("closed").hidden = false; };
  refresh();
}
main();
