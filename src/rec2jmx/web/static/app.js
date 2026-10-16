"use strict";
// rec2jmx web UI. All recording-derived text is rendered with textContent (never innerHTML).
//
// State model: `base` holds every planned request in the user's order (flows can be renamed,
// reordered, merged by drag-and-drop). Excluded hosts/requests are kept as sets so exclusion is
// reversible; the plan sent to the server is base minus exclusions (see effectivePlan()).

const DEFAULT_SECRET_POLICY = "include"; // recorded values are written into the .jmx unless changed
const EXCLUDABLE_CATEGORIES = new Set(["analytics", "monitoring", "feature flags", "chat/support"]);
const BANNER_CODES = new Set(["har-sanitized", "event-stream", "no-requests", "heuristic-grouping"]);

const state = {
  file: null, settings: null, report: null, base: null, index: {}, hostInfo: {},
  excludedHosts: new Set(), excludedReqs: new Set(), collapsed: new Set(), dismissed: new Set(), selectedFlows: new Set(),
  flowKeys: [], selected: null, detail: null, mainTab: "request", detailTab: "headers", reveal: false,
  seq: 0, detailSeq: 0, nextKey: 1, busy: false,
};
const $ = (id) => document.getElementById(id);

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, "");
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
  return node;
}
const pill = (text, color) => el("span", { class: "pill" + (color ? " " + color : "") }, text);
const methodBadge = (m) => el("span", { class: "method m-" + (["GET", "POST", "PUT", "PATCH", "DELETE"].includes(m) ? m : "other") }, m);

function toast(msg, kind) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (kind ? " " + kind : "");
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, kind === "error" ? 8000 : 3500);
}

async function api(path, body) {
  const resp = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await resp.json().catch(() => ({ error: "Unexpected server response." }));
  if (!resp.ok) throw new Error(data.error || `Request failed (${resp.status})`);
  return data;
}

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

// ------------------------------------------------------------------ plan model

function effectivePlan() {
  const b = state.base;
  const flows = [], keys = [];
  for (const f of b.flows) {
    const requests = f.requests.filter((id) => included(id));
    if (requests.length) { flows.push({ name: f.name, requests }); keys.push(f.key); }
  }
  return {
    plan: {
      rec2jmxPlan: 1, recordingFingerprint: b.fingerprint, testPlanName: b.testPlanName,
      secretPolicy: b.secretPolicy, thinkTime: "none", parameterizeHosts: b.parameterizeHosts,
      acceptSuggestions: b.acceptSuggestions, flows,
    },
    keys,
  };
}
const included = (id) => !state.excludedReqs.has(id) && !state.excludedHosts.has(state.index[id].host);
const payload = (plan, extra) => Object.assign({ filename: state.file.name, content: state.file.content, settings: state.settings, plan }, extra || {});

function findReq(id) {
  for (const f of state.base.flows) {
    const i = f.requests.indexOf(id);
    if (i >= 0) return { flow: f, i };
  }
  return null;
}
function cleanupFlows() { state.base.flows = state.base.flows.filter((f) => f.requests.length); }
function newKey() { return "f" + state.nextKey++; }

// ------------------------------------------------------------------ import

function readSettings() {
  return { groupBy: $("groupBy").value, gapSeconds: Number($("gapSeconds").value || 5), includeStatic: $("includeStatic").checked };
}

async function importFile(file) {
  $("import-error").textContent = "";
  const buf = await file.arrayBuffer();
  const pending = { name: file.name, content: toBase64(buf) };
  const settings = readSettings();
  try {
    setBusy(true);
    const report = await api("/api/inspect", { filename: pending.name, content: pending.content, settings });
    state.file = pending;
    state.settings = settings;
    const p = report.plan;
    state.base = {
      fingerprint: p.recordingFingerprint, testPlanName: p.testPlanName, secretPolicy: DEFAULT_SECRET_POLICY,
      parameterizeHosts: p.parameterizeHosts, acceptSuggestions: [],
      flows: p.flows.map((f) => ({ key: newKey(), name: f.name, requests: f.requests.slice() })),
    };
    state.index = Object.fromEntries(report.requestIndex.map((r) => [r.id, r]));
    state.hostInfo = report.hostInfo;
    state.excludedHosts = new Set(); state.excludedReqs = new Set(); state.collapsed = new Set(); state.dismissed = new Set();
    state.selectedFlows = new Set();
    state.selected = null; state.detail = null; state.mainTab = "request";
    state.report = report;
    state.flowKeys = state.base.flows.map((f) => f.key);
    showWorkspace();
    const first = state.base.flows[0] && state.base.flows[0].requests[0];
    if (first) selectRequest(first);
  } catch (e) {
    $("import-error").textContent = e.message;
  } finally {
    setBusy(false);
  }
}

function showWorkspace() {
  $("importView").hidden = true;
  $("workspace").hidden = false;
  for (const id of ["fileInfo", "newImport", "openGenerate"]) $(id).hidden = false;
  setStep("review");
  render();
}

function showImport() {
  $("workspace").hidden = true;
  $("importView").hidden = false;
  for (const id of ["fileInfo", "newImport", "openGenerate", "warnBadge"]) $(id).hidden = true;
  $("banners").replaceChildren();
  $("file").value = "";
  setStep("import");
}

function setStep(step) {
  const order = ["import", "review", "generate"];
  order.forEach((s, i) => {
    const li = $("st-" + s);
    li.className = s === step ? "active" : i < order.indexOf(step) ? "done" : "";
  });
}

function setBusy(b) {
  state.busy = b;
  $("busy").hidden = !b;
  $("openGenerate").disabled = b;
  $("generate").disabled = b;
}

// ------------------------------------------------------------------ refresh

let refreshTimer = null;
function scheduleRefresh() {
  clearTimeout(refreshTimer);
  render(); // optimistic: tree order/exclusions update immediately
  refreshTimer = setTimeout(refresh, 120);
}

async function refresh() {
  const { plan, keys } = effectivePlan();
  if (!plan.flows.length) {
    state.report = Object.assign({}, state.report, { flows: [] });
    state.flowKeys = [];
    render();
    toast("All requests are excluded. Include at least one request to generate a plan.", "error");
    return;
  }
  const seq = ++state.seq;
  setBusy(true);
  try {
    const report = await api("/api/inspect", payload(plan));
    if (seq !== state.seq) return;
    state.report = report;
    state.flowKeys = keys;
    render();
    if (state.selected) loadDetail(state.selected);
  } catch (e) {
    if (seq === state.seq) toast(e.message, "error");
  } finally {
    if (seq === state.seq) setBusy(false);
  }
}

// ------------------------------------------------------------------ rendering

function names() {
  const tx = {}, samplers = {};
  (state.report.flows || []).forEach((f, i) => {
    tx[state.flowKeys[i]] = f.txName;
    for (const r of f.requests) samplers[r.id] = r.samplerName;
  });
  return { tx, samplers };
}

function render() {
  if (!state.base) return;
  renderTopbar();
  renderBanners();
  renderHosts();
  renderTree();
  renderFiltered();
  renderTabs();
}

function renderTopbar() {
  const s = state.report.source;
  $("fileInfo").replaceChildren(pill(s.formatLabel.split(" (")[0], "blue"), el("span", { class: "name", title: s.name }, s.name));
  const warns = state.report.issues.filter((i) => i.severity !== "info").length;
  const badge = $("warnBadge");
  badge.hidden = !warns;
  badge.textContent = `⚠ ${warns} warning${warns === 1 ? "" : "s"}`;
}

function renderBanners() {
  const items = state.report.issues.filter((i) => BANNER_CODES.has(i.code) && !state.dismissed.has(i.code + (i.requestId || "")));
  const seen = new Set();
  $("banners").replaceChildren(...items.filter((i) => !seen.has(i.code) && seen.add(i.code)).map((i) => {
    const key = i.code + (i.requestId || "");
    const same = items.filter((x) => x.code === i.code).length;
    return el("div", { class: "banner " + (i.code === "har-sanitized" || i.severity === "error" ? "error" : "warning") },
      el("span", { class: "icon" }, i.code === "har-sanitized" ? "✖" : "⚠"),
      el("div", { class: "text" }, i.message, same > 1 ? ` (${same} requests)` : "",
        i.requestId ? el("span", {}, " ", el("button", { class: "link-btn", type: "button", onclick: () => selectRequest(i.requestId) }, "Show request")) : null),
      el("button", { class: "ghost icon", type: "button", "aria-label": "Dismiss", onclick: () => { items.filter((x) => x.code === i.code).forEach((x) => state.dismissed.add(x.code + (x.requestId || ""))); renderBanners(); } }, "×"));
  }));
}

function plannedIds() { return state.base.flows.flatMap((f) => f.requests); }

function renderHosts() {
  const counts = new Map();
  for (const id of plannedIds()) {
    const h = state.index[id].host;
    counts.set(h, (counts.get(h) || 0) + 1);
  }
  const hosts = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  $("hostChips").replaceChildren(...hosts.map(([h, n]) => {
    const off = state.excludedHosts.has(h);
    const cat = state.hostInfo[h];
    return el("button", { type: "button", class: "chip " + (off ? "off" : "on"), title: off ? "Excluded - click to include" : "Included - click to exclude",
      "aria-pressed": off ? "false" : "true", "data-host": h,
      onclick: () => { off ? state.excludedHosts.delete(h) : state.excludedHosts.add(h); scheduleRefresh(); } },
      el("span", {}, off ? "○" : "●"), el("span", { class: "host" }, h), el("span", { class: "n" }, String(n)),
      cat ? el("span", { class: "cat" }, cat) : null);
  }));
  const thirdParty = hosts.map(([h]) => h).filter((h) => EXCLUDABLE_CATEGORIES.has(state.hostInfo[h]) && !state.excludedHosts.has(h));
  const btn = $("excludeThirdParty");
  btn.hidden = !thirdParty.length;
  btn.textContent = `Exclude third-party (${thirdParty.length})`;
  btn.onclick = () => { thirdParty.forEach((h) => state.excludedHosts.add(h)); scheduleRefresh(); };
}

function renderTree() {
  // While a transaction name is being typed, a rebuild would drop the input: update names in place instead.
  if (state.editing && document.querySelector("#tree .flow-name input")) { patchTreeNames(); return; }
  state.editing = null;
  const { tx, samplers } = names();
  const tree = $("tree");
  tree.replaceChildren(...state.base.flows.map((f, fi) => {
    const collapsed = state.collapsed.has(f.key);
    const activeCount = f.requests.filter(included).length;
    const nameSpan = el("span", { class: "flow-name", title: "Double-click to rename" }, f.name);
    nameSpan.addEventListener("dblclick", (e) => { e.stopPropagation(); renameFlow(f, nameSpan, head); });
    const pick = el("input", { type: "checkbox", class: "flow-select", checked: state.selectedFlows.has(f.key),
      title: "Select this flow for merging", "aria-label": `Select flow ${f.name} for merging` });
    pick.addEventListener("click", (e) => e.stopPropagation());
    pick.addEventListener("change", () => { pick.checked ? state.selectedFlows.add(f.key) : state.selectedFlows.delete(f.key); renderTree(); });
    const head = el("div", { class: "flow-head" + (state.selectedFlows.has(f.key) ? " picked" : ""), draggable: "true" },
      el("span", { class: "grip", "aria-hidden": "true" }, "⋮⋮"),
      pick,
      el("button", { class: "caret", type: "button", "aria-label": collapsed ? "Expand" : "Collapse",
        onclick: (e) => { e.stopPropagation(); collapsed ? state.collapsed.delete(f.key) : state.collapsed.add(f.key); renderTree(); } },
        collapsed ? "▸" : "▾"),
      el("button", { class: "tx tx-btn", type: "button", title: "Rename this transaction",
        onclick: (e) => { e.stopPropagation(); renameFlow(f, nameSpan, head); } }, tx[f.key] || "(not in plan)"),
      nameSpan,
      el("button", { class: "rename-btn", type: "button", title: "Rename this transaction", "aria-label": `Rename transaction ${f.name}`,
        onclick: (e) => { e.stopPropagation(); renameFlow(f, nameSpan, head); } }, "✎ Rename"),
      el("span", { class: "muted small" }, activeCount === f.requests.length ? String(f.requests.length) : `${activeCount}/${f.requests.length}`),
      el("button", { class: "mini", type: "button", title: "Move up", disabled: fi === 0, onclick: (e) => { e.stopPropagation(); moveFlowBy(fi, -1); } }, "↑"),
      el("button", { class: "mini", type: "button", title: "Move down", disabled: fi === state.base.flows.length - 1, onclick: (e) => { e.stopPropagation(); moveFlowBy(fi, 1); } }, "↓"),
      fi < state.base.flows.length - 1 ? el("button", { class: "merge-next", type: "button",
        title: "Merge this flow with the next one (one Transaction Controller)",
        onclick: (e) => { e.stopPropagation(); mergeFlows([f.key, state.base.flows[fi + 1].key]); } }, "Merge ↓") : null);
    wireFlowDnD(head, f);
    const reqs = el("div", { class: "reqs" }, f.requests.map((id) => reqRow(id, samplers[id], f)));
    return el("div", { class: "flow" + (collapsed ? " collapsed" : ""), "data-key": f.key }, head, reqs);
  }));
  renderMergeActions();
}

function patchTreeNames() {
  const { tx, samplers } = names();
  document.querySelectorAll("#tree .flow").forEach((node) => {
    const t = node.querySelector(".tx-btn");
    if (t && tx[node.dataset.key]) t.textContent = tx[node.dataset.key];
  });
  document.querySelectorAll("#tree .req").forEach((row) => {
    const n = row.querySelector(".sname");
    if (n && samplers[row.dataset.id] && included(row.dataset.id)) n.textContent = samplers[row.dataset.id];
  });
}

function renderMergeActions() {
  const live = new Set(state.base.flows.map((f) => f.key));
  for (const k of [...state.selectedFlows]) if (!live.has(k)) state.selectedFlows.delete(k);
  const n = state.selectedFlows.size;
  const btn = $("mergeSelected");
  btn.hidden = n < 2;
  btn.textContent = `Merge selected (${n})`;
  $("clearSelection").hidden = n === 0;
}

// Merge flows into the first one (in current order): its name and position are kept, and the
// requests of all merged flows follow in their current order. The result is one Transaction Controller.
function mergeFlows(keys) {
  const chosen = state.base.flows.filter((f) => keys.includes(f.key));
  if (chosen.length < 2) return;
  const target = chosen[0];
  target.requests = chosen.flatMap((f) => f.requests);
  const drop = new Set(chosen.slice(1).map((f) => f.key));
  state.base.flows = state.base.flows.filter((f) => !drop.has(f.key));
  state.selectedFlows.clear();
  state.collapsed.delete(target.key);
  toast(`Merged ${chosen.length} flows into one transaction (${target.requests.length} requests). Type a name for it, or press Enter to keep "${target.name}".`);
  scheduleRefresh(); // re-renders the tree synchronously, then refreshes names from the server
  const node = document.querySelector(`#tree .flow[data-key="${target.key}"]`);
  if (node) renameFlow(target, node.querySelector(".flow-name"), node.querySelector(".flow-head"));
}

function reqRow(id, samplerName, flow) {
  const info = state.index[id];
  const on = included(id);
  const hostOff = state.excludedHosts.has(info.host);
  const cb = el("input", { type: "checkbox", checked: on, disabled: hostOff, title: hostOff ? "Host is excluded" : on ? "Exclude this request" : "Include this request",
    "aria-label": "Include request" });
  cb.addEventListener("click", (e) => e.stopPropagation());
  cb.addEventListener("change", () => { cb.checked ? state.excludedReqs.delete(id) : state.excludedReqs.add(id); scheduleRefresh(); });
  const row = el("div", { class: "req" + (on ? "" : " excluded") + (state.selected === id ? " selected" : ""), tabindex: "0",
    draggable: flow ? "true" : "false", "data-id": id, onclick: () => selectRequest(id),
    onkeydown: (e) => { if (e.key === "Enter") selectRequest(id); } },
    cb, methodBadge(info.method),
    el("span", { class: "sname", title: samplerName || id }, on && samplerName ? samplerName : id),
    info.issues.length ? el("span", { class: "flag", title: info.issues.join(", ") }, "⚠") : el("span"),
    el("span", { class: "url", title: info.url }, info.url));
  wireReqDnD(row, id);
  return row;
}

function renderFiltered() {
  const inPlan = new Set(plannedIds());
  const rest = Object.values(state.index).filter((r) => !inPlan.has(r.id));
  const box = $("filtered");
  box.hidden = !rest.length;
  $("filteredSummary").textContent = `Removed by import filter (${rest.length}) - drag into a flow to include`;
  $("filteredList").replaceChildren(...rest.map((r) => {
    const row = el("div", { class: "req excluded", draggable: "true", "data-id": r.id, onclick: () => selectRequest(r.id) },
      methodBadge(r.method), el("span", { class: "url", title: r.url }, r.url),
      el("span", { class: "muted small" }, r.excludedReason || "not in plan"));
    wireReqDnD(row, r.id);
    return row;
  }));
}

// Same rules as rec2jmx.naming.sanitize_flow_name (the server's name is what gets generated).
function sanitizeFlowName(name) {
  const cleaned = (name || "").replace(/[^A-Za-z0-9]+/g, "_").replace(/_+/g, "_").replace(/^_|_$/g, "");
  return cleaned.slice(0, 40).replace(/_+$/, "") || "Flow";
}

function renameFlow(f, span, head) {
  if (span.querySelector("input")) return;
  const prefix = (names().tx[f.key] || "TX_??_").match(/^TX_\d+_/);
  const input = el("input", { type: "text", value: f.name, maxlength: "80", "aria-label": "Transaction name" });
  const preview = el("div", { class: "rename-preview" });
  const showPreview = () => { preview.textContent = "Will be named " + (prefix ? prefix[0] : "TX_nn_") + sanitizeFlowName(input.value); };
  showPreview();
  span.replaceChildren(input, preview);
  state.editing = f.key;
  if (head) {
    head.setAttribute("draggable", "false"); // allow selecting text inside the input
    head.classList.add("editing");
  }
  input.focus();
  input.select();
  let finished = false;
  const done = (save) => {
    if (finished) return;
    finished = true;
    state.editing = null;
    if (save && input.value.trim()) f.name = input.value.trim();
    scheduleRefresh();
  };
  input.addEventListener("input", showPreview);
  input.addEventListener("keydown", (e) => {
    e.stopPropagation();
    if (e.key === "Enter") done(true);
    if (e.key === "Escape") done(false);
  });
  input.addEventListener("blur", () => done(true));
  input.addEventListener("click", (e) => e.stopPropagation());
  input.addEventListener("dblclick", (e) => e.stopPropagation());
}

function moveFlowBy(i, delta) {
  const f = state.base.flows;
  [f[i], f[i + delta]] = [f[i + delta], f[i]];
  scheduleRefresh();
}

// ------------------------------------------------------------------ drag and drop

let drag = null;
function clearDropMarks() {
  document.querySelectorAll(".drop-before,.drop-after,.drop-into").forEach((n) => n.classList.remove("drop-before", "drop-after", "drop-into"));
}
function half(e, node) {
  const r = node.getBoundingClientRect();
  return e.clientY > r.top + r.height / 2 ? "after" : "before";
}

function wireFlowDnD(head, f) {
  head.addEventListener("dragstart", (e) => {
    drag = { type: "flow", key: f.key };
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", "flow:" + f.key);
    head.parentElement.classList.add("dragging");
  });
  head.addEventListener("dragend", () => { drag = null; clearDropMarks(); renderTree(); });
  head.addEventListener("dragover", (e) => {
    if (!drag) return;
    e.preventDefault();
    clearDropMarks();
    if (drag.type === "flow") head.parentElement.classList.add(half(e, head.parentElement) === "after" ? "drop-after" : "drop-before");
    else head.parentElement.classList.add("drop-into");
  });
  head.addEventListener("drop", (e) => {
    e.preventDefault();
    if (!drag) return;
    if (drag.type === "flow") moveFlow(drag.key, f.key, half(e, head.parentElement) === "after");
    else moveReq(drag.id, { flowKey: f.key });
    drag = null;
    clearDropMarks();
  });
}

function wireReqDnD(row, id) {
  row.addEventListener("dragstart", (e) => {
    e.stopPropagation();
    drag = { type: "req", id };
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", "req:" + id);
    row.classList.add("dragging");
  });
  row.addEventListener("dragend", () => { drag = null; clearDropMarks(); renderTree(); });
  if (row.getAttribute("draggable") !== "true" || !findReq(id)) return; // filtered rows are sources only
  row.addEventListener("dragover", (e) => {
    if (!drag || drag.type !== "req" || drag.id === id) return;
    e.preventDefault();
    e.stopPropagation();
    clearDropMarks();
    row.classList.add(half(e, row) === "after" ? "drop-after" : "drop-before");
  });
  row.addEventListener("drop", (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!drag || drag.type !== "req" || drag.id === id) return;
    moveReq(drag.id, { beforeId: id, after: half(e, row) === "after" });
    drag = null;
    clearDropMarks();
  });
}

function moveFlow(key, targetKey, after) {
  if (key === targetKey) return;
  const flows = state.base.flows;
  const f = flows.splice(flows.findIndex((x) => x.key === key), 1)[0];
  const t = flows.findIndex((x) => x.key === targetKey);
  flows.splice(after ? t + 1 : t, 0, f);
  scheduleRefresh();
}

function moveReq(id, target) {
  const from = findReq(id);
  if (from) from.flow.requests.splice(from.i, 1);
  state.excludedReqs.delete(id);
  if (target.newFlow) {
    state.base.flows.push({ key: newKey(), name: "New flow", requests: [id] });
  } else if (target.flowKey) {
    const f = state.base.flows.find((x) => x.key === target.flowKey);
    f.requests.push(id);
  } else {
    const to = findReq(target.beforeId);
    to.flow.requests.splice(target.after ? to.i + 1 : to.i, 0, id);
  }
  cleanupFlows();
  scheduleRefresh();
}

function wireNewFlowZone() {
  const z = $("newFlowZone");
  z.addEventListener("dragover", (e) => { if (drag && drag.type === "req") { e.preventDefault(); clearDropMarks(); z.classList.add("drop-into"); } });
  z.addEventListener("dragleave", () => z.classList.remove("drop-into"));
  z.addEventListener("drop", (e) => { e.preventDefault(); if (drag && drag.type === "req") moveReq(drag.id, { newFlow: true }); drag = null; clearDropMarks(); });
}

// ------------------------------------------------------------------ right side

function renderTabs() {
  const r = state.report;
  $("cnt-correlations").textContent = r.suggestions.length ? String(r.suggestions.length) : "";
  $("cnt-secrets").textContent = r.secrets.length ? String(r.secrets.length) : "";
  const warn = r.issues.filter((i) => i.severity !== "info").length;
  $("cnt-messages").textContent = warn ? String(warn) : "";
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === state.mainTab));
  for (const name of ["request", "correlations", "secrets", "messages"]) $("panel-" + name).hidden = name !== state.mainTab;
  if (state.mainTab === "request") renderDetail();
  if (state.mainTab === "correlations") renderCorrelations();
  if (state.mainTab === "secrets") renderSecrets();
  if (state.mainTab === "messages") renderMessages();
}

function openTab(name) { state.mainTab = name; renderTabs(); }

function selectRequest(id) {
  state.selected = id;
  state.mainTab = "request";
  document.querySelectorAll(".req.selected").forEach((n) => n.classList.remove("selected"));
  document.querySelectorAll(`.req[data-id="${id}"]`).forEach((n) => n.classList.add("selected"));
  renderTabs();
  loadDetail(id);
}

async function loadDetail(id) {
  const seq = ++state.detailSeq;
  const { plan } = effectivePlan();
  if (!plan.flows.length) return;
  try {
    const detail = await api("/api/request", payload(plan, { requestId: id }));
    if (seq !== state.detailSeq) return;
    state.detail = detail;
    if (state.mainTab === "request") renderDetail();
  } catch (e) {
    if (seq === state.detailSeq) toast(e.message, "error");
  }
}

function shown(value, sensitive) {
  if (value == null) return el("span", { class: "masked" }, "-");
  if (sensitive && !state.reveal) return el("span", { class: "masked" }, `•••••• (${value.length} chars)`);
  return value === "" ? el("span", { class: "masked" }, "(empty)") : value;
}

const STATUS_PILL = { kept: ["kept", "green"], changed: ["changed", "blue"], mapped: ["mapped", "purple"],
  added: ["added", "purple"], dropped: ["not sent", "red"], excluded: ["excluded", ""] };

function renderDetail() {
  const panel = $("panel-request");
  const d = state.detail;
  if (!state.selected) {
    panel.replaceChildren(el("div", { class: "empty" }, el("div", {}, el("p", {}, "Select a request on the left"),
      el("p", { class: "small" }, "to see its headers, query, body and response, and what goes into the JMX."))));
    return;
  }
  if (!d || d.id !== state.selected) { panel.replaceChildren(el("p", { class: "muted" }, "Loading request…")); return; }
  const info = state.index[d.id];
  const tabs = [["headers", `Headers (${d.headers.length})`], ["query", `Query (${d.query.length})`], ["body", "Body"],
    ["response", "Response"], ["sampler", "Sampler"]];
  const reveal = el("input", { type: "checkbox", class: "toggle", checked: state.reveal, "aria-label": "Show sensitive values" });
  reveal.addEventListener("change", () => { state.reveal = reveal.checked; renderDetail(); });
  panel.replaceChildren(
    el("div", { class: "detail-head" }, methodBadge(d.method), el("h2", {}, d.samplerName || "Not in plan"),
      included(d.id) ? null : pill(info.excludedReason || "excluded", "yellow"),
      d.response && d.response.status != null ? pill(`recorded ${d.response.status}`, d.response.status < 400 ? "green" : "red") : null),
    el("div", { class: "detail-url" }, state.reveal ? d.url : info.url),
    el("div", { class: "muted small" }, `${d.id} · ${d.source}`),
    ...d.issues.map((i) => el("div", { class: "callout " + i.severity }, i.message)),
    d.suggestions.length ? el("div", { class: "callout" }, "Dynamic values in this request:",
      el("span", { class: "sugg-links" }, ...d.suggestions.map((sid) => el("button", { class: "req-link", type: "button",
        onclick: () => openTab("correlations") }, sid))),
      el("span", { class: "muted small" }, "review them in the Correlations tab")) : null,
    el("div", { class: "subbar" },
      ...tabs.map(([k, label]) => el("button", { class: "subtab" + (state.detailTab === k ? " active" : ""), type: "button",
        onclick: () => { state.detailTab = k; renderDetail(); } }, label)),
      el("label", { class: "switch" }, reveal, "Show sensitive values")),
    detailBody(d));
}

function detailBody(d) {
  if (state.detailTab === "headers") {
    if (!d.headers.length) return el("p", { class: "muted" }, "This request has no recorded headers.");
    return el("table", {}, el("thead", {}, el("tr", {}, ["Status", "Header", "Value in JMX", "Note"].map((h) => el("th", {}, h)))),
      el("tbody", {}, d.headers.map((h) => {
        const [label, color] = STATUS_PILL[h.status] || [h.status, ""];
        const value = h.jmx != null ? h.jmx : h.recorded;
        return el("tr", { class: h.status === "mapped" || h.status === "dropped" ? "dim" : "" },
          el("td", {}, pill(label, color)), el("td", { class: "mono" }, h.name),
          el("td", { class: "mono" }, shown(value, h.sensitive),
            h.status === "changed" ? el("span", { class: "was" }, "recorded: ", shown(h.recorded, h.sensitive)) : null),
          el("td", { class: "muted small" }, h.note || ""));
      })));
  }
  if (state.detailTab === "query") {
    if (!d.query.length) return el("p", { class: "muted" }, "No query parameters.");
    return el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "Name"), el("th", {}, "Value (decoded)"))),
      el("tbody", {}, d.query.map((q) => el("tr", {}, el("td", { class: "mono" }, q.name), el("td", { class: "mono" }, shown(q.value, q.sensitive))))));
  }
  if (state.detailTab === "body") {
    const b = d.body;
    if (b.kind === "none") return el("p", { class: "muted" }, "No request body.");
    const meta = el("p", { class: "muted small" }, `${b.kind} body`, b.contentType ? ` · ${b.contentType}` : "", b.truncated ? " · truncated for display" : "");
    if (b.kind === "raw") return el("div", {}, meta, el("pre", { class: "code" }, hiddenText(prettyJson(b.text), b.sensitive, "Body")));
    return el("div", {}, meta, el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "Field"), el("th", {}, "Value"))),
      el("tbody", {}, b.fields.map((f) => el("tr", {}, el("td", { class: "mono" }, f.name),
        el("td", { class: "mono" }, f.fileName ? `file: ${f.fileName} (read from \${FILE_DIR} at run time)` : shown(f.value, f.sensitive)))))));
  }
  if (state.detailTab === "response") {
    const r = d.response;
    if (!r) return el("p", { class: "muted" }, "This format has no recorded response.");
    return el("div", {}, el("p", { class: "muted small" }, "Recorded response (used only to suggest correlations; never written to the JMX)."),
      el("dl", { class: "kv" }, el("dt", {}, "Status"), el("dd", {}, String(r.status ?? "-")), el("dt", {}, "Content-Type"), el("dd", {}, r.contentType || "-"),
        ...r.headers.flatMap((h) => [el("dt", {}, h.name), el("dd", {}, shown(h.value, /cookie|token|auth/i.test(h.name)))])),
      r.body ? el("pre", { class: "code" }, hiddenText(prettyJson(r.body), r.sensitive, "Response body")) : null);
  }
  const s = d.sampler;
  if (!s) return el("p", { class: "muted" }, "This request is not in the plan, so it has no sampler.");
  return el("dl", { class: "kv" }, ...Object.entries(s).flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v || "(default)")]));
}

function prettyJson(text) {
  const t = (text || "").trim();
  if (t.length < 200000 && (t.startsWith("{") || t.startsWith("["))) {
    try { return JSON.stringify(JSON.parse(t), null, 2); } catch (e) { /* not JSON */ }
  }
  return text;
}
function hiddenText(text, sensitive, what) {
  if (!sensitive || state.reveal) return text;
  return `${what} contains detected secret values and is hidden (${text.length} characters). Turn on "Show sensitive values" to view it.`;
}

function renderCorrelations() {
  const r = state.report;
  const accepted = new Set(state.base.acceptSuggestions);
  const panel = $("panel-correlations");
  if (!r.suggestions.length) {
    panel.replaceChildren(el("div", { class: "empty" }, el("p", {}, "No dynamic values detected.",
      el("br"), el("span", { class: "small" }, "Correlations need recorded responses (HAR or rec2jmx JSON)."))));
    return;
  }
  panel.replaceChildren(
    el("p", { class: "muted" }, "Values that a later request sends after receiving them in an earlier response. Turn one on to add an extractor and use the variable instead of the recorded value."),
    el("table", {}, el("thead", {}, el("tr", {}, ["Apply", "Id", "Kind", "Confidence", "What", "Used in"].map((h) => el("th", {}, h)))),
      el("tbody", {}, r.suggestions.map((x) => {
        const t = el("input", { type: "checkbox", class: "toggle", checked: accepted.has(x.id), disabled: !x.acceptable, "aria-label": "Apply " + x.id });
        t.addEventListener("change", () => {
          const set = new Set(state.base.acceptSuggestions);
          t.checked ? set.add(x.id) : set.delete(x.id);
          state.base.acceptSuggestions = [...set];
          scheduleRefresh();
        });
        let what = x.reason;
        if (x.kind === "correlation") {
          const how = x.extractor.type === "json" ? `JSON ${x.extractor.expression}` : `boundary in response ${x.extractor.scope}`;
          what = el("span", {}, el("code", {}, "${" + x.variable + "}"), " from ", reqLink(x.sourceRequestId), ` (${how})`);
        } else if (x.kind === "timestamp") what = el("span", {}, "replace with ", el("code", {}, x.replacement));
        return el("tr", {}, el("td", {}, t), el("td", {}, x.id), el("td", {}, x.kind),
          el("td", {}, pill(x.confidence, { high: "green", medium: "yellow", low: "red" }[x.confidence])), el("td", {}, what),
          el("td", {}, ...x.usages.slice(0, 6).map((u) => el("div", {}, reqLink(u.requestId), " ", el("span", { class: "muted small" }, u.location))),
            x.usages.length > 6 ? el("div", { class: "muted small" }, `+${x.usages.length - 6} more`) : null));
      }))));
}

function reqLink(id) { return el("button", { class: "req-link", type: "button", onclick: () => selectRequest(id) }, id); }

function renderSecrets() {
  const r = state.report;
  const include = state.base.secretPolicy === "include";
  const panel = $("panel-secrets");
  panel.replaceChildren(
    el("div", { class: "callout " + (include ? "warning" : "") }, include
      ? `Secret handling: Include recorded values. These ${r.secrets.length} value(s) are written into the .jmx as recorded; treat the file as confidential. Change this in Generate.`
      : "Secret handling: Parameterize. Each value becomes a ${SECRET_*} property; pass it with -J when running JMeter."),
    r.secrets.length
      ? el("table", {}, el("thead", {}, el("tr", {}, ["Id", "Request", "Location", "Why", include ? "Written as" : "Variable"].map((h) => el("th", {}, h)))),
        el("tbody", {}, r.secrets.map((s) => el("tr", {}, el("td", {}, s.id), el("td", {}, s.requestId ? reqLink(s.requestId) : "variables"),
          el("td", {}, s.location), el("td", { class: "muted" }, s.reason),
          el("td", { class: "mono" }, include ? "recorded value" : "${" + s.variable + "}")))))
      : el("p", { class: "muted" }, "No likely secrets detected."));
}

function renderMessages() {
  const issues = state.report.issues.filter((i) => i.code !== "detected-format");
  const groups = [["error", "Errors"], ["warning", "Warnings"], ["info", "Information"]];
  const panel = $("panel-messages");
  panel.replaceChildren(
    ...groups.map(([sev, title]) => {
      const list = issues.filter((i) => i.severity === sev);
      if (!list.length) return null;
      return el("div", { class: "msg-group" }, el("h3", {}, `${title} (${list.length})`),
        ...list.map((i) => el("div", { class: "msg" }, el("span", { class: "sev" }, pill(sev, { error: "red", warning: "yellow", info: "blue" }[sev])),
          el("div", {}, i.message, i.requestId ? el("div", {}, reqLink(i.requestId)) : null))));
    }),
    el("div", { class: "msg-group" }, el("h3", {}, "Limitations"),
      el("ul", { class: "muted" }, state.report.limitations.map((l) => el("li", {}, l)))));
}

// ------------------------------------------------------------------ generate

function openGenerate() {
  const b = state.base;
  $("planName").value = b.testPlanName;
  $("secretPolicy").value = b.secretPolicy;
  $("paramHosts").checked = b.parameterizeHosts;
  $("generate-error").textContent = "";
  $("genForm").hidden = false;
  $("genResult").hidden = true;
  showSecretNote();
  $("generateDialog").hidden = false;
  setStep("generate");
  $("planName").focus();
}

function closeGenerate() {
  $("generateDialog").hidden = true;
  setStep("review");
}

function readConfig() {
  const b = state.base;
  b.testPlanName = $("planName").value.trim() || "Recorded scenario";
  b.parameterizeHosts = $("paramHosts").checked;
  b.secretPolicy = $("secretPolicy").value;
  showSecretNote();
}

function showSecretNote() {
  const n = state.report ? state.report.secrets.length : 0;
  $("secretNote").textContent = state.base.secretPolicy === "include"
    ? (n ? `${n} detected secret value(s) will be written into the .jmx as recorded.` : "Recorded values are written into the .jmx as recorded.")
    : "Detected secrets become ${SECRET_*} properties; pass them with -J at run time.";
}

async function generate() {
  readConfig();
  $("generate-error").textContent = "";
  const { plan } = effectivePlan();
  if (!plan.flows.length) { $("generate-error").textContent = "All requests are excluded."; return; }
  try {
    setBusy(true);
    $("generate").textContent = "Generating…";
    const out = await api("/api/generate", payload(plan, { validateJmeter: $("validateJmeter").checked, validateMock: $("validateMock").checked }));
    showResult(out);
    render();
  } catch (e) {
    $("generate-error").textContent = e.message;
  } finally {
    setBusy(false);
    $("generate").textContent = "Generate .jmx";
  }
}

function showResult(out) {
  const g = out.report.generation, s = out.summary;
  const url = URL.createObjectURL(new Blob([out.jmx], { type: "application/xml" }));
  let view = "summary";
  const body = el("div");
  const tabSummary = el("button", { class: "subtab active", type: "button" }, "Summary");
  const tabXml = el("button", { class: "subtab", type: "button" }, "XML preview");
  const ranJmeter = g.validations.some((v) => v.name.startsWith("jmeter"));

  const summary = () => el("div", {},
    el("div", { class: "cards" },
      ...[["Transactions", s.transactions.length], ["Samplers", s.samplers], ["Headers", s.headers], ["Extractors", s.extractors],
        ["Variables", s.variables.length], ["Size", (s.bytes / 1024).toFixed(1) + " KB"]].map(([k, v]) => el("div", { class: "card" }, el("div", { class: "v" }, String(v)), el("div", { class: "k" }, k)))),
    el("h3", {}, "Validation"),
    el("ul", { class: "validations" }, g.validations.map((v) => el("li", {}, pill(v.passed ? "passed" : "failed", v.passed ? "green" : "red"), " ", el("strong", {}, v.name), " - ", v.details.join(" | ")))),
    ranJmeter ? null : el("p", { class: "muted small" }, "JMeter-based validation was not run."),
    ...(g.notes || []).map((n) => el("div", { class: "callout warning" }, n)),
    g.appliedSuggestions.length ? el("p", {}, "Applied suggestions: " + g.appliedSuggestions.join(", ")) : null,
    el("h3", {}, "Transactions"),
    el("table", {}, el("tbody", {}, s.transactions.map((t) => el("tr", {}, el("td", { class: "mono" }, t.name), el("td", { class: "mono muted" }, t.samplers.join(", ")))))),
    s.variables.length ? el("p", { class: "small" }, "Variables: ", el("span", { class: "mono" }, s.variables.join(", "))) : null,
    g.issues.length ? el("h3", {}, "Generation messages") : null,
    ...g.issues.map((i) => el("div", { class: "msg" }, pill(i.severity, { error: "red", warning: "yellow", info: "blue" }[i.severity]), el("div", {}, i.message))),
    el("p", { class: "muted small" }, `Run: jmeter -n -t ${out.filename} -l results.jtl -Jthreads=10 -Jrampup=10 -Jloops=1`));

  const renderResult = () => {
    tabSummary.className = "subtab" + (view === "summary" ? " active" : "");
    tabXml.className = "subtab" + (view === "xml" ? " active" : "");
    body.replaceChildren(view === "summary" ? summary() : highlightXml(out.jmx));
  };
  tabSummary.addEventListener("click", () => { view = "summary"; renderResult(); });
  tabXml.addEventListener("click", () => { view = "xml"; renderResult(); });
  const copy = el("button", { type: "button", onclick: async () => {
    try { await navigator.clipboard.writeText(out.jmx); toast("XML copied to the clipboard"); } catch (e) { toast("Copy failed: " + e.message, "error"); }
  } }, "Copy XML");
  $("genResult").replaceChildren(
    el("div", { class: "subbar" }, tabSummary, tabXml, el("span", { class: "spacer" }),
      el("button", { type: "button", onclick: () => { $("genForm").hidden = false; $("genResult").hidden = true; } }, "← Options"),
      copy, el("a", { href: url, download: out.filename, class: "download" }, el("button", { class: "primary", type: "button", tabindex: "-1" }, `Download ${out.filename}`))),
    body);
  renderResult();
  $("genForm").hidden = true;
  $("genResult").hidden = false;
}

function highlightXml(xml) {
  const pre = el("pre", { class: "code xml" });
  if (xml.length > 400000) { pre.textContent = xml; return pre; }
  const frag = document.createDocumentFragment();
  const span = (cls, text) => { const s = document.createElement("span"); s.className = cls; s.textContent = text; frag.appendChild(s); };
  const re = /<[^>]*>|[^<]+/g;
  let m;
  while ((m = re.exec(xml))) {
    const tok = m[0];
    if (tok[0] !== "<") { frag.appendChild(document.createTextNode(tok)); continue; }
    if (tok.startsWith("<?")) { span("x-decl", tok); continue; }
    const t = /^(<\/?)([^\s/>]+)([\s\S]*?)(\/?>)$/.exec(tok);
    if (!t) { frag.appendChild(document.createTextNode(tok)); continue; }
    span("x-punct", t[1]); span("x-tag", t[2]);
    const attrRe = /(\s+)([^\s=]+)(=)("[^"]*")/g;
    let a, last = 0;
    while ((a = attrRe.exec(t[3]))) {
      if (a.index > last) frag.appendChild(document.createTextNode(t[3].slice(last, a.index)));
      frag.appendChild(document.createTextNode(a[1])); span("x-attr", a[2]); span("x-punct", a[3]); span("x-val", a[4]);
      last = a.index + a[0].length;
    }
    if (last < t[3].length) frag.appendChild(document.createTextNode(t[3].slice(last)));
    span("x-punct", t[4]);
  }
  pre.appendChild(frag);
  return pre;
}

// ------------------------------------------------------------------ wiring

$("file").addEventListener("change", (e) => e.target.files[0] && importFile(e.target.files[0]));
const drop = $("drop");
drop.addEventListener("click", (e) => { if (e.target.tagName !== "INPUT" && e.target.tagName !== "LABEL") $("file").click(); });
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("file").click(); } });
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); if (e.dataTransfer.files[0]) importFile(e.dataTransfer.files[0]); });
$("newImport").addEventListener("click", showImport);
$("openGenerate").addEventListener("click", openGenerate);
$("closeGenerate").addEventListener("click", closeGenerate);
$("generateDialog").addEventListener("click", (e) => { if (e.target === $("generateDialog")) closeGenerate(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("generateDialog").hidden) closeGenerate(); });
$("generate").addEventListener("click", generate);
$("warnBadge").addEventListener("click", () => openTab("messages"));
$("mergeSelected").addEventListener("click", () => mergeFlows([...state.selectedFlows]));
$("clearSelection").addEventListener("click", () => { state.selectedFlows.clear(); renderTree(); });
for (const id of ["planName", "paramHosts", "secretPolicy"]) $(id).addEventListener("change", readConfig);
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => openTab(t.dataset.tab)));
wireNewFlowZone();
