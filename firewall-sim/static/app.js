// app.js - talks to the Flask API and draws the page. No frameworks.
const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(url, method = "GET", body) {
  const opts = { method, headers: {} };
  if (body instanceof FormData) opts.body = body;
  else if (body) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(url, opts);
  const data = res.status === 204 ? null : await res.json();
  if (!res.ok) throw new Error(data?.error || "Something went wrong.");
  return data;
}
function say(msg, isError = false) {
  const el = $("#status"); el.textContent = msg; el.className = isError ? "error" : "";
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { say(e.message, true); } };

// ---------- rules ----------
async function loadRules() {
  const { rules } = await api("/api/rules");
  $("#rules-table tbody").innerHTML = rules.map((r, i) => `
    <tr data-id="${r.id}">
      <td class="num">${r.id}</td>
      <td><span class="pill ${r.action}">${r.action}</span></td>
      <td class="ip">${esc(r.src_ip)}</td><td class="ip">${esc(r.dst_ip)}</td>
      <td>${esc(r.protocol)}</td><td class="num">${r.dst_port ?? "any"}</td>
      <td>${esc(r.description)}${r.shadowed_by ? `<span class="warn">Never reached: rule #${r.shadowed_by} already covers it</span>` : ""}</td>
      <td>
        <button class="icon" data-move="up" data-id="${r.id}" aria-label="Move rule ${r.id} up" ${i === 0 ? "disabled" : ""}>&#9650;</button>
        <button class="icon" data-move="down" data-id="${r.id}" aria-label="Move rule ${r.id} down" ${i === rules.length - 1 ? "disabled" : ""}>&#9660;</button>
        <button class="icon" data-del="${r.id}" aria-label="Delete rule ${r.id}">Delete</button>
      </td>
    </tr>`).join("");
}
$("#rules-table").addEventListener("click", guard(async (e) => {
  const b = e.target.closest("button"); if (!b) return;
  if (b.dataset.move) await api(`/api/rules/${b.dataset.id}/move`, "POST", { direction: b.dataset.move });
  else if (b.dataset.del) await api(`/api/rules/${b.dataset.del}`, "DELETE");
  else return;
  clearWalk(); await loadRules();
}));
$("#rule-form").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  await api("/api/rules", "POST", Object.fromEntries(new FormData(e.target)));
  e.target.reset(); say("Rule added at the bottom of the chain."); await loadRules();
}));

// ---------- the "walk": highlight which rules were checked ----------
function clearWalk() { document.querySelectorAll("#rules-table tr").forEach((tr) => (tr.className = "")); }
function showWalk(res) {
  clearWalk();
  const rows = [...document.querySelectorAll("#rules-table tbody tr")];
  rows.forEach((tr) => {
    const id = Number(tr.dataset.id);
    tr.className = id === res.rule_id ? `hit-${res.verdict}` : res.checked.includes(id) ? "checked" : "skipped";
  });
  if (res.rule_id === null) $("#row-default").className = `hit-${res.verdict}`;
}

// ---------- packet tester ----------
$("#sim-form").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  const res = await api("/api/simulate", "POST", Object.fromEntries(new FormData(e.target)));
  const box = $("#result"); box.hidden = false; box.className = `result ${res.verdict}`;
  $("#verdict").textContent = res.verdict; $("#reason").textContent = res.reason;
  $("#scapy").textContent = `Scapy packet: ${res.scapy}`;
  showWalk(res); say(""); await refresh();
}));
document.querySelector(".presets").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  const [src, dst, proto, dport] = b.dataset.p.split(",");
  const f = $("#sim-form").elements;
  f.src.value = src; f.dst.value = dst; f.proto.value = proto; f.dport.value = dport;
  $("#sim-form").requestSubmit();
});

// ---------- traffic log ----------
async function loadLogs() {
  const q = new URLSearchParams({ verdict: $("#f-verdict").value, proto: $("#f-proto").value, src: $("#f-src").value });
  const { logs } = await api("/api/logs?" + q);
  $("#log-table tbody").innerHTML = logs.length ? logs.map((l) => `
    <tr><td class="num">${l.time}</td><td class="ip">${esc(l.src)}</td><td class="ip">${esc(l.dst)}</td>
    <td>${esc(l.proto)}</td><td class="num">${l.dport ?? "-"}</td>
    <td><span class="pill ${l.verdict}">${l.verdict}</span></td><td>${esc(l.reason)}</td></tr>`).join("")
    : `<tr><td colspan="7" class="empty">No traffic yet. Send a packet or generate some.</td></tr>`;
}
["#f-verdict", "#f-proto"].forEach((s) => $(s).addEventListener("change", guard(loadLogs)));
$("#f-src").addEventListener("input", guard(loadLogs));
$("#gen-btn").addEventListener("click", guard(async () => {
  const r = await api("/api/generate", "POST", { count: 20 });
  say(`Generated ${r.count} packets: ${r.blocked} blocked, ${r.count - r.blocked} allowed.`); await refresh();
}));
$("#pcap").addEventListener("change", guard(async (e) => {
  const fd = new FormData(); fd.append("file", e.target.files[0]);
  const r = await api("/api/pcap", "POST", fd); e.target.value = "";
  say(`Replayed ${r.count} packets from the file: ${r.blocked} blocked.`); await refresh();
}));
$("#clear-btn").addEventListener("click", guard(async () => { await api("/api/logs/clear", "POST"); await refresh(); }));

// ---------- stats ----------
function bars(title, pairs, labeler = String) {
  const max = Math.max(1, ...pairs.map((p) => p[1]));
  return `<div><h3>${title}</h3>${pairs.length ? pairs.map(([k, n]) => `
    <div class="bar-row"><span class="${typeof k === "string" ? "mono" : ""}">${esc(labeler(k))}</span>
    <div class="bar"><i style="width:${(n / max) * 100}%"></i></div><span>${n}</span></div>`).join("") : '<p class="empty">Nothing yet.</p>'}</div>`;
}
async function loadStats() {
  const s = await api("/api/stats");
  const pct = s.total ? (s.allowed / s.total) * 100 : 0;
  $("#stats").innerHTML = `
    <div class="bar-row" style="grid-template-columns:1fr"><span>${s.allowed} allowed, ${s.blocked} blocked out of ${s.total}</span></div>
    <div class="bar split" aria-hidden="true"><i class="a" style="width:${pct}%"></i><i class="b" style="width:${s.total ? 100 - pct : 0}%"></i></div>
    <div class="stats-grid">
      ${bars("Top blocked ports", s.top_blocked_ports, (p) => "port " + p)}
      ${bars("Top blocked sources", s.top_blocked_sources)}
      ${bars("Decisions per rule", s.rule_hits, (id) => (id === null ? "default policy" : "rule #" + id))}
    </div>`;
}

const refresh = () => Promise.all([loadLogs(), loadStats()]);
guard(async () => { await loadRules(); await refresh(); })();
