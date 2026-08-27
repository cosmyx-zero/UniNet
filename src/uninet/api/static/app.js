"use strict";
const $ = (s) => document.querySelector(s);
const SVGNS = "http://www.w3.org/2000/svg";

async function j(url, opts) {
  const r = await fetch(url, opts);
  return r.json();
}

async function loadStats() {
  const s = await j("/api/stats");
  $("#stats").textContent =
    `flows ${s.flows} · windows ${s.windows} · graph ${s.graph.nodes}n/${s.graph.edges}e · ` +
    `alerts ${s.alerts} (` +
    Object.entries(s.by_severity).map(([k, v]) => `${v} ${k}`).join(", ") + ")";
}

async function loadAlerts() {
  const rows = await j("/api/alerts");
  const tb = $("#alerts tbody");
  tb.innerHTML = "";
  rows.forEach((a) => {
    const tr = document.createElement("tr");
    tr.dataset.id = a.alert_id;
    tr.dataset.host = a.src_host;
    const sc = a.scores || {};
    tr.innerHTML = `
      <td class="sev ${a.severity}">${a.severity.toUpperCase()}</td>
      <td>${a.threat_type}</td>
      <td>${a.src_host}</td>
      <td>${a.confidence.toFixed(2)}<div class="bar"><span style="width:${Math.round(a.confidence * 100)}%"></span></div></td>
      <td>${(sc.rule ?? 0).toFixed(2)} / ${(sc.anomaly ?? 0).toFixed(2)} / ${(sc.graph ?? 0).toFixed(2)}</td>
      <td>${a.evidence && a.evidence[0] ? a.evidence[0].detail : "-"}</td>`;
    tr.addEventListener("click", () => selectAlert(tr));
    tb.appendChild(tr);
  });
  const first = tb.querySelector("tr");
  if (first) selectAlert(first);
}

async function selectAlert(tr) {
  document.querySelectorAll("#alerts tbody tr").forEach((r) => r.classList.remove("active"));
  tr.classList.add("active");
  const { id, host } = tr.dataset;
  $("#detail-host").textContent = `— ${host}`;

  const ex = await j(`/api/explain/${id}`);
  $("#evidence").innerHTML = (ex.evidence || [])
    .map((e) => `<li><div class="kind">${e.kind} · ${e.name} · ${(e.score ?? 0).toFixed(2)}</div>${e.detail}</li>`)
    .join("");

  drawGraph(await j(`/api/graph?host=${encodeURIComponent(host)}`), host);
}

function drawGraph(view, host) {
  const svg = $("#graph");
  svg.innerHTML = "";
  const W = 480, H = 360, cx = W / 2, cy = H / 2;
  const color = { host: "#6ea8ff", burst: "#ffd24a", domain: "#4ad991", alert: "#ff5470" };

  const nodes = view.nodes.slice(0, 60);
  const idset = new Set(nodes.map((n) => n.id));
  const pos = {};
  const rings = { host: [], burst: [], domain: [], alert: [] };
  nodes.forEach((n) => (rings[n.type] || rings.burst).push(n));

  const place = (arr, radius) =>
    arr.forEach((n, i) => {
      const a = (i / Math.max(arr.length, 1)) * Math.PI * 2;
      pos[n.id] = [cx + radius * Math.cos(a), cy + radius * Math.sin(a)];
    });
  rings.host.forEach((n) => (pos[n.id] = [cx, cy]));
  place(rings.burst, 95);
  place(rings.domain, 160);
  place(rings.alert, 55);

  view.edges.forEach((e) => {
    if (!idset.has(e.src) || !idset.has(e.dst)) return;
    const [x1, y1] = pos[e.src], [x2, y2] = pos[e.dst];
    const ln = document.createElementNS(SVGNS, "line");
    ln.setAttribute("x1", x1); ln.setAttribute("y1", y1);
    ln.setAttribute("x2", x2); ln.setAttribute("y2", y2);
    ln.setAttribute("stroke", e.rel === "periodic" ? "#ff9f45"
      : e.rel === "direction_change" ? "#ff5470" : "#3a4668");
    ln.setAttribute("stroke-width", e.rel === "emits" ? 0.6 : 1.4);
    svg.appendChild(ln);
  });

  nodes.forEach((n) => {
    const [x, y] = pos[n.id] || [cx, cy];
    const c = document.createElementNS(SVGNS, "circle");
    c.setAttribute("cx", x); c.setAttribute("cy", y);
    c.setAttribute("r", n.type === "host" ? 8 : n.type === "burst" ? 5 : 4);
    c.setAttribute("fill", color[n.type] || "#999");
    const title = document.createElementNS(SVGNS, "title");
    title.textContent = n.id + (n.attrs && n.attrs.byte_count ? ` · ${n.attrs.byte_count | 0} B` : "");
    c.appendChild(title);
    svg.appendChild(c);
  });
}

async function tick() {
  await Promise.all([loadStats(), loadAlerts()]);
}
tick();
setInterval(loadStats, 5000);
