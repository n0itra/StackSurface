const tools = [
  {key:"subfinder", icon:"⌁", desc:"Passive subdomain enumeration (auto-uses github/securitytrails/virustotal/censys/netlas/c99/urlscan/shodan keys if configured on the server)", tag:"Passive"},
  {key:"findomain", icon:"◎", desc:"Fast subdomain enumeration", tag:"Discovery"},
  {key:"assetfinder", icon:"◇", desc:"Find subdomains from multiple sources", tag:"Passive"},
  {key:"crt.sh", icon:"◉", desc:"Certificate transparency search", tag:"OSINT", url:"https://crt.sh/"},
  {key:"waymore", icon:"🕘", desc:"Historical URLs (Wayback, OTX, CommonCrawl)", tag:"Archive", url:"https://web.archive.org/"},
  {key:"anew", icon:"≋", desc:"Merge & deduplicate results", tag:"Cleanup"},
  {key:"dnsx", icon:"◆", desc:"Resolves each subdomain to an IP (unresolved ones are stored, not probed)", tag:"DNS"},
  {key:"cdncheck", icon:"◆", desc:"Flags CDN/WAF-fronted IPs before port lookup", tag:"DNS"},
  {key:"shodan", icon:"•", desc:"Open-port lookup per resolved IP (requires SHODAN_API_KEY)", tag:"Network", url:"https://www.shodan.io/", apiKey:true},
  {key:"permutations", icon:"⟲", desc:"Generates & resolves likely subdomain guesses (high DNS volume)", tag:"Active"},
  {key:"httpx", icon:"↗", desc:"Alive host & technology detection", tag:"HTTP"},
  {key:"katana", icon:"⌁", desc:"Web crawling & URL discovery", tag:"Crawler"},
  {key:"trufflehog", icon:"◍", desc:"Regex/entropy-based secret scanning", tag:"Secrets"},
  {key:"jsluice", icon:"◍", desc:"AST-aware JS secret & endpoint analysis", tag:"Secrets"},
  {key:"arjun", icon:"⟐", desc:"Parameter discovery", tag:"Params"},
  {key:"sqlmap", icon:"▣", desc:"Disabled — exploit/payload testing is not automated on this platform", tag:"Disabled", disabled:true},
  {key:"nuclei", icon:"⬢", desc:"Vulnerability scanning", tag:"Scanner"},
  {key:"feroxbuster", icon:"◫", desc:"Directory & file fuzzing", tag:"Fuzzing"}
];

const stepMap = [
  ["subfinder","Subdomain Enumeration"],
  ["waymore","Historical URL Discovery (waymore)"],
  ["anew","Merge & Deduplicate"],
  ["permutations","Permutation Generation & Resolution"],
  ["dnsx","DNS Resolution (dnsx)"],
  ["cdncheck","CDN/WAF Detection (cdncheck)"],
  ["shodan","Open-Port Lookup (Shodan)"],
  ["httpx","Alive Host Detection (httpx)"],
  ["katana","URL Discovery (katana)"],
  ["trufflehog","Secret Discovery (trufflehog)"],
  ["jsluice","JS Secret Analysis (jsluice)"],
  ["arjun","Parameter Discovery (arjun)"],
  ["nuclei","Vulnerability Scanning (nuclei)"],
  ["feroxbuster","Directory Fuzzing (feroxbuster)"]
];

function buildDatasets(scan) {
  const subdomains = scan.subdomains || [];
  const unresolved = new Set(scan.unresolved || []);
  const alive = scan.alive || [];
  const vulnerabilities = scan.vulnerabilities || [];

  const aliveByHost = {};
  alive.forEach(h => { if (h && h.host) aliveByHost[h.host] = h; });

  return {
    subdomains: {
      title: "Subdomains",
      subtitle: `Total: ${subdomains.length} subdomains — ${unresolved.size} with no IP (stored only, not probed)`,
      search: "Search subdomains...",
      columns: ["#", "Subdomain", "Status", "Technology"],
      rows: subdomains.map((s, i) => {
        const live = aliveByHost[s];
        let status = "-";
        if (unresolved.has(s)) status = "No IP";
        else if (live) status = String(live["status-code"] ?? live.status_code ?? "-");
        else status = "No response";
        return [
          String(i + 1), s, status,
          live && live.tech ? live.tech.join(", ") : "-",
        ];
      }),
      total: subdomains.length,
    },
    alive: {
      title: "Alive Hosts",
      subtitle: `${alive.length} responsive hosts discovered`,
      search: "Search hosts...",
      columns: ["#", "Host", "Status", "Title", "Technology"],
      rows: alive.map((h, i) => [
        String(i + 1),
        h.url || h.host || "-",
        String(h["status-code"] ?? h.status_code ?? "-"),
        h.title || "-",
        (h.tech || []).join(", ") || "-",
      ]),
      total: alive.length,
    },
    endpoints: {
      title: "Endpoints",
      subtitle: scan.endpoints && scan.endpoints.length
        ? `${scan.endpoints.length} endpoints discovered (katana / arjun)`
        : "No endpoints yet — select katana and/or arjun for this scan",
      search: "Search endpoints...",
      columns: ["#", "Endpoint", "Method", "Status"],
      rows: (scan.endpoints || []).map((e, i) => [
        String(i + 1), e.url || "-", e.method || "GET", String(e.status ?? "-"),
      ]),
      total: (scan.endpoints || []).length,
    },
    secrets: {
      title: "Secrets",
      subtitle: scan.secrets && scan.secrets.length
        ? `${scan.secrets.length} potential secrets found in discovered JS files`
        : "No findings — select trufflehog and/or jsluice (requires katana for JS discovery)",
      search: "Search secret locations...",
      columns: ["#", "Type", "Location", "Severity"],
      rows: (scan.secrets || []).map((s, i) => [
        String(i + 1), s.type || "-", s.location || "-",
        (s.severity || "medium").replace(/^\w/, c => c.toUpperCase()),
      ]),
      total: (scan.secrets || []).length,
    },
    vulnerabilities: {
      title: "Vulnerabilities",
      subtitle: vulnerabilities.length
        ? `${vulnerabilities.length} template matches from nuclei (detection only, not confirmed exploits)`
        : "No nuclei findings (nuclei may not have been selected for this scan)",
      search: "Search vulnerabilities...",
      columns: ["#", "Finding", "Host", "Severity", "Confidence"],
      rows: vulnerabilities.map((v, i) => [
        String(i + 1), v.name || v.template || "-", v.host || "-",
        (v.severity || "info").replace(/^\w/, c => c.toUpperCase()),
        v.confidence || "potential",
      ]),
      total: vulnerabilities.length,
    },
    changes: {
      title: "Changes",
      subtitle: (() => {
        const added = (scan.added_assets || []).length;
        const removed = (scan.removed_assets || []).length;
        if (!added && !removed) return "No changes detected — either the first scan of this project, or nothing's changed since last time";
        return `${added} new, ${removed} removed since last scan`;
      })(),
      search: "Search changes...",
      columns: ["#", "Subdomain", "Change"],
      rows: [
        ...(scan.added_assets || []).map((s, i) => [String(i + 1), s, "Added"]),
        ...(scan.removed_assets || []).map((s, i) => [String(i + 1), s, "Removed"]),
      ],
      total: (scan.added_assets || []).length + (scan.removed_assets || []).length,
    },
    dependencies: {
      title: "Dependencies",
      subtitle: (() => {
        const newCount = (scan.new_js_dependencies || []).length;
        const cveCount = (scan.js_cve_findings || []).length;
        if (!newCount && !cveCount) return "No new JS libraries detected, or no project linked for tracking";
        return `${newCount} new librar${newCount === 1 ? "y" : "ies"}, ${cveCount} with known CVEs`;
      })(),
      search: "Search dependencies...",
      columns: ["#", "Library", "Version", "Script", "CVEs"],
      rows: (scan.js_cve_findings && scan.js_cve_findings.length
        ? scan.js_cve_findings
        : (scan.new_js_dependencies || [])
      ).map((d, i) => [
        String(i + 1), d.library || "-", d.version || "-", d.script || "-",
        (d.cves || []).join(", ") || "-",
      ]),
      total: (scan.new_js_dependencies || []).length,
    },
    directories: {
      title: "Directories",
      subtitle: scan.directories && scan.directories.length
        ? `${scan.directories.length} paths discovered (feroxbuster)`
        : "No results — select feroxbuster for this scan",
      search: "Search directories...",
      columns: ["#", "Path", "Status", "Size"],
      rows: (scan.directories || []).map((d, i) => [
        String(i + 1), d.path || "-", String(d.status ?? "-"), String(d.size ?? "-"),
      ]),
      total: (scan.directories || []).length,
    },
  };
}

let datasets = buildDatasets({});

const toolsList = document.getElementById("toolsList");
const progressList = document.getElementById("progressList");
const consoleEl = document.getElementById("console");
const startBtn = document.getElementById("startBtn");
const domainInput = document.getElementById("domainInput");
const statusDot = document.getElementById("statusDot");
const scanStatus = document.getElementById("scanStatus");
const selectAll = document.getElementById("selectAll");

let currentStep = -1;
let running = false;
let timers = [];

// Improved API wrapper with better error handling and strict headers
function api(url, options = {}) {
  if (!window.__API_KEY__) {
    console.warn("API Key is missing in the frontend! Requests may be rejected by the backend.");
  }
  
  const headers = {
    "x-api-key": window.__API_KEY__ || "",
    ...(options.headers || {})
  };
  
  return fetch(url, { ...options, headers })
    .catch(err => {
      // Catch network errors specifically (like backend down or CORS issues)
      console.error(`Network Error while fetching ${url}:`, err);
      throw err;
    });
}

function renderTools() {
  toolsList.innerHTML = tools.map((tool) => `
    <label class="tool-row${tool.disabled ? " tool-row-disabled" : ""}">
      <input type="checkbox" data-tool="${tool.key}" ${tool.disabled ? "disabled" : "checked"} />
      <span class="tool-icon">${tool.icon}</span>
      <span>
        <span class="tool-name">${
          tool.url
            ? `<a href="${tool.url}" target="_blank" rel="noopener noreferrer" class="tool-link" onclick="event.stopPropagation()">${tool.key}</a>`
            : tool.key
        }</span>
        <span class="tool-desc">${tool.desc}</span>
      </span>
      ${tool.apiKey ? `<span class="tool-tags"><span class="tool-tag key-tag" title="Requires an API key configured on the server">🔑 Key</span><span class="tool-tag">${tool.tag}</span></span>` : `<span class="tool-tag">${tool.tag}</span>`}
    </label>
  `).join("");
}

function renderProgress() {
  progressList.innerHTML = stepMap.map(([key,name], idx) => `
    <div class="progress-item" id="step-${idx}" data-key="${key}">
      <span class="progress-circle"></span>
      <span>
        <span class="progress-name">${name}</span>
        <span class="progress-meta">Waiting...</span>
      </span>
      <span class="progress-pct">—</span>
    </div>
  `).join("");
}

function setProgress(idx,state,meta,pct) {
  const el = document.getElementById(`step-${idx}`);
  if(!el) return;
  el.classList.remove("running","done","skipped");
  el.classList.add(state);
  el.querySelector(".progress-meta").textContent = meta;
  el.querySelector(".progress-pct").textContent = pct ?? "—";
}

function appendLog(text) {
  const stamp = new Date().toLocaleTimeString([], {hour12:false});
  consoleEl.textContent += `[${stamp}] ${text}\n`;
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function selectedToolKeys(){
  return [...document.querySelectorAll(".tool-row input:checked")].map(i => i.dataset.tool);
}

function resetProgress() {
  currentStep = -1;
  renderProgress();
  statusDot.classList.remove("running","done");
  scanStatus.textContent = "Idle";
}

async function runScan()  { 
  if(running) return;
  const domain = domainInput.value.trim() || "example.com";
  const selected = selectedToolKeys();
  const selectedSet = new Set(selected);
  const projectId = document.getElementById("projectSelect").value || null;
  running = true;
  startBtn.disabled = true;
  startBtn.querySelector("span").textContent = "Running...";
  statusDot.classList.add("running");
  scanStatus.textContent = "Running";
  consoleEl.textContent = "";
  appendLog(`Target accepted: ${domain}`);
  appendLog(`Selected tools: ${selected.join(", ") || "none"}`);
  if (projectId) appendLog(`Linked to project — asset history & JS dependency tracking enabled.`);

  resetProgress();
  stepMap.forEach(([key], idx) => {
    setProgress(idx, selectedSet.has(key) ? "running" : "skipped",
                selectedSet.has(key) ? "Queued..." : "Skipped by user",
                selectedSet.has(key) ? "—" : "SKIP");
  });

  let scanId;
  try {
    const res = await api("/api/scans", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({domain, tools: selected, project_id: projectId}),
    });
    
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      appendLog(`Error: ${data.detail || `HTTP ${res.status} - scan could not be started`}`);
      resetRunState();
      return;
    }
    const data = await res.json();
    scanId = data.scan_id;
    appendLog(`Scan queued (${scanId}).`);
  } catch (e) {
    appendLog(`Network error contacting backend. Make sure the server is running.`);
    resetRunState();
    return;
  }

  const startedAt = Date.now();
  const maxWaitMs = 15 * 60 * 1000; 
  let lastProgress = -1;
  let lastLogIndex = 0; 

  while (true) {
    await new Promise(r => setTimeout(r, 1500));
    let scan;
    try {
      const res = await api(`/api/scans/${scanId}`);
      if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
      scan = await res.json();
    } catch (e) {
      appendLog(`Polling error: ${e.message || "Failed to fetch progress"}`);
      continue;
    }

    const liveLogs = scan.live_logs || [];
    if (liveLogs.length > lastLogIndex) {
        for (let i = lastLogIndex; i < liveLogs.length; i++) {
            appendLog(`> ${liveLogs[i]}`); 
        }
        lastLogIndex = liveLogs.length;
    }

    const progress = Number(scan.progress || 0);
    if (progress !== lastProgress) {
      lastProgress = progress;
    }

    if (scan.status === "completed" || scan.status === "failed") {
      stepMap.forEach(([key], idx) => {
        if (!selectedSet.has(key)) return;
        setProgress(idx, "done", scan.status === "failed" ? "Finished with errors" : "Completed", "DONE");
      });
      (scan.errors || []).forEach(e => appendLog(`Note: ${e}`));

      datasets = buildDatasets(scan);
      refreshResultTabs(scan, domain);
      renderTable(document.querySelector(".result-tab.active")?.dataset.tab || "subdomains");

      statusDot.classList.remove("running");
      statusDot.classList.add("done");
      scanStatus.textContent = scan.status === "failed" ? "Failed" : "Completed";
      appendLog(scan.status === "failed" ? "Scan finished with errors." : "Recon pipeline completed successfully.");
      resetRunState();
      if (scan.status !== "failed" || (scan.subdomains || []).length) {
        goTo("results");
      }
      return;
    }

    if (Date.now() - startedAt > maxWaitMs) {
      appendLog("Timed out waiting for scan to finish. It may still be running server-side.");
      resetRunState();
      return;
    }
  }
}

function resetRunState() {
  running = false;
  startBtn.disabled = false;
  startBtn.querySelector("span").textContent = "Start";
}

function goTo(page) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active-page"));
  document.getElementById(page+"Page").classList.add("active-page");
  document.querySelectorAll(".nav-link").forEach(n => n.classList.toggle("active", n.dataset.page === page));
}

function refreshResultTabs(scan, domain) {
  document.querySelectorAll(".result-tab").forEach(tab => {
    const key = tab.dataset.tab;
    const total = (datasets[key] && datasets[key].total) || 0;
    const span = tab.querySelector("span");
    if (span) span.textContent = total.toLocaleString();
  });
  document.getElementById("resultDomain").textContent = domain;
  document.querySelector(".scan-time").textContent =
    "Scan Time: " + new Date().toLocaleString([], {dateStyle:"medium", timeStyle:"short"});
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderTable(tabKey, filter=""){
  const data = datasets[tabKey];
  document.getElementById("tableTitle").textContent = data.title;
  document.getElementById("tableSubtitle").textContent = data.subtitle;
  document.getElementById("tableSearch").placeholder = data.search;

  document.getElementById("tableHead").innerHTML = `<tr>${data.columns.map(c=>`<th>${escapeHtml(c)}</th>`).join("")}</tr>`;
  const rows = data.rows.filter(r => r.join(" ").toLowerCase().includes(filter.toLowerCase()));
  document.getElementById("tableBody").innerHTML = rows.map(row => {
    return `<tr>${row.map((cell,i)=>{
      const safeCell = escapeHtml(cell);
      if(data.columns[i] === "Status"){
        const cls = cell==="200" ? "b200" : cell==="403" ? "b403" : cell==="302" || cell==="301" ? "b302" : "b404";
        return `<td><span class="badge ${cls}">${safeCell}</span></td>`;
      }
      if(data.columns[i] === "Severity"){
        const cls = cell==="Critical" ? "b403" : cell==="High" ? "b302" : "b404";
        return `<td><span class="badge ${cls}">${safeCell}</span></td>`;
      }
      if(cell==="Details") return `<td><button class="details-btn" type="button">Details</button></td>`;
      return `<td>${safeCell}</td>`;
    }).join("")}</tr>`;
  }).join("");
  document.getElementById("rowSummary").textContent = `Showing 1 to ${rows.length} of ${data.total} results`;
  document.getElementById("pagination").innerHTML = [1,2,3,4,5,"…",10].map((n,i)=>
    `<button class="page-btn ${i===0?"active":""}">${n}</button>`).join("");
}

renderTools();
renderProgress();
renderTable("subdomains");
document.getElementById("workspace").classList.add("collapsed");

async function loadProjects() {
  const select = document.getElementById("projectSelect");
  try {
    const res = await api("/api/projects");
    if (!res.ok) return; 
    const projects = await res.json();
    const current = select.value;
    select.innerHTML = '<option value="">No project (one-off scan)</option>' +
      projects.map(p => `<option value="${escapeHtml(p.project_id)}">${escapeHtml(p.name)} — ${escapeHtml(p.domain)}${p.monitoring ? " 🟢" : ""}</option>`).join("");
    select.value = current;
  } catch (e) {
    console.warn("Could not load projects (Backend/Supabase unreachable).");
  }
}

document.getElementById("newProjectBtn").addEventListener("click", () => {
  document.getElementById("newProjectCard").style.display = "grid";
});
document.getElementById("cancelProjectBtn").addEventListener("click", () => {
  document.getElementById("newProjectCard").style.display = "none";
});
document.getElementById("saveProjectBtn").addEventListener("click", async () => {
  const name = document.getElementById("newProjectName").value.trim();
  const domain = document.getElementById("newProjectDomain").value.trim();
  const monitoring = document.getElementById("newProjectMonitor").checked;
  if (!name || !domain) return;
  try {
    const res = await api("/api/projects", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({name, domain, monitoring}),
    });
    
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      alert(data.detail || "Could not create project");
      return;
    }
    const data = await res.json();
    document.getElementById("newProjectCard").style.display = "none";
    document.getElementById("newProjectName").value = "";
    document.getElementById("newProjectDomain").value = "";
    document.getElementById("newProjectMonitor").checked = false;
    await loadProjects();
    document.getElementById("projectSelect").value = data.project_id;
    domainInput.value = data.domain;
  } catch (e) {
    alert("Could not reach the backend to create the project.");
  }
});

loadProjects();

startBtn.addEventListener("click", runScan);

selectAll.addEventListener("change", e => {
  document.querySelectorAll(".tool-row input:not(:disabled)").forEach(i => i.checked = e.target.checked);
});
toolsList.addEventListener("change", e => {
  if(e.target.matches('input[data-tool]')){
    const all = [...document.querySelectorAll(".tool-row input:not(:disabled)")];
    selectAll.checked = all.every(i => i.checked);
  }
});

document.querySelectorAll(".nav-link,[data-page]").forEach(btn => {
  btn.addEventListener("click", () => {
    const page = btn.dataset.page;
    if(page) goTo(page);
  });
});

document.getElementById("configureToggle").addEventListener("click", ()=>{
  const toolsCard = document.getElementById("toolsCard");
  const progressCard = document.getElementById("progressCard");
  const workspace = document.getElementById("workspace");
  const arrow = document.getElementById("configureArrow");
  const label = document.getElementById("configureToggle");
  const nowVisible = !toolsCard.classList.contains("visible");

  toolsCard.classList.toggle("visible", nowVisible);
  progressCard.classList.toggle("visible", nowVisible);
  workspace.classList.toggle("collapsed", !nowVisible);
  arrow.textContent = nowVisible ? "⌃" : "⌄";
  label.lastChild.textContent = nowVisible ? " Hide Tools & Progress" : " Show Tools & Progress";

  if (nowVisible) {
    toolsCard.scrollIntoView({behavior:"smooth",block:"center"});
  }
});

document.getElementById("clearConsole").addEventListener("click", ()=>{
  consoleEl.textContent = "Console cleared.\n";
});

document.getElementById("tableSearch").addEventListener("input", e=>{
  const active = document.querySelector(".result-tab.active").dataset.tab;
  renderTable(active,e.target.value);
});

document.querySelectorAll(".result-tab").forEach(tab => {
  tab.addEventListener("click", ()=>{
    document.querySelectorAll(".result-tab").forEach(t=>t.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tableSearch").value = "";
    renderTable(tab.dataset.tab);
  });
});

document.getElementById("exportBtn").addEventListener("click", ()=>{
  const active = document.querySelector(".result-tab.active").dataset.tab;
  const data = datasets[active];
  const csv = [data.columns.join(","), ...data.rows.map(r=>r.map(v=>`"${String(v).replaceAll('"','""')}"`).join(","))].join("\n");
  const blob = new Blob([csv], {type:"text/csv"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `reconx-${active}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
});

document.getElementById("downloadBtn").addEventListener("click", ()=>{
  const domain = domainInput.value.trim() || "example.com";
  const activeTab = document.querySelector(".result-tab.active")?.dataset.tab || "subdomains";
  const data = datasets[activeTab];
  const reportHtml = `<!doctype html><html><head><meta charset="utf-8"><title>ReconX Report</title><style>body{font-family:Arial,sans-serif;color:#17283a;padding:36px}h1{margin:0 0 8px;font-size:28px}.meta{color:#60758a;margin-bottom:28px}h2{font-size:18px;margin-top:28px}table{width:100%;border-collapse:collapse;margin-top:12px}th,td{border:1px solid #d6e0e8;padding:9px;text-align:left;font-size:11px}th{background:#eef4f8}.footer{margin-top:28px;color:#71869a;font-size:10px}</style></head><body><h1>ReconX Security Report</h1><div class="meta">Automated Recon • ${domain} • ${new Date().toLocaleString()}</div><h2>${data.title}</h2><p>${data.subtitle}</p><table><thead><tr>${data.columns.map(c=>`<th>${c}</th>`).join("")}</tr></thead><tbody>${data.rows.map(r=>`<tr>${r.map(v=>`<td>${String(v).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")}</td>`).join("")}</tr>`).join("")}</tbody></table><div class="footer">Generated by ReconX.</div></body></html>`;
  const reportWindow = window.open("", "_blank");
  if (!reportWindow) { alert("Please allow pop-ups to generate the PDF report."); return; }
  reportWindow.document.open(); reportWindow.document.write(reportHtml); reportWindow.document.close();
  setTimeout(()=>reportWindow.print(),350);
});

const themeToggle = document.getElementById("themeToggle");
const savedTheme = localStorage.getItem("reconx-theme");
if (savedTheme === "light") document.body.classList.add("light");
themeToggle?.addEventListener("click", () => {
  document.body.classList.toggle("light");
  localStorage.setItem("reconx-theme", document.body.classList.contains("light") ? "light" : "dark");
});
