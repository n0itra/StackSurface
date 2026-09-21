const tools = [
  {key:"subfinder", icon:"⌁", desc:"Passive subdomain enumeration (auto-uses github/securitytrails/virustotal/censys/netlas/c99/urlscan/shodan keys if configured on the server)", tag:"Passive"},
  {key:"findomain", icon:"◎", desc:"Fast subdomain enumeration", tag:"Discovery"},
  {key:"assetfinder", icon:"◇", desc:"Find subdomains from multiple sources", tag:"Passive"},
  {key:"crt.sh", icon:"◉", desc:"Certificate transparency search", tag:"OSINT", url:"https://crt.sh/"},
  {key:"gau", icon:"🕘", desc:"Historical URLs (CommonCrawl, Wayback) via gau", tag:"Archive", url:"https://github.com/lc/gau"},
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
  {key:"nuclei", icon:"⬢", desc:"Vulnerability scanning", tag:"Scanner"},
  {key:"ffuf", icon:"◫", desc:"Directory & file fuzzing", tag:"Fuzzing"}
];

const stepMap = [
  ["subfinder","Subdomain Enumeration"],
  ["gau","Historical URL Discovery (gau)"],
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
  ["ffuf","Directory Fuzzing (ffuf)"]
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
        ? `${scan.directories.length} paths discovered (ffuf)`
        : "No results — select ffuf for this scan",
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
let activeScan = null;
let activeScanDomain = "example.com";

let accessToken = localStorage.getItem("reconx-access-token");
let refreshToken = localStorage.getItem("reconx-refresh-token");

function api(url, options = {}) {
  const headers = {...(options.headers || {})};
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  return fetch(url, { ...options, headers }).then(async response => {
    if (response.status !== 401 || !refreshToken || url.startsWith("/api/auth/")) return response;
    const refreshed = await fetch("/api/auth/refresh", {method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({refresh_token: refreshToken})});
    if (!refreshed.ok) return response;
    const data = await refreshed.json();
    setAuthenticated(data.session, data.user);
    return fetch(url, {...options, headers: {...(options.headers || {}), Authorization: `Bearer ${accessToken}`}});
  })
    .catch(err => {
      // Catch network errors specifically (like backend down or CORS issues)
      console.error(`Network Error while fetching ${url}:`, err);
      throw err;
    });
}

const authPage = document.getElementById("authPage");
const authForm = document.getElementById("authForm");
const authToggle = document.getElementById("authToggle");
const authSubmit = document.getElementById("authSubmit");
const authMessage = document.getElementById("authMessage");
let signupMode = false;

function setAuthenticated(session, user) {
  accessToken = session?.access_token || accessToken;
  refreshToken = session?.refresh_token || refreshToken;
  if (accessToken) localStorage.setItem("reconx-access-token", accessToken);
  if (refreshToken) localStorage.setItem("reconx-refresh-token", refreshToken);
  authPage.style.display = "none";
  document.querySelector("main").classList.remove("auth-required");
  document.getElementById("userEmail").textContent = user?.email || "";
  document.getElementById("logoutBtn").hidden = false;
  loadProjects();
}

authToggle.addEventListener("click", () => {
  signupMode = !signupMode;
  authSubmit.textContent = signupMode ? "Create account" : "Sign in";
  authToggle.textContent = signupMode ? "Already have an account? Sign in" : "Create an account";
});
authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  authMessage.textContent = "";
  const endpoint = signupMode ? "/api/auth/signup" : "/api/auth/login";
  try {
    const response = await fetch(endpoint, {method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({email: document.getElementById("authEmail").value,
        password: document.getElementById("authPassword").value})});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Authentication failed");
    if (!data.session) {
      authMessage.textContent = "Check your email to confirm your account, then sign in.";
      signupMode = false;
      authSubmit.textContent = "Sign in";
      return;
    }
    setAuthenticated(data.session, data.user);
  } catch (error) {
    authMessage.textContent = error.message;
  }
});
document.getElementById("logoutBtn").addEventListener("click", async () => {
  await api("/api/auth/logout", {method: "POST"}).catch(() => {});
  localStorage.removeItem("reconx-access-token");
  localStorage.removeItem("reconx-refresh-token");
  accessToken = null;
  refreshToken = null;
  location.reload();
});

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
  activeScanDomain = domain;
  activeScan = {};
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
    activeScan = {scan_id: scanId, status: "running"};
    updateResultSnapshot(activeScan, domain);
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

    // Keep the result view useful while the backend is still producing data.
    updateResultSnapshot(scan, domain);

    if (scan.status === "completed" || scan.status === "failed") {
      stepMap.forEach(([key], idx) => {
        if (!selectedSet.has(key)) return;
        setProgress(idx, "done", scan.status === "failed" ? "Finished with errors" : "Completed", "DONE");
      });
      (scan.errors || []).forEach(e => appendLog(`Note: ${e}`));

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

function updateResultSnapshot(scan, domain) {
  activeScan = scan;
  activeScanDomain = domain;
  datasets = buildDatasets(scan);
  refreshResultTabs(scan, domain);
  renderTable(document.querySelector(".result-tab.active")?.dataset.tab || "subdomains");
}

function refreshResultTabs(scan, domain) {
  document.querySelectorAll(".result-tab").forEach(tab => {
    const key = tab.dataset.tab;
    const total = (datasets[key] && datasets[key].total) || 0;
    const span = tab.querySelector("span");
    if (span) span.textContent = total.toLocaleString();
  });
  document.getElementById("resultDomain").textContent = domain;
  const status = document.getElementById("resultScanStatus");
  const isTerminal = scan.status === "completed" || scan.status === "failed";
  status.className = `result-scan-status ${scan.status === "failed" ? "failed" : isTerminal ? "completed" : "running"}`;
  status.textContent = scan.status === "failed"
    ? "Failed — partial results"
    : isTerminal ? "Completed" : "Running — partial results";
  document.querySelector(".scan-time").textContent = isTerminal
    ? "Scan Time: " + new Date().toLocaleString([], {dateStyle:"medium", timeStyle:"short"})
    : "Live update — scan in progress";
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const tableState = {
  search: "",
  page: 1,
  pageSize: 15,
  sort: {column: null, direction: "asc"},
  statuses: new Set(),
};

function getProcessedRows(tabKey) {
  const data = datasets[tabKey];
  let rows = data.rows.slice();
  if (tabKey === "alive" && tableState.statuses.size) {
    rows = rows.filter(row => tableState.statuses.has(String(row[2])));
  }
  if (tableState.search) {
    const query = tableState.search.toLowerCase();
    rows = rows.filter(row => row.join(" ").toLowerCase().includes(query));
  }
  if (tabKey === "alive" && tableState.sort.column !== null) {
    const index = tableState.sort.column;
    const direction = tableState.sort.direction === "asc" ? 1 : -1;
    rows.sort((a, b) => {
      const left = String(a[index] ?? "");
      const right = String(b[index] ?? "");
      if (index === 2) {
        const leftNumber = Number(left);
        const rightNumber = Number(right);
        const leftValid = left !== "" && Number.isFinite(leftNumber);
        const rightValid = right !== "" && Number.isFinite(rightNumber);
        if (leftValid !== rightValid) return leftValid ? -1 : 1;
        if (leftValid && leftNumber !== rightNumber) return (leftNumber - rightNumber) * direction;
      } else {
        const comparison = left.localeCompare(right, undefined, {numeric: true, sensitivity: "base"});
        if (comparison) return comparison * direction;
      }
      return 0;
    });
  }
  return rows;
}

function renderStatusFilter(data) {
  const filter = document.getElementById("statusFilter");
  if (!filter) return;
  const isAlive = data.title === "Alive Hosts";
  filter.hidden = !isAlive;
  if (!isAlive) return;
  const statuses = [...new Set(data.rows.map(row => String(row[2])))].sort((a, b) => {
    const an = Number(a), bn = Number(b);
    if (Number.isFinite(an) && Number.isFinite(bn)) return an - bn;
    if (Number.isFinite(an)) return -1;
    if (Number.isFinite(bn)) return 1;
    return a.localeCompare(b);
  });
  tableState.statuses.forEach(status => {
    if (!statuses.includes(status)) tableState.statuses.delete(status);
  });
  const menu = document.getElementById("statusFilterMenu");
  menu.innerHTML = `<label class="status-filter-option"><input type="checkbox" data-status-all ${
    tableState.statuses.size === 0 ? "checked" : ""
  }>All statuses</label>${statuses.map(status => `<label class="status-filter-option"><input type="checkbox" data-status="${escapeHtml(status)}" ${
    tableState.statuses.has(status) ? "checked" : ""
  }>${escapeHtml(status)}</label>`).join("")}<button type="button" class="ghost-btn" data-status-reset>Clear/reset</button>`;
  document.getElementById("statusFilterToggle").textContent = tableState.statuses.size
    ? `Statuses (${tableState.statuses.size}) ▾` : "Statuses ▾";
}

function renderTable(tabKey){
  const data = datasets[tabKey];
  document.getElementById("tableTitle").textContent = data.title;
  renderStatusFilter(data);
  document.getElementById("tableSearch").placeholder = data.search;
  const sortable = tabKey === "alive";
  document.getElementById("tableHead").innerHTML = `<tr>${data.columns.map((column, index) => {
    if (!sortable || index === 0) return `<th>${escapeHtml(column)}</th>`;
    const active = tableState.sort.column === index;
    const ariaSort = active ? (tableState.sort.direction === "asc" ? "ascending" : "descending") : "none";
    return `<th class="sortable" aria-sort="${ariaSort}"><button type="button" data-sort-column="${index}">${escapeHtml(column)}</button></th>`;
  }).join("")}</tr>`;
  const filteredRows = getProcessedRows(tabKey);
  const pageCount = Math.max(1, Math.ceil(filteredRows.length / tableState.pageSize));
  tableState.page = Math.min(tableState.page, pageCount);
  const start = (tableState.page - 1) * tableState.pageSize;
  const rows = filteredRows.slice(start, start + tableState.pageSize);
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
  const first = filteredRows.length ? start + 1 : 0;
  const last = Math.min(start + rows.length, filteredRows.length);
  document.getElementById("rowSummary").textContent = `Showing ${first} to ${last} of ${filteredRows.length} results`;
  document.getElementById("tableSubtitle").textContent = tabKey === "alive"
    ? `${filteredRows.length} of ${data.total} responsive hosts discovered`
    : data.subtitle;
  document.getElementById("pagination").innerHTML = Array.from({length: pageCount}, (_, i) => i + 1).map(page =>
    `<button type="button" class="page-btn ${page === tableState.page ? "active" : ""}" data-page="${page}">${page}</button>`).join("");
}

renderTools();
renderProgress();
renderTable("subdomains");
document.getElementById("workspace").classList.add("collapsed");

async function loadProjects() {
  const select = document.getElementById("projectSelect");
  if (!accessToken) return;
  try {
    const res = await api("/api/projects");
    if (res.status === 401) {
      localStorage.removeItem("reconx-access-token");
      localStorage.removeItem("reconx-refresh-token");
      accessToken = null;
      refreshToken = null;
      authPage.style.display = "flex";
      return;
    }
    if (!res.ok) return;
    const projects = await res.json();
    renderProfileProjects(projects);
    const current = select.value;
    select.innerHTML = '<option value="">No project (one-off scan)</option>' +
      projects.map(p => `<option value="${escapeHtml(p.project_id)}">${escapeHtml(p.name)} — ${escapeHtml(p.domain)}${p.monitoring ? " 🟢" : ""}</option>`).join("");
    select.value = current;
  } catch (e) {
    console.warn("Could not load projects (Backend/Supabase unreachable).");
  }

  function renderProfileProjects(projects) {
    const target = document.getElementById("profileProjects");
    if (target) target.innerHTML = projects.length
      ? projects.map(p => `<div class="profile-item"><strong>${escapeHtml(p.name)}</strong> — ${escapeHtml(p.domain)} ${p.monitoring ? "🟢 Monitoring" : ""}</div>`).join("")
      : "<p>No projects yet.</p>";
  }

  async function loadHistory() {
    if (!accessToken) return;
    const response = await api("/api/history");
    if (!response.ok) return;
    const rows = await response.json();
    const body = document.getElementById("historyBody");
    body.innerHTML = rows.length ? rows.map(row => `<tr><td>${escapeHtml(row.domain)}</td><td>${escapeHtml(row.status)}</td><td>${escapeHtml(new Date(row.created_at).toLocaleString())}</td><td>${escapeHtml(row.project_id || "One-off")}</td></tr>`).join("") : '<tr><td colspan="4">No scans yet.</td></tr>';
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

if (accessToken) {
  authPage.style.display = "none";
  loadProjects();
} else {
  authPage.style.display = "flex";
}

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
    if(page) {
      goTo(page);
      if (page === "profile") loadHistory().catch(() => {});
    }
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
  tableState.search = e.target.value.trim();
  tableState.page = 1;
  renderTable(document.querySelector(".result-tab.active").dataset.tab);
});

document.querySelectorAll(".result-tab").forEach(tab => {
  tab.addEventListener("click", ()=>{
    document.querySelectorAll(".result-tab").forEach(t=>t.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tableSearch").value = "";
    tableState.search = "";
    tableState.page = 1;
    tableState.sort = {column: null, direction: "asc"};
    tableState.statuses.clear();
    document.getElementById("statusFilterMenu").hidden = true;
    document.getElementById("statusFilterToggle").setAttribute("aria-expanded", "false");
    renderTable(tab.dataset.tab);
  });
});

document.getElementById("tableHead").addEventListener("click", event => {
  const button = event.target.closest("[data-sort-column]");
  if (!button) return;
  const column = Number(button.dataset.sortColumn);
  if (tableState.sort.column === column) {
    tableState.sort.direction = tableState.sort.direction === "asc" ? "desc" : "asc";
  } else {
    tableState.sort = {column, direction: "asc"};
  }
  tableState.page = 1;
  renderTable("alive");
});

document.getElementById("pagination").addEventListener("click", event => {
  const button = event.target.closest("[data-page]");
  if (!button) return;
  tableState.page = Number(button.dataset.page);
  renderTable(document.querySelector(".result-tab.active").dataset.tab);
});

document.getElementById("statusFilterToggle").addEventListener("click", () => {
  const menu = document.getElementById("statusFilterMenu");
  const open = menu.hidden !== true;
  menu.hidden = open;
  document.getElementById("statusFilterToggle").setAttribute("aria-expanded", String(!open));
});
document.getElementById("statusFilterMenu").addEventListener("change", event => {
  if (!event.target.matches("input")) return;
  if (event.target.hasAttribute("data-status-all")) {
    tableState.statuses.clear();
  } else {
    const status = event.target.dataset.status;
    if (event.target.checked) tableState.statuses.add(status);
    else tableState.statuses.delete(status);
  }
  tableState.page = 1;
  renderTable("alive");
  document.getElementById("statusFilterMenu").hidden = false;
});
document.getElementById("statusFilterMenu").addEventListener("click", event => {
  if (!event.target.matches("[data-status-reset]")) return;
  tableState.statuses.clear();
  tableState.page = 1;
  renderTable("alive");
});
document.addEventListener("click", event => {
  const filter = document.getElementById("statusFilter");
  if (filter && !filter.hidden && !filter.contains(event.target)) {
    document.getElementById("statusFilterMenu").hidden = true;
    document.getElementById("statusFilterToggle").setAttribute("aria-expanded", "false");
  }
});

document.getElementById("exportBtn").addEventListener("click", ()=>{
  const active = document.querySelector(".result-tab.active").dataset.tab;
  const data = datasets[active];
  const csv = [data.columns.join(","), ...getProcessedRows(active).map(r=>r.map(v=>`"${String(v).replaceAll('"','""')}"`).join(","))].join("\n");
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
  const reportRows = getProcessedRows(activeTab);
  const reportHtml = `<!doctype html><html><head><meta charset="utf-8"><title>StackSurface Report</title><style>body{font-family:Arial,sans-serif;color:#17283a;padding:36px}h1{margin:0 0 8px;font-size:28px}.meta{color:#60758a;margin-bottom:28px}h2{font-size:18px;margin-top:28px}table{width:100%;border-collapse:collapse;margin-top:12px}th,td{border:1px solid #d6e0e8;padding:9px;text-align:left;font-size:11px}th{background:#eef4f8}.footer{margin-top:28px;color:#71869a;font-size:10px}</style></head><body><h1>StackSurface Security Report</h1><div class="meta">Automated Recon • ${domain} • ${new Date().toLocaleString()}</div><h2>${data.title}</h2><p>${data.subtitle}</p><table><thead><tr>${data.columns.map(c=>`<th>${c}</th>`).join("")}</tr></thead><tbody>${reportRows.map(r=>`<tr>${r.map(v=>`<td>${String(v).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")}</td>`).join("")}</tr>`).join("")}</tbody></table><div class="footer">Generated by StackSurface.</div></body></html>`;
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
