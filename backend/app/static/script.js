// --- Supabase & Auth Setup ---
const supabaseClient = supabase.createClient(window.__SUPABASE_URL__, window.__SUPABASE_ANON_KEY__);
let currentSession = null;
let currentScanData = null; 
let networkInstance = null; 

async function initAuth() {
  const { data, error } = await supabaseClient.auth.getSession();
  if (data.session) {
    handleLoginSuccess(data.session);
  } else {
    document.getElementById("authOverlay").style.display = "flex";
    document.getElementById("appContent").style.display = "none";
  }

  supabaseClient.auth.onAuthStateChange((event, session) => {
    if (event === 'SIGNED_IN' && session) {
      handleLoginSuccess(session);
    } else if (event === 'SIGNED_OUT') {
      currentSession = null;
      document.getElementById("authOverlay").style.display = "flex";
      document.getElementById("appContent").style.display = "none";
      window.location.reload();
    }
  });
}

function handleLoginSuccess(session) {
  currentSession = session;
  document.getElementById("authOverlay").style.display = "none";
  document.getElementById("appContent").style.display = "block";
  document.getElementById("userEmailDisplay").textContent = session.user.email;
  loadProjects();
  loadHistory();
}

document.getElementById("loginBtn").addEventListener("click", async () => {
  const email = document.getElementById("authEmail").value;
  const password = document.getElementById("authPassword").value;
  const msgEl = document.getElementById("authMessage");
  
  if (!email || !password) {
    msgEl.textContent = "Please enter email and password.";
    return;
  }
  msgEl.textContent = "Logging in...";
  
  const { data, error } = await supabaseClient.auth.signInWithPassword({ email, password });
  if (error) {
    msgEl.textContent = error.message;
  } else {
    msgEl.textContent = "";
  }
});

document.getElementById("signupBtn").addEventListener("click", async () => {
  const email = document.getElementById("authEmail").value;
  const password = document.getElementById("authPassword").value;
  const msgEl = document.getElementById("authMessage");
  
  if (!email || !password) {
    msgEl.textContent = "Please enter email and password.";
    return;
  }
  msgEl.textContent = "Creating account...";
  
  const { data, error } = await supabaseClient.auth.signUp({ email, password });
  if (error) {
    msgEl.textContent = error.message;
  } else {
    msgEl.textContent = "Account created! You can now log in.";
  }
});

document.getElementById("logoutBtn").addEventListener("click", async () => {
  await supabaseClient.auth.signOut();
});

function api(url, options = {}) {
  if (!currentSession) {
    console.error("No active session found!");
    return Promise.reject("No session");
  }
  
  const headers = {
    "Authorization": `Bearer ${currentSession.access_token}`,
    ...(options.headers || {})
  };
  
  return fetch(url, { ...options, headers })
    .catch(err => {
      console.error(`Network Error while fetching ${url}:`, err);
      throw err;
    });
}

// --- ترتيب الأدوات المنطقي الجديد (Kill Chain) ---
const tools = [
  {key:"subfinder", icon:"⌁", desc:"Passive subdomain enumeration", tag:"Passive"},
  {key:"findomain", icon:"◎", desc:"Fast subdomain enumeration", tag:"Discovery"},
  {key:"assetfinder", icon:"◇", desc:"Find subdomains from multiple sources", tag:"Passive"},
  {key:"crt.sh", icon:"◉", desc:"Certificate transparency search", tag:"OSINT", url:"https://crt.sh/"},
  {key:"gau", icon:"🕘", desc:"Fetch historical URLs (Archive & Wayback)", tag:"Archive"},
  {key:"anew", icon:"≋", desc:"Merge & deduplicate results", tag:"Cleanup"},
  
  {key:"permutations", icon:"⟲", desc:"Generates & resolves likely subdomain guesses", tag:"Active"},
  {key:"dnsx", icon:"◆", desc:"Resolves each subdomain to an IP", tag:"DNS"},
  {key:"cdncheck", icon:"◆", desc:"Flags CDN/WAF-fronted IPs before port lookup", tag:"DNS"},
  {key:"shodan", icon:"•", desc:"Open-port lookup per resolved IP (requires API Key)", tag:"Network", apiKey:true},
  
  {key:"httpx", icon:"↗", desc:"Alive host & technology detection", tag:"HTTP"},
  
  {key:"katana", icon:"⌁", desc:"Web crawling & URL discovery", tag:"Crawler"},
  {key:"feroxbuster", icon:"◫", desc:"Directory & file fuzzing", tag:"Fuzzing"},
  
  {key:"arjun", icon:"⟐", desc:"Parameter discovery", tag:"Params"},
  {key:"jsluice", icon:"◍", desc:"AST-aware JS secret & endpoint analysis", tag:"Secrets"},
  {key:"trufflehog", icon:"◍", desc:"Regex/entropy-based secret scanning", tag:"Secrets"},
  {key:"nuclei", icon:"⬢", desc:"Vulnerability scanning", tag:"Scanner"}
];

// --- ترتيب خطوات التحميل في الواجهة بنفس المنطق ---
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
  ["feroxbuster","Directory Fuzzing (feroxbuster)"],
  ["arjun","Parameter Discovery (arjun)"],
  ["jsluice","JS Secret Analysis (jsluice)"],
  ["trufflehog","Secret Discovery (trufflehog)"],
  ["nuclei","Vulnerability Scanning (nuclei)"]
];

const lightScanTools = ["subfinder", "findomain", "assetfinder", "crt.sh", "gau", "anew", "dnsx", "cdncheck", "shodan", "httpx"];

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
      subtitle: `Total: ${subdomains.length} subdomains — ${unresolved.size} with no IP`,
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
      subtitle: `${(scan.endpoints || []).length} endpoints discovered`,
      search: "Search endpoints...",
      columns: ["#", "Endpoint", "Method", "Status"],
      rows: (scan.endpoints || []).map((e, i) => [
        String(i + 1), e.url || "-", e.method || "GET", String(e.status ?? "-"),
      ]),
      total: (scan.endpoints || []).length,
    },
    secrets: {
      title: "Secrets",
      subtitle: `${(scan.secrets || []).length} potential secrets found`,
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
      subtitle: `${vulnerabilities.length} template matches`,
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
      subtitle: `${(scan.added_assets || []).length} new, ${(scan.removed_assets || []).length} removed since last scan`,
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
      subtitle: `${(scan.new_js_dependencies || []).length} new JS libraries`,
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
      subtitle: `${(scan.directories || []).length} paths discovered`,
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
let sortCol = -1;
let sortAsc = true;

const toolsList = document.getElementById("toolsList");
const progressList = document.getElementById("progressList");
const consoleEl = document.getElementById("console");
const startBtn = document.getElementById("startBtn");
const domainInput = document.getElementById("domainInput");
const webhookInput = document.getElementById("webhookInput");
const forceRefreshToggle = document.getElementById("forceRefreshToggle");
const statusDot = document.getElementById("statusDot");
const scanStatus = document.getElementById("scanStatus");
const selectAll = document.getElementById("selectAll");

let currentStep = -1;
let running = false;

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
  
  const lines = consoleEl.textContent.split('\n');
  if (lines.length > 600) {
    consoleEl.textContent = lines.slice(-600).join('\n') + '\n';
  }
  
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

function drawNetworkGraph(scanData) {
  if (!scanData || !scanData.subdomains) return;
  
  const container = document.getElementById("networkGraph");
  if (!container) return; 

  const nodes = new vis.DataSet();
  const edges = new vis.DataSet();
  
  const subdomains = scanData.subdomains.slice(0, 300);
  const rootDomain = scanData.domain || "Target";
  
  nodes.add({ id: rootDomain, label: rootDomain, shape: "hexagon", color: "#3b82f6", font: {color: "#fff"}, size: 25 });
  
  const aliveByHost = {};
  (scanData.alive || []).forEach(h => { if (h && h.host) aliveByHost[h.host] = h; });
  
  subdomains.forEach(sub => {
    if (sub === rootDomain) return; 
    const isAlive = !!aliveByHost[sub];
    
    nodes.add({ 
      id: sub, 
      label: sub, 
      shape: "dot", 
      size: isAlive ? 14 : 9,
      color: isAlive ? "#10b981" : "#475569", 
      font: {color: "#cbd5e1"} 
    });
    
    edges.add({ from: rootDomain, to: sub, color: "#1e293b" });
    
    if (isAlive && aliveByHost[sub].a) {
      aliveByHost[sub].a.slice(0, 2).forEach(ip => {
        if (!nodes.get(ip)) {
          nodes.add({ id: ip, label: ip, shape: "box", color: "#ef4444", font: {color: "#fff"}, size: 10 });
        }
        edges.add({ from: sub, to: ip, color: "#1e293b", dashes: true });
      });
    }
  });
  
  const data = { nodes: nodes, edges: edges };
  const options = {
    physics: { barnesHut: { gravitationalConstant: -2000, centralGravity: 0.3, springLength: 100 } },
    interaction: { hover: true, tooltipDelay: 200, zoomView: true, dragView: true }
  };
  
  if (networkInstance) networkInstance.destroy(); 
  networkInstance = new vis.Network(container, data, options);
}

async function runScan()  { 
  if(running) return;
  const domain = domainInput.value.trim() || "example.com";
  const discordWebhook = webhookInput ? webhookInput.value.trim() : null; 
  const forceRefresh = forceRefreshToggle ? forceRefreshToggle.checked : false;
  const selected = selectedToolKeys();
  const selectedSet = new Set(selected);
  const projectId = document.getElementById("projectSelect").value || null;
  
  const customWordlistEl = document.getElementById("customWordlistInput");
  const customWordlist = customWordlistEl ? customWordlistEl.value.trim() : "";
  
  running = true;
  startBtn.disabled = true;
  startBtn.querySelector("span").textContent = "Running...";
  statusDot.classList.add("running");
  scanStatus.textContent = "Running";
  consoleEl.textContent = "";
  
  appendLog(`Target accepted: ${domain}`);
  if (forceRefresh) appendLog(`Force Refresh requested. Ignoring cached data.`);
  if (discordWebhook) appendLog(`Custom Discord Webhook attached. Alerts enabled.`);
  if (customWordlist && selected.includes("feroxbuster")) appendLog(`Custom wordlist provided for directory fuzzing.`);
  appendLog(`Selected tools: ${selected.join(", ") || "none"}`);

  resetProgress();
  stepMap.forEach(([key], idx) => {
    setProgress(idx, selectedSet.has(key) ? "running" : "skipped",
                selectedSet.has(key) ? "Queued..." : "Skipped by user",
                selectedSet.has(key) ? "—" : "SKIP");
  });

  let scanId;
  let isCached = false;
  
  try {
    const res = await api("/api/scans", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        domain, 
        tools: selected, 
        project_id: projectId,
        discord_webhook: discordWebhook || undefined,
        force_refresh: forceRefresh,
        custom_wordlist: customWordlist || undefined 
      }),
    });
    
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      appendLog(`Error: ${data.detail || `HTTP ${res.status} - scan could not be started`}`);
      resetRunState();
      return;
    }
    const data = await res.json();
    scanId = data.scan_id;
    isCached = data.cached;
    
    if (isCached) {
      appendLog(`Found recent cached scan for ${domain}. Displaying results instantly.`);
    } else {
      appendLog(`Scan queued (${scanId}).`);
    }
  } catch (e) {
    appendLog(`Network error contacting backend. Make sure the server is running.`);
    resetRunState();
    return;
  }

  const startedAt = Date.now();
  const maxWaitMs = 60 * 60 * 1000; 
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
      continue;
    }

    const liveLogs = scan.live_logs || [];
    if (liveLogs.length > lastLogIndex) {
        let chunk = "";
        for (let i = lastLogIndex; i < liveLogs.length; i++) {
            chunk += `> ${liveLogs[i]}\n`;
        }
        appendLog(chunk.trim()); 
        lastLogIndex = liveLogs.length;
    }

    const progress = Number(scan.progress || 0);
    if (progress !== lastProgress) {
      lastProgress = progress;
    }

    currentScanData = scan;
    datasets = buildDatasets(scan);
    refreshResultTabs(scan, domain);
    
    if (!isCached) {
      const activeTab = document.querySelector(".result-tab.active")?.dataset.tab || "subdomains";
      if (activeTab === "network") {
        drawNetworkGraph(currentScanData);
      } else {
        renderTable(activeTab);
      }
    }

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
      loadHistory(); 
      
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
  document.querySelectorAll(".result-tab:not([data-tab='network'])").forEach(tab => {
    const key = tab.dataset.tab;
    const total = (datasets[key] && datasets[key].total) || 0;
    const span = tab.querySelector("span");
    if (span) span.textContent = total.toLocaleString();
  });
  
  document.getElementById("resultDomain").textContent = domain;
  document.getElementById("resultTitleH1").textContent = scan.status === "running" ? "Live Results..." : "Scan Results";
  
  if (scan.completed_at || scan.status === "completed") {
    document.getElementById("scanTimeDisplay").textContent = "Scan Time: " + new Date().toLocaleString([], {dateStyle:"medium", timeStyle:"short"});
  } else {
    document.getElementById("scanTimeDisplay").textContent = "Scan running...";
  }
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
  if (!data) return; 
  
  document.getElementById("tableTitle").textContent = data.title;
  document.getElementById("tableSubtitle").textContent = data.subtitle;
  document.getElementById("tableSearch").placeholder = data.search;

  // التعديل هنا: تصميم احترافي للأسهم (↕ افتراضي، ↑ تصاعدي، ↓ تنازلي)
  document.getElementById("tableHead").innerHTML = `<tr>${data.columns.map((c, i) => {
    let sortIcon = "↕"; // السهمين الافتراضيين
    let iconColor = "#475569"; // لون باهت للعمود اللي مش مترتب
    
    if (sortCol === i) {
      sortIcon = sortAsc ? "↑" : "↓"; // سهم طالع أو نازل
      iconColor = "#3b82f6"; // لون أزرق مميز للعمود المترتب حالياً
    }
    
    return `<th style="cursor: pointer; user-select: none; transition: background 0.2s;" onclick="sortTable(${i})" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
      <div style="display: flex; align-items: center; justify-content: space-between;">
        <span>${escapeHtml(c)}</span>
        <span style="color: ${iconColor}; font-size: 14px; margin-left: 8px;">${sortIcon}</span>
      </div>
    </th>`;
  }).join("")}</tr>`;
  
  const rows = data.rows.filter(r => r.join(" ").toLowerCase().includes(filter.toLowerCase()));
  
  if (rows.length === 0) {
    document.getElementById("tableBody").innerHTML = `<tr class="loading-row"><td colspan="${data.columns.length}">No data found or still scanning...</td></tr>`;
    document.getElementById("rowSummary").textContent = `Showing 0 results`;
    document.getElementById("pagination").innerHTML = "";
    return;
  }

  document.getElementById("tableBody").innerHTML = rows.map(row => {
    return `<tr>${row.map((cell,i)=>{
      const safeCell = escapeHtml(cell);
      // دي الجزئية اللي بتحافظ على شكل وحجم بادج الـ Status بدون تغيير
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
  
  document.getElementById("rowSummary").textContent = `Showing 1 to ${rows.length > 50 ? 50 : rows.length} of ${data.total} results`;
  document.getElementById("pagination").innerHTML = [1,2,3,4,5,"…",10].map((n,i)=>
    `<button class="page-btn ${i===0?"active":""}">${n}</button>`).join("");
}

// الإضافة: دالة ترتيب الجدول
window.sortTable = function(colIndex) {
  const activeTab = document.querySelector(".result-tab.active").dataset.tab;
  const data = datasets[activeTab];
  if (!data) return;

  if (sortCol === colIndex) {
    sortAsc = !sortAsc;
  } else {
    sortCol = colIndex;
    sortAsc = true;
  }

  data.rows.sort((a, b) => {
    let valA = a[colIndex] || "";
    let valB = b[colIndex] || "";
    
    valA = String(valA).replace(/(<([^>]+)>)/gi, "");
    valB = String(valB).replace(/(<([^>]+)>)/gi, "");

    let numA = parseFloat(valA);
    let numB = parseFloat(valB);

    if (!isNaN(numA) && !isNaN(numB)) {
      return sortAsc ? numA - numB : numB - numA;
    }
    
    return sortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
  });

  renderTable(activeTab, document.getElementById("tableSearch").value);
};

async function loadHistory() {
  const tbody = document.getElementById("historyTableBody");
  try {
    const res = await api("/api/history");
    if (!res.ok) throw new Error("Failed to load history");
    const history = await res.json();
    
    if (history.length === 0) {
      tbody.innerHTML = `<tr class="loading-row"><td colspan="6">No scans found in your history.</td></tr>`;
      return;
    }
    
    tbody.innerHTML = history.map(item => {
      const date = item.completed_at ? new Date(item.completed_at).toLocaleString([], {dateStyle:"medium", timeStyle:"short"}) : "Running...";
      const isCompleted = item.status === "completed";
      const statusClass = isCompleted ? "b200" : item.status === "failed" ? "b404" : "b302";
      
      const subsCount = item.subdomains_count ?? 0;
      const vulnsCount = item.vulnerabilities_count ?? 0;
      const vulnClass = vulnsCount > 0 ? "color: #ef4444; font-weight: bold;" : "color: #60758a;";
      
      return `<tr>
        <td>${escapeHtml(date)}</td>
        <td style="font-weight: 500;">${escapeHtml(item.domain)}</td>
        <td><span class="badge ${statusClass}">${escapeHtml(item.status)}</span></td>
        <td style="font-weight: 500; color: #3b82f6;">${subsCount}</td>
        <td style="${vulnClass}">${vulnsCount}</td>
        <td>
          <button class="secondary-btn small" onclick="loadScanFromHistory('${escapeHtml(item.scan_id)}')">View</button>
        </td>
      </tr>`;
    }).join("");
    
  } catch (e) {
    tbody.innerHTML = `<tr class="loading-row"><td colspan="6">Failed to load history.</td></tr>`;
  }
}

window.loadScanFromHistory = async function(scanId) {
  try {
    const res = await api(`/api/scans/${scanId}`);
    if (!res.ok) throw new Error("Scan not found");
    const scan = await res.json();
    
    currentScanData = scan;
    datasets = buildDatasets(scan);
    refreshResultTabs(scan, scan.domain);
    
    document.querySelectorAll(".result-tab").forEach(t => t.classList.remove("active"));
    document.querySelector(".result-tab[data-tab='subdomains']").classList.add("active");
    
    const tableCard = document.getElementById("tableCard");
    const mapCard = document.getElementById("mapCard");
    if (tableCard) tableCard.style.display = "block";
    if (mapCard) mapCard.style.display = "none";
    
    renderTable("subdomains");
    goTo("results");
  } catch (e) {
    alert("Could not load scan details.");
  }
};

document.getElementById("refreshHistoryBtn").addEventListener("click", loadHistory);

// --- Events Setup ---
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
    console.warn("Could not load projects.");
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

startBtn.addEventListener("click", runScan);

// Presets
document.getElementById("lightScanBtn").addEventListener("click", () => {
  document.querySelectorAll(".tool-row input:not(:disabled)").forEach(checkbox => {
    checkbox.checked = lightScanTools.includes(checkbox.dataset.tool);
  });
  selectAll.checked = false;
});
document.getElementById("deepScanBtn").addEventListener("click", () => {
  document.querySelectorAll(".tool-row input:not(:disabled)").forEach(checkbox => {
    checkbox.checked = true;
  });
  selectAll.checked = true;
});

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
  if(active !== "network") renderTable(active,e.target.value);
});

document.querySelectorAll(".result-tab").forEach(tab => {
  tab.addEventListener("click", ()=>{
    document.querySelectorAll(".result-tab").forEach(t=>t.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tableSearch").value = "";
    // تصفير مؤشر الترتيب عند تغيير التاب
    sortCol = -1;
    sortAsc = true;
    
    const targetTab = tab.dataset.tab;
    const tableCard = document.getElementById("tableCard");
    const mapCard = document.getElementById("mapCard");
    
    if (targetTab === "network") {
      if(tableCard) tableCard.style.display = "none";
      if(mapCard) mapCard.style.display = "block";
      setTimeout(() => drawNetworkGraph(currentScanData), 50); 
    } else {
      if(tableCard) tableCard.style.display = "block";
      if(mapCard) mapCard.style.display = "none";
      renderTable(targetTab);
    }
  });
});

document.getElementById("exportBtn").addEventListener("click", ()=>{
  const active = document.querySelector(".result-tab.active").dataset.tab;
  if (active === "network") return alert("Can't export map directly to CSV. Export a table instead.");
  
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
  if (activeTab === "network") return alert("Please select a table tab to download a PDF report.");
  
  const data = datasets[activeTab];
  const reportHtml = `<!doctype html><html><head><meta charset="utf-8"><title>ReconX Report</title><style>body{font-family:Arial,sans-serif;color:#17283a;padding:36px}h1{margin:0 0 8px;font-size:28px}.meta{color:#60758a;margin-bottom:28px}h2{font-size:18px;margin-top:28px}table{width:100%;border-collapse:collapse;margin-top:12px}th,td{border:1px solid #d6e0e8;padding:9px;text-align:left;font-size:11px}th{background:#eef4f8}.footer{margin-top:28px;color:#71869a;font-size:10px}</style></head><body><h1>ReconX Security Report</h1><div class="meta">Automated Recon • ${domain} • ${new Date().toLocaleString()}</div><h2>${data.title}</h2><p>${data.subtitle}</p><table><thead><tr>${data.columns.map(c=>`<th>${c}</th>`).join("")}</tr></thead><tbody>${data.rows.map(r=>`<tr>${r.map(v=>`<td>${String(v).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")}</td>`).join("")}</tr>`).join("")}</tbody></table><div class="footer">Generated by ReconX.</div></body></html>`;
  const reportWindow = window.open("", "_blank");
  if (!reportWindow) { alert("Please allow pop-ups to generate the PDF report."); return; }
  reportWindow.document.open(); reportWindow.document.write(reportHtml); reportWindow.document.close();
  setTimeout(()=>reportWindow.print(),350);
});

// الإضافة: زر طلب تقرير الذكاء الاصطناعي (AI Report)
document.getElementById("aiReportBtn")?.addEventListener("click", async () => {
  if (!currentScanData || !currentScanData.scan_id) {
    alert("Please wait for a scan to finish or select one from history.");
    return;
  }
  
  const btn = document.getElementById("aiReportBtn");
  const originalText = btn.innerHTML;
  btn.innerHTML = "⏳ Generating AI Report...";
  btn.disabled = true;

  try {
    const res = await api(`/api/scans/${currentScanData.scan_id}/ai-report`, { method: "POST" });
    if (!res.ok) throw new Error("Failed to generate AI report");
    
    const data = await res.json();
    
    const reportWindow = window.open("", "_blank");
    if (!reportWindow) { alert("Please allow pop-ups to view the AI report."); return; }
    
    reportWindow.document.write(`
      <html><head><title>AI Security Report</title>
      <style>body{font-family: Arial, sans-serif; line-height: 1.6; padding: 40px; color: #333; max-width: 800px; margin: auto; background-color: #f8fafc;}</style>
      </head><body>
      <div style="background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
        <h1 style="color: #1e293b; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;">🤖 AI Security Executive Report</h1>
        <p style="color: #64748b; font-size: 14px;">Target: ${currentScanData.domain} | Scan ID: ${currentScanData.scan_id}</p>
        <pre style="white-space: pre-wrap; font-family: inherit; font-size: 16px; color: #334155; margin-top: 20px;">${data.report}</pre>
        <button onclick="window.print()" style="margin-top: 20px; padding: 10px 20px; cursor: pointer; background: #3b82f6; color: white; border: none; border-radius: 5px; font-weight: bold;">Print Report</button>
      </div>
      </body></html>
    `);
    reportWindow.document.close();
  } catch (err) {
    alert("Error: " + err.message);
  } finally {
    btn.innerHTML = originalText;
    btn.disabled = false;
  }
});

const themeToggle = document.getElementById("themeToggle");
const savedTheme = localStorage.getItem("reconx-theme");
if (savedTheme === "light") document.body.classList.add("light");
themeToggle?.addEventListener("click", () => {
  document.body.classList.toggle("light");
  localStorage.setItem("reconx-theme", document.body.classList.contains("light") ? "light" : "dark");
});

initAuth();
