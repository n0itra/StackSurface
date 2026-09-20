import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import redis
import httpx
from supabase import create_client

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)

SCAN_DIR = Path("/scans")
SCAN_DIR.mkdir(parents=True, exist_ok=True)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")
NETLAS_API_KEY = os.getenv("NETLAS_API_KEY")
C99_API_KEY = os.getenv("C99_API_KEY")

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_notification(message: str, custom_discord_webhook: str = None):
    webhook = custom_discord_webhook or DISCORD_WEBHOOK_URL
    if webhook:
        try:
            httpx.post(webhook, json={"content": message}, timeout=10)
        except Exception as e:
            print(f"[Alert Error] Discord: {e}")

    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            httpx.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": message}, timeout=10)
        except Exception as e:
            print(f"[Alert Error] Telegram: {e}")

def update(scan_id, **fields):
    r.hset(f"scan:{scan_id}", mapping={k: str(v) for k, v in fields.items()})

def run_command(args, timeout=300):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"
    except FileNotFoundError as e:
        return -1, "", f"command not found: {e}"

def run_command_live(scan_id, args, timeout=300, tool_name=""):
    try:
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out_lines = []
        for line in p.stdout:
            out_lines.append(line)
            clean = line.strip()
            if not clean:
                continue
            display = ""
            if tool_name in ["subfinder", "assetfinder", "findomain", "puredns"]:
                display = clean
            elif tool_name == "dnsx":
                try: display = json.loads(clean).get("host")
                except: pass
            elif tool_name == "httpx":
                try: display = json.loads(clean).get("url")
                except: pass
            elif tool_name == "katana":
                try: 
                    d = json.loads(clean)
                    display = d.get("request", {}).get("endpoint") or d.get("endpoint")
                except: pass
            elif tool_name == "nuclei":
                try: 
                    d = json.loads(clean)
                    display = f"[VULN] {d.get('info', {}).get('name')} -> {d.get('host')}"
                except: pass
            elif tool_name == "feroxbuster":
                try:
                    d = json.loads(clean)
                    if d.get("type") == "response" and d.get("status", 0) < 400:
                        display = d.get("url")
                except: pass
            if display:
                r.rpush(f"scan:{scan_id}:live_logs", f"[{tool_name}] {display}")
        p.wait(timeout=timeout)
        return p.returncode, "".join(out_lines), ""
    except subprocess.TimeoutExpired:
        p.kill()
        return -1, "", f"timed out after {timeout}s"
    except FileNotFoundError as e:
        return -1, "", f"command not found: {e}"
    except Exception as e:
        return -1, "", str(e)

def is_safe_target(domain: str) -> bool:
    try:
        resolved_ips = {info[4][0] for info in socket.getaddrinfo(domain, None)}
    except socket.gaierror:
        return False
    for ip_str in resolved_ips:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return False
    return bool(resolved_ips)

def in_scope(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)

def src_subfinder(scan_id, domain):
    code, out, err = run_command_live(scan_id, ["subfinder", "-d", domain, "-silent"], tool_name="subfinder")
    if code != 0: return set(), f"subfinder: exit {code}: {out[-300:]!r}"
    return {x.strip().lower() for x in out.splitlines() if x.strip() and not x.startswith("{")}, None

def src_assetfinder(scan_id, domain):
    code, out, err = run_command_live(scan_id, ["assetfinder", "--subs-only", domain], tool_name="assetfinder")
    if code != 0: return set(), f"assetfinder: exit {code}: {out[-300:]!r}"
    return {x.strip().lower() for x in out.splitlines() if x.strip()}, None

def src_findomain(scan_id, domain):
    code, out, err = run_command_live(scan_id, ["findomain", "-t", domain, "-q"], timeout=120, tool_name="findomain")
    if code != 0: return set(), f"findomain: exit {code}: {out[-300:]!r}"
    return {x.strip().lower() for x in out.splitlines() if x.strip()}, None

def src_crtsh(scan_id, domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(2):
        try:
            with httpx.Client(timeout=30, follow_redirects=True) as client:
                data = client.get(url).json()
            names = set()
            for row in data:
                for name in row.get("name_value", "").splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if in_scope(name, domain):
                        names.add(name)
                        r.rpush(f"scan:{scan_id}:live_logs", f"[crt.sh] {name}")
            return names, None
        except Exception as e:
            last_err = e
            time.sleep(2)
    return set(), f"crt.sh: {last_err}"

def src_gau(scan_id, domain):
    out_file = SCAN_DIR / f"gau_{os.getpid()}_{time.time_ns()}.txt"
    try:
        code, out, err = run_command(["gau", domain, "--o", str(out_file)], timeout=180)
        if code != 0: return set(), f"gau: exit {code}: {err[-300:]!r}"
        names = set()
        if out_file.exists():
            for line in out_file.read_text().splitlines()[:5000]:
                try: host = line.strip().split("://")[-1].split("/")[0].split(":")[0].lower()
                except IndexError: continue
                if in_scope(host, domain) and host not in names:
                    names.add(host)
                    r.rpush(f"scan:{scan_id}:live_logs", f"[gau] {host}")
        return names, None
    except Exception as e: return set(), f"gau: {e}"
    finally: out_file.unlink(missing_ok=True)

def write_subfinder_provider_config():
    config_dir = Path.home() / ".config" / "subfinder"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "provider-config.yaml"
    lines = []
    if GITHUB_TOKEN: lines.append(f"github:\n  - {GITHUB_TOKEN}")
    if SECURITYTRAILS_API_KEY: lines.append(f"securitytrails:\n  - {SECURITYTRAILS_API_KEY}")
    if VIRUSTOTAL_API_KEY: lines.append(f"virustotal:\n  - {VIRUSTOTAL_API_KEY}")
    if SHODAN_API_KEY: lines.append(f"shodan:\n  - {SHODAN_API_KEY}")
    if CENSYS_API_ID and CENSYS_API_SECRET: lines.append(f"censys:\n  - {CENSYS_API_ID}:{CENSYS_API_SECRET}")
    if NETLAS_API_KEY: lines.append(f"netlas:\n  - {NETLAS_API_KEY}")
    if C99_API_KEY: lines.append(f"c99:\n  - {C99_API_KEY}")
    if lines:
        config_path.write_text("\n".join(lines) + "\n")
        config_path.chmod(0o600)

PASSIVE_SOURCES = {
    "subfinder": src_subfinder,
    "assetfinder": src_assetfinder,
    "findomain": src_findomain,
    "crt.sh": src_crtsh,
    "gau": src_gau,
}

def run_passive_sources(scan_id, domain, selected_tools, errors):
    all_assets = set()
    active = {name: fn for name, fn in PASSIVE_SOURCES.items() if name in selected_tools}
    with ThreadPoolExecutor(max_workers=max(len(active), 1)) as pool:
        futures = {pool.submit(fn, scan_id, domain): name for name, fn in active.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                names, err = future.result()
                all_assets.update(names)
                if err: errors.append(err)
            except Exception: errors.append(f"{name}: {traceback.format_exc(limit=3)}")
    return all_assets

def run_dnsx(scan_id, subdomains, errors):
    if not subdomains: return {}, []
    in_file = SCAN_DIR / f"dnsx_{os.getpid()}_{time.time_ns()}.txt"
    in_file.write_text("\n".join(subdomains) + "\n")
    resolved = {}
    resolved_set = set()
    try:
        code, out, err = run_command_live(scan_id, ["dnsx", "-l", str(in_file), "-a", "-resp", "-json", "-silent"], timeout=180, tool_name="dnsx")
        if code != 0: errors.append(f"dnsx: exit {code}: {out[-300:]!r}")
        for line in out.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                host = data.get("host")
                ips = data.get("a") or []
                if host and ips:
                    resolved[host] = ips
                    resolved_set.add(host)
            except json.JSONDecodeError: continue
    except Exception: errors.append(f"dnsx: {traceback.format_exc(limit=3)}")
    finally: in_file.unlink(missing_ok=True)
    unresolved = sorted(set(subdomains) - resolved_set)
    return resolved, unresolved

def run_cdncheck(resolved_map, errors):
    unique_ips = sorted({ip for ips in resolved_map.values() for ip in ips})
    if not unique_ips: return {}
    in_file = SCAN_DIR / f"cdncheck_{os.getpid()}_{time.time_ns()}.txt"
    in_file.write_text("\n".join(unique_ips) + "\n")
    cdn_by_ip = {}
    try:
        # شلنا -silent و تجاهلنا طباعة الـ exit code عشان ننظف اللوج
        code, out, err = run_command(["cdncheck", "-i", str(in_file), "-json"], timeout=60)
        for line in out.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                ip = data.get("ip")
                if ip and (data.get("cdn") or data.get("waf")):
                    cdn_by_ip[ip] = data.get("cdn_name") or data.get("waf_name") or "unknown"
            except json.JSONDecodeError: continue
    except Exception: pass
    finally: in_file.unlink(missing_ok=True)
    return cdn_by_ip

def run_permutations(scan_id, domain, existing_subdomains, errors, max_permutations=20000):
    if not existing_subdomains: return set()
    seed_file = SCAN_DIR / f"alterx_{os.getpid()}_{time.time_ns()}.txt"
    seed_file.write_text("\n".join(existing_subdomains) + "\n")
    perms_file = SCAN_DIR / f"alterx_{os.getpid()}_{time.time_ns()}_out.txt"
    new_resolved = set()
    try:
        code, out, err = run_command(["alterx", "-l", str(seed_file), "-o", str(perms_file)], timeout=120)
        if code != 0: return set()
        if not perms_file.exists(): return set()
        candidates = perms_file.read_text().splitlines()[:max_permutations]
        if not candidates: return set()
        resolve_in = SCAN_DIR / f"puredns_{os.getpid()}_{time.time_ns()}.txt"
        resolve_in.write_text("\n".join(candidates) + "\n")
        code, out, err = run_command_live(scan_id, ["puredns", "resolve", str(resolve_in), "-r", "/usr/local/share/resolvers-small.txt", "--bin", "/usr/local/bin/massdns", "-l", "500", "--quiet"], timeout=600, tool_name="puredns")
        resolve_in.unlink(missing_ok=True)
        if code != 0: return set()
        for line in out.splitlines():
            host = line.strip().lower()
            if in_scope(host, domain):
                new_resolved.add(host)
    except Exception: pass
    finally:
        seed_file.unlink(missing_ok=True)
        perms_file.unlink(missing_ok=True)
    return new_resolved

def shodan_host_ports(ips, errors):
    if not SHODAN_API_KEY or not ips: return {}
    ports_by_ip = {}
    try:
        with httpx.Client(timeout=15) as client:
            for ip in ips:
                try:
                    resp = client.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": SHODAN_API_KEY})
                    if resp.status_code == 200: ports_by_ip[ip] = resp.json().get("ports", [])
                except Exception: pass
                time.sleep(1) 
    except Exception: pass
    return ports_by_ip

def run_httpx(scan_id, resolved, port_map, errors):
    if not resolved: return []
    lines = []
    for host, ips in resolved.items():
        ports = port_map.get(ips[0]) if ips else None
        if ports: lines.extend(f"{host}:{p}" for p in ports)
        else: lines.append(host) 
    targets_file = SCAN_DIR / f"{scan_id}_targets.txt"
    targets_file.write_text("\n".join(lines) + "\n")
    live = []
    try:
        code, out, err = run_command_live(scan_id, ["httpx", "-l", str(targets_file), "-silent", "-json", "-status-code", "-title", "-tech-detect", "-t", "30", "-rl", "150"], timeout=600, tool_name="httpx")
        if code == 0:
            for line in out.splitlines():
                if not line.strip(): continue
                try: live.append(json.loads(line))
                except json.JSONDecodeError: continue
    except Exception: pass
    finally: targets_file.unlink(missing_ok=True)
    return live

def run_nuclei(scan_id, live_hosts, errors):
    if not live_hosts: return []
    urls_file = SCAN_DIR / f"{scan_id}_urls.txt"
    urls = [h.get("url") for h in live_hosts if h.get("url")]
    urls_file.write_text("\n".join(urls) + "\n")
    findings = []
    try:
        code, out, err = run_command_live(scan_id, ["nuclei", "-l", str(urls_file), "-jsonl", "-silent", "-etags", "dos,fuzz", "-severity", "info,low,medium,high,critical", "-c", "25", "-rl", "100"], timeout=900, tool_name="nuclei")
        for line in out.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                findings.append({
                    "host": data.get("host"),
                    "template": data.get("template-id"),
                    "name": data.get("info", {}).get("name"),
                    "severity": data.get("info", {}).get("severity"),
                    "confidence": "potential", 
                })
            except json.JSONDecodeError: continue
    except Exception: pass
    finally: urls_file.unlink(missing_ok=True)
    return findings

def run_katana(scan_id, live_hosts, errors, max_hosts=15, depth=2):
    if not live_hosts: return []
    urls = [h.get("url") for h in live_hosts if h.get("url")][:max_hosts]
    if not urls: return []
    urls_file = SCAN_DIR / f"{scan_id}_katana_in.txt"
    urls_file.write_text("\n".join(urls) + "\n")
    endpoints = []
    try:
        code, out, err = run_command_live(scan_id, ["katana", "-list", str(urls_file), "-silent", "-jsonl", "-depth", str(depth), "-timeout", "10", "-c", "5"], timeout=600, tool_name="katana")
        for line in out.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                endpoint_url = data.get("request", {}).get("endpoint") or data.get("endpoint")
                if endpoint_url:
                    endpoints.append({
                        "url": endpoint_url,
                        "method": data.get("request", {}).get("method", "GET"),
                        "status": data.get("response", {}).get("status_code"),
                    })
            except json.JSONDecodeError: continue
    except Exception: pass
    finally: urls_file.unlink(missing_ok=True)
    return endpoints

def url_host_is_safe(url):
    try:
        host = url.split("://", 1)[-1].split("/")[0].split(":")[0]
        return is_safe_target(host)
    except Exception: return False

def run_arjun(endpoints, domain, errors, max_urls=15):
    if not endpoints: return []
    urls = [e["url"] for e in endpoints if e.get("url") and url_host_is_safe(e["url"])][:max_urls]
    if not urls: return []
    urls_file = SCAN_DIR / f"arjun_{os.getpid()}_{time.time_ns()}.txt"
    out_file = SCAN_DIR / f"arjun_{os.getpid()}_{time.time_ns()}_out.json"
    urls_file.write_text("\n".join(urls) + "\n")
    discovered = []
    try:
        code, out, err = run_command(["arjun", "-i", str(urls_file), "-oJ", str(out_file), "-t", "5"], timeout=600)
        if out_file.exists():
            data = json.loads(out_file.read_text())
            for url, params in data.items():
                for param in params: discovered.append({"url": url, "method": "GET", "status": f"param: {param}"})
    except Exception: pass
    finally:
        urls_file.unlink(missing_ok=True)
        out_file.unlink(missing_ok=True)
    return discovered

def download_js_files(endpoints, scan_id, max_files=30):
    js_urls = [e["url"] for e in endpoints if e.get("url", "").endswith(".js") and url_host_is_safe(e["url"])][:max_files]
    if not js_urls: return None
    js_dir = SCAN_DIR / f"{scan_id}_js"
    js_dir.mkdir(exist_ok=True)
    with httpx.Client(timeout=15, follow_redirects=False) as client:
        for i, url in enumerate(js_urls):
            try:
                resp = client.get(url)
                if resp.status_code == 200: (js_dir / f"file_{i}.js").write_bytes(resp.content)
            except Exception: continue
    return js_dir if any(js_dir.iterdir()) else None

def run_trufflehog(js_dir, errors):
    if not js_dir: return []
    findings = []
    try:
        code, out, err = run_command(["trufflehog", "filesystem", str(js_dir), "--json", "--no-update"], timeout=300)
        for line in out.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                findings.append({
                    "type": data.get("DetectorName", "unknown"),
                    "location": data.get("SourceMetadata", {}).get("Data", {})
                                    .get("Filesystem", {}).get("file", "unknown"),
                    "severity": "high" if data.get("Verified") else "medium",
                })
            except json.JSONDecodeError: continue
    except Exception: pass
    return findings

def run_jsluice(js_dir, errors):
    if not js_dir: return []
    findings = []
    try:
        for js_file in js_dir.glob("*.js"):
            code, out, err = run_command(["jsluice", "secrets", str(js_file)], timeout=30)
            if code != 0: continue
            for line in out.splitlines():
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    findings.append({"type": data.get("kind", "unknown"), "location": js_file.name, "severity": "medium"})
                except json.JSONDecodeError: continue
    except Exception: pass
    return findings

JS_LIBRARY_SIGNATURES = [
    ("jquery", re.compile(r"jquery[/\-]?v?(\d+\.\d+\.\d+)", re.I)),
    ("bootstrap", re.compile(r"bootstrap[/\-]?v?(\d+\.\d+\.\d+)", re.I)),
    ("react", re.compile(r"react(?:-dom)?[/\-]?v?(\d+\.\d+\.\d+)", re.I)),
    ("vue", re.compile(r"vue(?:\.js)?[/\-]?v?(\d+\.\d+\.\d+)", re.I)),
    ("angular", re.compile(r"angular[/\-]?v?(\d+\.\d+\.\d+)", re.I)),
    ("lodash", re.compile(r"lodash[/\-]?v?(\d+\.\d+\.\d+)", re.I)),
    ("moment", re.compile(r"moment[/\-]?v?(\d+\.\d+\.\d+)", re.I)),
    ("axios", re.compile(r"axios[/\-]?v?(\d+\.\d+\.\d+)", re.I)),
]

def fingerprint_js_libraries(js_dir, errors):
    if not js_dir: return []
    detected = []
    try:
        for js_file in js_dir.glob("*.js"):
            try: content = js_file.read_text(errors="ignore")[:20000] 
            except Exception: continue
            for lib_name, pattern in JS_LIBRARY_SIGNATURES:
                m = pattern.search(content)
                if m: detected.append({"script": js_file.name, "library": lib_name, "version": m.group(1)})
    except Exception: pass
    return detected

def lookup_osv_cves(library, version, errors):
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.post("https://api.osv.dev/v1/query", json={"version": version, "package": {"name": library, "ecosystem": "npm"}})
            if resp.status_code != 200: return []
            return [v.get("id") for v in resp.json().get("vulns", []) if v.get("id")]
    except Exception: return []

# --- التعديل هنا: استقبال custom_wordlist ومعالجتها ---
def run_feroxbuster(scan_id, live_hosts, errors, max_hosts=10, custom_wordlist=None):
    hosts = [h.get("url") for h in live_hosts if h.get("url")][:max_hosts]
    if not hosts: return []
    directories = []
    
    # تحديد ملف الووردليست الافتراضي أو المخصص
    wordlist_path = "/usr/local/share/wordlist-small.txt"
    tmp_wordlist = None
    
    if custom_wordlist and custom_wordlist.strip():
        tmp_wordlist = SCAN_DIR / f"custom_words_{os.getpid()}_{time.time_ns()}.txt"
        words = [w.strip() for w in custom_wordlist.replace(',', '\n').split('\n') if w.strip()]
        if words:
            tmp_wordlist.write_text("\n".join(words) + "\n")
            wordlist_path = str(tmp_wordlist)

    for base_url in hosts:
        code, out, err = run_command_live(scan_id, ["feroxbuster", "-u", base_url, "--silent", "--json", "-t", "10", "-d", "1", "-w", wordlist_path], timeout=300, tool_name="feroxbuster")
        for line in out.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                if data.get("type") == "response" and data.get("status", 0) < 400:
                    directories.append({"path": data.get("url"), "status": data.get("status"), "size": data.get("content_length")})
            except json.JSONDecodeError: continue
            
    # مسح الملف المؤقت بعد الاستخدام
    if tmp_wordlist and tmp_wordlist.exists():
        tmp_wordlist.unlink(missing_ok=True)
        
    return directories

def persist_to_supabase(scan_id, domain, tools, status, user_id, **fields):
    if not supabase: return
    row = {
        "scan_id": scan_id, "domain": domain, "status": status,
        "tools": list(tools) if tools else [], "user_id": user_id,
        "completed_at": datetime.now(timezone.utc).isoformat(), **fields,
    }
    try: supabase.table("scans").upsert(row, on_conflict="scan_id").execute()
    except Exception: pass

def diff_asset_history(project_id, user_id, current_subdomains, errors):
    if not supabase or not project_id: return [], []
    now = datetime.now(timezone.utc).isoformat()
    try:
        existing = supabase.table("asset_history").select("subdomain").eq("project_id", project_id).eq("user_id", user_id).execute()
        previously_known = {row["subdomain"] for row in existing.data}
        current_set = set(current_subdomains)
        added, removed = sorted(current_set - previously_known), sorted(previously_known - current_set)
        for s in current_set:
            supabase.table("asset_history").upsert(
                {"project_id": project_id, "user_id": user_id, "subdomain": s, "last_seen": now}, on_conflict="project_id,subdomain"
            ).execute()
        return added, removed
    except Exception: return [], []

def diff_js_dependencies(project_id, user_id, detected_libs, errors):
    if not detected_libs: return [], []
    cve_findings = []
    for lib in detected_libs:
        cves = lookup_osv_cves(lib["library"], lib["version"], errors)
        if cves: cve_findings.append({**lib, "cves": cves})
    if not supabase or not project_id: return detected_libs, cve_findings
    now = datetime.now(timezone.utc).isoformat()
    new_libs = []
    try:
        existing = supabase.table("js_dependencies").select("library_name,library_version").eq("project_id", project_id).eq("user_id", user_id).execute()
        known = {(r["library_name"], r["library_version"]) for r in existing.data}
        for lib in detected_libs:
            key = (lib["library"], lib["version"])
            if key not in known: new_libs.append(lib)
            matching_cves = next((f["cves"] for f in cve_findings if f["library"] == lib["library"] and f["version"] == lib["version"]), [])
            supabase.table("js_dependencies").upsert({
                "project_id": project_id, "user_id": user_id, "script_url": lib["script"],
                "library_name": lib["library"], "library_version": lib["version"],
                "known_cves": matching_cves, "last_seen": now,
            }, on_conflict="project_id,script_url").execute()
    except Exception: pass
    return new_libs, cve_findings

# --- التعديل هنا: تمرير custom_wordlist للدالة ---
def run_scan(scan_id, domain, tools, user_id, project_id=None, discord_webhook=None, custom_wordlist=None):
    errors = []
    tools = set(tools or [])
    update(scan_id, status="running", progress="5")
    
    if not is_safe_target(domain):
        msg = f"refused: disallowed address"
        update(scan_id, status="failed", progress="100", errors=json.dumps([msg]))
        persist_to_supabase(scan_id, domain, tools, "failed", user_id, errors=[msg])
        send_notification(f"🛑 Scan Failed: {domain}", custom_discord_webhook=discord_webhook)
        return

    update(scan_id, progress="8")
    all_assets = run_passive_sources(scan_id, domain, tools, errors)
    all_assets.add(domain)
    subdomains = sorted(x for x in all_assets if re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+" + re.escape(domain), x) or x == domain)
    update(scan_id, subdomains=json.dumps(subdomains), progress="18")

    if "permutations" in tools:
        new_hosts = run_permutations(scan_id, domain, subdomains, errors)
        if new_hosts: subdomains = sorted(set(subdomains) | new_hosts)
    update(scan_id, subdomains=json.dumps(subdomains), progress="25")

    added_assets, removed_assets = diff_asset_history(project_id, user_id, subdomains, errors)
    update(scan_id, added_assets=json.dumps(added_assets), removed_assets=json.dumps(removed_assets))

    resolved_map = {}
    unresolved = []
    if "dnsx" in tools: resolved_map, unresolved = run_dnsx(scan_id, subdomains, errors)
    else: resolved_map = {s: [] for s in subdomains}
    update(scan_id, unresolved=json.dumps(unresolved), progress="30")

    cdn_by_ip = {}
    if "cdncheck" in tools: cdn_by_ip = run_cdncheck(resolved_map, errors)
    port_map = {}
    if "shodan" in tools and resolved_map:
        unique_ips = sorted({ip for ips in resolved_map.values() for ip in ips} - set(cdn_by_ip))
        port_map = shodan_host_ports(unique_ips, errors)
    update(scan_id, progress="35")

    live_hosts = []
    if "httpx" in tools: live_hosts = run_httpx(scan_id, resolved_map, port_map, errors)
    update(scan_id, alive=json.dumps(live_hosts), progress="40")

    vulnerabilities, endpoints = [], []
    if "katana" in tools: endpoints = run_katana(scan_id, live_hosts, errors)
    update(scan_id, endpoints=json.dumps(endpoints), progress="60")

    if "nuclei" in tools: vulnerabilities.extend(run_nuclei(scan_id, live_hosts, errors))
    update(scan_id, vulnerabilities=json.dumps(vulnerabilities), progress="75")

    if "arjun" in tools:
        endpoints.extend(run_arjun(endpoints, domain, errors))
        update(scan_id, endpoints=json.dumps(endpoints))

    secrets, new_js_deps, js_cve_findings = [], [], []
    if "trufflehog" in tools or "jsluice" in tools or project_id:
        js_dir = download_js_files(endpoints, scan_id)
        try:
            if "trufflehog" in tools: secrets.extend(run_trufflehog(js_dir, errors))
            if "jsluice" in tools: secrets.extend(run_jsluice(js_dir, errors))
            detected_libs = fingerprint_js_libraries(js_dir, errors)
            new_js_deps, js_cve_findings = diff_js_dependencies(project_id, user_id, detected_libs, errors)
        finally:
            if js_dir:
                for f in js_dir.glob("*"): f.unlink(missing_ok=True)
                js_dir.rmdir()
    update(scan_id, secrets=json.dumps(secrets), new_js_dependencies=json.dumps(new_js_deps), js_cve_findings=json.dumps(js_cve_findings), progress="88")

    directories = []
    # التعديل هنا: تمرير custom_wordlist لـ run_feroxbuster
    if "feroxbuster" in tools: directories = run_feroxbuster(scan_id, live_hosts, errors, custom_wordlist=custom_wordlist)
    update(scan_id, directories=json.dumps(directories), progress="100", status="completed", errors=json.dumps(errors))

    persist_to_supabase(
        scan_id, domain, tools, "completed", user_id,
        subdomains=subdomains, unresolved=unresolved, alive=live_hosts, ports=[],
        vulnerabilities=vulnerabilities, endpoints=endpoints, secrets=secrets, directories=directories,
        added_assets=added_assets, removed_assets=removed_assets, new_js_dependencies=new_js_deps, js_cve_findings=js_cve_findings,
        project_id=project_id, errors=errors,
    )

    high_critical_vulns = [v for v in vulnerabilities if v.get("severity", "").lower() in ["high", "critical"]]
    notify_msg = f"✅ [StackSurface] Scan Completed\n🎯 Target: {domain}\n🔍 Subdomains: {len(subdomains)}\n🟢 Alive Hosts: {len(live_hosts)}\n🚨 Vulns: {len(vulnerabilities)}\n"
    if high_critical_vulns:
        notify_msg += "\n⚠️ CRITICAL/HIGH:\n" + "\n".join([f"- {v.get('name')} on {v.get('host')}" for v in high_critical_vulns[:5]])
    send_notification(notify_msg, custom_discord_webhook=discord_webhook)

def main():
    print("PTaaS worker started (Cleaned UI logic & sqlmap removed & custom wordlists active)")
    write_subfinder_provider_config()
    while True:
        item = r.blpop("ptaas:scans", timeout=0)
        if not item: continue
        _, payload = item
        job = json.loads(payload)
        scan_id, domain, tools, user_id = job["scan_id"], job["domain"], job.get("tools", []), job.get("user_id")
        project_id, discord_webhook = job.get("project_id"), job.get("discord_webhook") 
        
        # التعديل هنا: قراءة custom_wordlist من المهمة
        custom_wordlist = job.get("custom_wordlist")
        
        try:
            # التعديل هنا: تمرير custom_wordlist لدالة run_scan
            run_scan(scan_id, domain, tools, user_id, project_id=project_id, discord_webhook=discord_webhook, custom_wordlist=custom_wordlist)
        except Exception:
            tb = traceback.format_exc(limit=5)
            update(scan_id, status="failed", errors=json.dumps([tb]))
            persist_to_supabase(scan_id, domain, tools, "failed", user_id, errors=[tb])
            send_notification(f"❌ Worker Error on {domain}", custom_discord_webhook=discord_webhook)

if __name__ == "__main__":
    main()
