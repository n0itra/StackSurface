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
from urllib.parse import quote, urlparse

import redis
import httpx

from sqlite_store import SQLiteStore

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)

db = SQLiteStore()

SCAN_DIR = Path("/scans")
SCAN_DIR.mkdir(parents=True, exist_ok=True)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")
NETLAS_API_KEY = os.getenv("NETLAS_API_KEY")
C99_API_KEY = os.getenv("C99_API_KEY")
MAX_SHODAN_REQUESTS = max(1, min(100, int(os.getenv("MAX_SHODAN_REQUESTS", "25"))))

BLOCKED_TOOLS = set()

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
    """Runs a command, reads its stdout line-by-line, parses relevant data, 
    and streams it live to Redis for the frontend UI."""
    try:
        p = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr to avoid pipe deadlocks
            text=True
        )
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
            elif tool_name == "ffuf":
                try:
                    d = json.loads(clean)
                    if d.get("status") is not None and d.get("status", 0) < 400:
                        display = d.get("url") or d.get("input", {}).get("URL")
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
        if (
            addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified
        ):
            return False
    return bool(resolved_ips)

def normalize_host_name(name, domain=None):
    if name is None:
        return None
    cleaned = str(name).strip().lower().rstrip(".")
    if not cleaned:
        return None
    cleaned = re.sub(r"^https?://", "", cleaned)
    cleaned = cleaned.split("/", 1)[0]
    cleaned = cleaned.split(":", 1)[0]
    cleaned = cleaned.lstrip("*.")
    if not cleaned or cleaned.startswith("."):
        return None
    if domain:
        domain_name = str(domain).strip().lower().rstrip(".")
        if domain_name.startswith("*."):
            domain_name = domain_name[2:]
        if cleaned == domain_name or cleaned.endswith("." + domain_name):
            return cleaned
        return None
    return cleaned


def in_scope(name: str, domain: str) -> bool:
    normalized = normalize_host_name(name, domain)
    return bool(normalized)


def dedupe_names(names, domain=None):
    seen = set()
    normalized = set()
    for name in names or []:
        candidate = normalize_host_name(name, domain)
        if candidate and candidate not in seen:
            seen.add(candidate)
            normalized.add(candidate)
    return normalized


def should_stop(scan_id):
    raw = r.hget(f"scan:{scan_id}", "stop_requested") or r.get(f"scan:{scan_id}:stop") or "0"
    return str(raw).strip().lower() in {"1", "true", "yes", "stop_requested", "stopped"}


def record_stop(scan_id, user_id=None, project_id=None, domain=None, tools=None, errors=None, progress=None):
    try:
        r.set(f"scan:{scan_id}:stop", "1")
        r.hset(f"scan:{scan_id}", mapping={"stop_requested": "1", "status": "stop_requested"})
        if progress is not None:
            r.hset(f"scan:{scan_id}", mapping={"progress": str(progress)})
        db.upsert_scan(
            scan_id,
            user_id=user_id,
            project_id=project_id,
            domain=domain,
            status="stop_requested",
            stop_requested=True,
            progress=progress,
            errors=errors or [],
            tools=list(tools or []) if tools is not None else None,
        )
    except Exception:
        pass


def finalize_stopped_scan(scan_id, domain, tools, user_id=None, project_id=None, errors=None, progress=None):
    payload = errors or []
    msg = "scan stopped by user request"
    if payload and msg not in payload:
        payload = payload + [msg]
    elif not payload:
        payload = [msg]
    update(scan_id, status="stopped", progress=str(progress if progress is not None else 100), stop_requested="1", errors=json.dumps(payload))
    checkpoint_scan(
        scan_id, domain, tools, "stopped", user_id=user_id, project_id=project_id,
        stop_requested=True, progress=progress if progress is not None else 100, errors=payload,
    )
    return True


def normalize_http_url(value, domain=None):
    if value is None:
        return None
    candidate = str(value).strip()
    if not candidate:
        return None
    candidate = candidate.rstrip(".,;)")
    candidate = candidate.rstrip("\"'")
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    if not re.match(r"^https?://", candidate, re.I):
        candidate = "https://" + candidate if "." in candidate else candidate
    try:
        parsed = urlparse(candidate)
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"}:
        return None
    host = parsed.hostname
    if not host:
        return None
    host = host.lower().rstrip('.')
    if domain:
        domain_name = str(domain).strip().lower().rstrip('.')
        if domain_name.startswith("*."):
            domain_name = domain_name[2:]
        if not (host == domain_name or host.endswith("." + domain_name)):
            return None
    try:
        if not is_safe_target(host):
            return None
    except Exception:
        return None
    return parsed._replace(netloc=host if parsed.port is None else f"{host}:{parsed.port}").geturl()

def normalize_httpx_targets(live_hosts, domain=None):
    urls = []
    seen = set()
    for item in live_hosts or []:
        candidate = None
        if isinstance(item, dict):
            candidate = item.get("url") or item.get("host")
        else:
            candidate = str(item)
        normalized = normalize_http_url(candidate, domain)
        if normalized and normalized not in seen:
            seen.add(normalized)
            urls.append(normalized)
    return urls


# ---------------------------------------------------------------------------
# Passive discovery sources
# ---------------------------------------------------------------------------

def src_subfinder(scan_id, domain):
    code, out, err = run_command_live(scan_id, ["subfinder", "-d", domain, "-silent"], tool_name="subfinder")
    if code != 0:
        return set(), f"subfinder: exit {code}: {out[-300:]!r}"
    return dedupe_names((x for x in out.splitlines() if x.strip() and not x.startswith("{")), domain), None


def src_assetfinder(scan_id, domain):
    code, out, err = run_command_live(scan_id, ["assetfinder", "--subs-only", domain], tool_name="assetfinder")
    if code != 0:
        return set(), f"assetfinder: exit {code}: {out[-300:]!r}"
    return dedupe_names((x for x in out.splitlines() if x.strip()), domain), None


def src_findomain(scan_id, domain):
    code, out, err = run_command_live(scan_id, ["findomain", "-t", domain, "-q"], timeout=120, tool_name="findomain")
    if code != 0:
        return set(), f"findomain: exit {code}: {out[-300:]!r}"
    return dedupe_names((x for x in out.splitlines() if x.strip()), domain), None


def src_crtsh(scan_id, domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(2):
        try:
            with httpx.Client(timeout=30, follow_redirects=True) as client:
                data = client.get(url).json()
            names = set()
            for row in data:
                for name in row.get("name_value", "").splitlines():
                    candidate = normalize_host_name(name, domain)
                    if candidate:
                        names.add(candidate)
                        r.rpush(f"scan:{scan_id}:live_logs", f"[crt.sh] {candidate}")
            return dedupe_names(names, domain), None
        except Exception as e:
            last_err = e
            time.sleep(2)
    return set(), f"crt.sh: {last_err}"


def src_gau(scan_id, domain):
    """Run gau for passive URL discovery and extract hostnames in-scope.

    Returns a set of hostnames and an optional error message.
    """
    try:
        code, out, err = run_command(["gau", domain], timeout=60)
        if code != 0 and not out:
            return set(), f"gau: exit {code}: {err[-300:]!r}"
        names = set()
        for line in out.splitlines():
            if not line.strip():
                continue
            try:
                host = normalize_host_name(line, domain)
            except Exception:
                continue
            if host and host not in names:
                names.add(host)
                r.rpush(f"scan:{scan_id}:live_logs", f"[gau] {host}")
        return names, None
    except FileNotFoundError:
        return set(), "gau: not installed"
    except Exception as e:
        return set(), f"gau: {e}"


def run_gau(scan_id, domain, cleaned_targets, errors):
    try:
        code, out, err = run_command(["gau", domain], timeout=90)
    except Exception as exc:
        errors.append(f"gau: {exc}")
        return []
    if code != 0 and not out:
        errors.append(f"gau: exit {code}: {err[-300:]!r}")
        return []
    urls = []
    seen_urls = set()
    normalized_targets = {normalize_http_url(item, domain) for item in cleaned_targets or [] if normalize_http_url(item, domain)}
    for line in out.splitlines():
        if not line.strip():
            continue
        normalized = normalize_http_url(line, domain)
        if not normalized:
            continue
        if normalized_targets and normalized not in normalized_targets and not any(
            urlparse(normalized).hostname == urlparse(t).hostname for t in normalized_targets
        ):
            continue
        if normalized in seen_urls:
            continue
        seen_urls.add(normalized)
        urls.append(normalized)
        r.rpush(f"scan:{scan_id}:live_logs", f"[gau] {normalized}")
    return urls


def run_dorking(scan_id, domain, errors, max_results=20):
    if not domain:
        return []
    query_terms = [
        f'site:{domain} "login"',
        f'site:{domain} "admin"',
        f'site:{domain} "filetype:pdf"',
        f'site:{domain} "internal"',
    ]
    findings = []
    seen = set()
    try:
        for query in query_terms:
            if should_stop(scan_id):
                return findings
            url = "https://duckduckgo.com/html/?q=" + quote(query, safe="")
            with httpx.Client(timeout=15, follow_redirects=True, headers={"User-Agent": "StackSurface/1.0"}) as client:
                resp = client.get(url)
            if resp.status_code != 200:
                continue
            for match in re.findall(r'<a rel="nofollow" class="result-link" href="(.*?)"', resp.text):
                decoded = match
                try:
                    decoded = str(match).replace('\x3F', '?')
                except Exception:
                    pass
                normalized = normalize_http_url(decoded, domain)
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                findings.append({
                    "type": "dorking",
                    "location": normalized,
                    "severity": "medium",
                    "source": "duckduckgo",
                })
                if len(findings) >= max_results:
                    return findings
    except Exception as exc:
        errors.append(f"dorking: {exc}")
    return findings


def write_subfinder_provider_config():
    config_dir = Path.home() / ".config" / "subfinder"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "provider-config.yaml"

    lines = []
    if GITHUB_TOKEN:
        lines.append(f"github:\n  - {GITHUB_TOKEN}")
    if SECURITYTRAILS_API_KEY:
        lines.append(f"securitytrails:\n  - {SECURITYTRAILS_API_KEY}")
    if VIRUSTOTAL_API_KEY:
        lines.append(f"virustotal:\n  - {VIRUSTOTAL_API_KEY}")
    if SHODAN_API_KEY:
        lines.append(f"shodan:\n  - {SHODAN_API_KEY}")
    if CENSYS_API_ID and CENSYS_API_SECRET:
        lines.append(f"censys:\n  - {CENSYS_API_ID}:{CENSYS_API_SECRET}")
    if NETLAS_API_KEY:
        lines.append(f"netlas:\n  - {NETLAS_API_KEY}")
    if C99_API_KEY:
        lines.append(f"c99:\n  - {C99_API_KEY}")

    if lines:
        config_path.write_text("\n".join(lines) + "\n")
        config_path.chmod(0o600)
        print(f"[subfinder] wrote provider-config.yaml with {len(lines)} source(s) configured")
    else:
        print("[subfinder] no OSINT API keys set — running with free sources only")


PASSIVE_SOURCES = {
    "subfinder": src_subfinder,
    "assetfinder": src_assetfinder,
    "findomain": src_findomain,
    "crt.sh": src_crtsh,
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
                if err:
                    errors.append(err)
                if names:
                    all_assets.update(dedupe_names(names, domain))
            except Exception:
                errors.append(f"{name}: {traceback.format_exc(limit=3)}")

    return dedupe_names(all_assets, domain)


def run_dnsx(scan_id, subdomains, errors, domain=None):
    if not subdomains:
        return {}, []
    normalized = sorted(dedupe_names(subdomains, domain))
    in_file = SCAN_DIR / f"dnsx_{os.getpid()}_{time.time_ns()}.txt"
    in_file.write_text("\n".join(normalized) + "\n")
    resolved = {}
    resolved_set = set()
    try:
        code, out, err = run_command_live(
            scan_id, ["dnsx", "-l", str(in_file), "-a", "-resp", "-json", "-silent"],
            timeout=180, tool_name="dnsx"
        )
        if code != 0:
            errors.append(f"dnsx: exit {code}: {out[-300:]!r}")
        for line in out.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                host = normalize_host_name(data.get("host"), domain)
                ips = data.get("a") or []
                if host and ips:
                    resolved[host] = ips
                    resolved_set.add(host)
            except json.JSONDecodeError:
                continue
    except Exception:
        errors.append(f"dnsx: {traceback.format_exc(limit=3)}")
    finally:
        in_file.unlink(missing_ok=True)

    unresolved = sorted(set(normalized) - resolved_set)
    return resolved, unresolved


def run_cdncheck(resolved_map, errors):
    unique_ips = sorted({ip for ips in resolved_map.values() for ip in ips})
    if not unique_ips:
        return {}
    in_file = SCAN_DIR / f"cdncheck_{os.getpid()}_{time.time_ns()}.txt"
    in_file.write_text("\n".join(unique_ips) + "\n")
    cdn_by_ip = {}
    try:
        code, out, err = run_command(
            ["cdncheck", "-l", str(in_file), "-json", "-silent"], timeout=60
        )
        if code != 0:
            errors.append(f"cdncheck: exit {code}: {err[-300:]!r}")
        for line in out.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                ip = data.get("ip")
                if ip and (data.get("cdn") or data.get("waf")):
                    cdn_by_ip[ip] = data.get("cdn_name") or data.get("waf_name") or "unknown"
            except json.JSONDecodeError:
                continue
    except Exception:
        errors.append(f"cdncheck: {traceback.format_exc(limit=3)}")
    finally:
        in_file.unlink(missing_ok=True)
    return cdn_by_ip


def run_permutations(scan_id, domain, existing_subdomains, errors, max_permutations=20000):
    if not existing_subdomains:
        return set()

    seed_file = SCAN_DIR / f"alterx_{os.getpid()}_{time.time_ns()}.txt"
    seed_file.write_text("\n".join(existing_subdomains) + "\n")
    perms_file = SCAN_DIR / f"alterx_{os.getpid()}_{time.time_ns()}_out.txt"
    new_resolved = set()
    try:
        code, out, err = run_command(
            ["alterx", "-l", str(seed_file), "-o", str(perms_file)], timeout=120
        )
        if code != 0:
            errors.append(f"alterx: exit {code}: {err[-300:]!r}")
            return set()

        if not perms_file.exists():
            return set()
        candidates = perms_file.read_text().splitlines()[:max_permutations]
        if not candidates:
            return set()

        resolve_in = SCAN_DIR / f"puredns_{os.getpid()}_{time.time_ns()}.txt"
        resolve_in.write_text("\n".join(candidates) + "\n")
        code, out, err = run_command_live(
            scan_id, ["puredns", "resolve", str(resolve_in), "-r", "/usr/local/share/resolvers-small.txt", "--quiet"],
            timeout=600, tool_name="puredns"
        )
        resolve_in.unlink(missing_ok=True)
        if code != 0:
            errors.append(f"puredns: exit {code}: {out[-300:]!r}")
            return set()
        for line in out.splitlines():
            host = line.strip().lower()
            if in_scope(host, domain):
                new_resolved.add(host)
    except Exception:
        errors.append(f"permutations: {traceback.format_exc(limit=3)}")
    finally:
        seed_file.unlink(missing_ok=True)
        perms_file.unlink(missing_ok=True)
    return new_resolved


def shodan_host_ports(scan_id, ips, errors):
    if not SHODAN_API_KEY or not ips:
        return {}
    ports_by_ip = {}
    limited_ips = list(dict.fromkeys(ips))[:MAX_SHODAN_REQUESTS]
    try:
        with httpx.Client(timeout=15) as client:
            for ip in limited_ips:
                if should_stop(scan_id):
                    break
                try:
                    resp = client.get(
                        f"https://api.shodan.io/shodan/host/{ip}",
                        params={"key": SHODAN_API_KEY},
                    )
                    if resp.status_code == 200:
                        payload = resp.json()
                        ports = payload.get("ports") or []
                        if ports:
                            ports_by_ip[ip] = ports
                    elif resp.status_code != 404:
                        errors.append(f"shodan-host({ip}): HTTP {resp.status_code}")
                except Exception as e:
                    errors.append(f"shodan-host({ip}): {e}")
                time.sleep(0.6)
    except Exception:
        errors.append(f"shodan-host: {traceback.format_exc(limit=3)}")
    return ports_by_ip


def run_httpx(scan_id, resolved, port_map, errors):
    if not resolved:
        return []
    lines = []
    for host, ips in resolved.items():
        ports = port_map.get(ips[0]) if ips else None
        if ports:
            lines.extend(f"{host}:{p}" for p in ports)
        else:
            lines.append(host)
    if not lines:
        return []
    targets_file = SCAN_DIR / f"{scan_id}_targets.txt"
    targets_file.write_text("\n".join(lines) + "\n")
    live = []
    try:
        code, out, err = run_command_live(
            scan_id,
            ["httpx", "-l", str(targets_file), "-silent", "-json", "-status-code", "-title", "-tech-detect", "-timeout", "10", "-max-host-error", "3", "-no-color"],
            timeout=600,
            tool_name="httpx",
        )
        if code == 0:
            for line in out.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("url") or data.get("host")
                    if not url:
                        continue
                    parsed = normalize_http_url(url)
                    if parsed:
                        data["url"] = parsed
                        if data.get("host") is None:
                            data["host"] = urlparse(parsed).hostname
                        live.append(data)
                except json.JSONDecodeError:
                    continue
        else:
            errors.append(f"httpx: exit {code}: stdout/err={out[-500:]!r}")
    except Exception:
        errors.append(f"httpx: {traceback.format_exc(limit=3)}")
    finally:
        targets_file.unlink(missing_ok=True)
    return live

def run_nuclei(scan_id, live_hosts, errors):
    if not live_hosts:
        return []
    urls_file = SCAN_DIR / f"{scan_id}_urls.txt"
    urls = [h.get("url") for h in live_hosts if h.get("url")]
    urls_file.write_text("\n".join(urls) + "\n")
    findings = []
    try:
        code, out, err = run_command_live(
            scan_id, ["nuclei", "-l", str(urls_file), "-jsonl", "-silent", "-etags", "dos,fuzz", "-severity", "info,low,medium,high,critical"],
            timeout=900, tool_name="nuclei"
        )
        if code not in (0, 1): 
            errors.append(f"nuclei: exit {code}: {out[-300:]!r}")
        for line in out.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "host": data.get("host"),
                    "template": data.get("template-id"),
                    "name": data.get("info", {}).get("name"),
                    "severity": data.get("info", {}).get("severity"),
                    "confidence": "potential", 
                })
            except json.JSONDecodeError:
                continue
    except Exception:
        errors.append(f"nuclei: {traceback.format_exc(limit=3)}")
    finally:
        urls_file.unlink(missing_ok=True)
    return findings


def run_katana(scan_id, live_hosts, errors, max_hosts=15, depth=2):
    urls = normalize_httpx_targets(live_hosts)
    if not urls:
        return []
    urls = urls[:max_hosts]
    urls_file = SCAN_DIR / f"{scan_id}_katana_in.txt"
    urls_file.write_text("\n".join(urls) + "\n")
    endpoints = []
    seen_urls = set()
    try:
        code, out, err = run_command_live(
            scan_id,
            ["katana", "-list", str(urls_file), "-silent", "-jsonl", "-depth", str(depth), "-timeout", "10", "-c", "10", "-headless"],
            timeout=180,
            tool_name="katana",
        )
        if code not in (0, 1):
            errors.append(f"katana: exit {code}: {out[-300:]!r}")
        for line in out.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            req = data.get("request") if isinstance(data.get("request"), dict) else {}
            endpoint_url = req.get("endpoint") or data.get("endpoint") or data.get("url")
            if not endpoint_url or not isinstance(endpoint_url, str):
                continue
            endpoint_url = normalize_http_url(endpoint_url)
            if not endpoint_url:
                continue
            method = req.get("method") or data.get("method") or "GET"
            status = (req.get("response") or {}).get("status_code") or data.get("response", {}).get("status_code") or data.get("status")
            if endpoint_url in seen_urls:
                continue
            seen_urls.add(endpoint_url)
            endpoints.append({
                "url": endpoint_url,
                "method": str(method).upper(),
                "status": status,
            })
    except FileNotFoundError:
        errors.append("katana: not installed")
    except TimeoutError:
        errors.append("katana: timed out after 180s")
    except Exception:
        errors.append(f"katana: {traceback.format_exc(limit=3)}")
    finally:
        urls_file.unlink(missing_ok=True)
    return endpoints

def url_host_is_safe(url):
    try:
        host = url.split("://", 1)[-1].split("/")[0].split(":")[0]
        return is_safe_target(host)
    except Exception:
        return False


def run_arjun(endpoints, domain, errors, max_urls=15):
    if not endpoints:
        return []
    urls = [e["url"] for e in endpoints if e.get("url") and url_host_is_safe(e["url"])][:max_urls]
    if not urls:
        return []
    urls_file = SCAN_DIR / f"arjun_{os.getpid()}_{time.time_ns()}.txt"
    out_file = SCAN_DIR / f"arjun_{os.getpid()}_{time.time_ns()}_out.json"
    urls_file.write_text("\n".join(urls) + "\n")
    discovered = []
    try:
        code, out, err = run_command(
            ["arjun", "-i", str(urls_file), "-oJ", str(out_file), "-t", "5"],
            timeout=600,
        )
        if code != 0:
            errors.append(f"arjun: exit {code}: {err[-300:]!r}")
        if out_file.exists():
            data = json.loads(out_file.read_text())
            for url, params in data.items():
                for param in params:
                    discovered.append({
                        "url": url,
                        "method": "GET",
                        "status": f"param: {param}",
                    })
    except Exception:
        errors.append(f"arjun: {traceback.format_exc(limit=3)}")
    finally:
        urls_file.unlink(missing_ok=True)
        out_file.unlink(missing_ok=True)
    return discovered


def download_js_files(endpoints, scan_id, max_files=30):
    js_urls = [
        e["url"] for e in endpoints
        if e.get("url", "").endswith(".js") and url_host_is_safe(e["url"])
    ][:max_files]
    if not js_urls:
        return None
    js_dir = SCAN_DIR / f"{scan_id}_js"
    js_dir.mkdir(exist_ok=True)
    with httpx.Client(timeout=15, follow_redirects=False) as client:
        for i, url in enumerate(js_urls):
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    (js_dir / f"file_{i}.js").write_bytes(resp.content)
            except Exception:
                continue
    return js_dir if any(js_dir.iterdir()) else None


def run_trufflehog(js_dir, errors):
    if not js_dir:
        return []
    findings = []
    try:
        code, out, err = run_command(
            ["trufflehog", "filesystem", str(js_dir), "--json", "--no-update"],
            timeout=300,
        )
        if code not in (0, 1, 183):  
            errors.append(f"trufflehog: exit {code}: {err[-300:]!r}")
        for line in out.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "type": data.get("DetectorName", "unknown"),
                    "location": data.get("SourceMetadata", {}).get("Data", {})
                                    .get("Filesystem", {}).get("file", "unknown"),
                    "severity": "high" if data.get("Verified") else "medium",
                })
            except json.JSONDecodeError:
                continue
    except Exception:
        errors.append(f"trufflehog: {traceback.format_exc(limit=3)}")
    return findings


def run_jsluice(js_dir, errors):
    if not js_dir:
        return []
    findings = []
    try:
        for js_file in js_dir.glob("*.js"):
            code, out, err = run_command(["jsluice", "secrets", str(js_file)], timeout=30)
            if code != 0:
                errors.append(f"jsluice({js_file.name}): exit {code}: {err[-200:]!r}")
                continue
            for line in out.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    findings.append({
                        "type": data.get("kind", "unknown"),
                        "location": js_file.name,
                        "severity": "medium",
                    })
                except json.JSONDecodeError:
                    continue
    except Exception:
        errors.append(f"jsluice: {traceback.format_exc(limit=3)}")
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
    if not js_dir:
        return []
    detected = []
    try:
        for js_file in js_dir.glob("*.js"):
            try:
                content = js_file.read_text(errors="ignore")[:20000] 
            except Exception:
                continue
            for lib_name, pattern in JS_LIBRARY_SIGNATURES:
                m = pattern.search(content)
                if m:
                    detected.append({
                        "script": js_file.name,
                        "library": lib_name,
                        "version": m.group(1),
                    })
    except Exception:
        errors.append(f"js-fingerprint: {traceback.format_exc(limit=3)}")
    return detected


def lookup_osv_cves(library, version, errors):
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.post(
                "https://api.osv.dev/v1/query",
                json={"version": version, "package": {"name": library, "ecosystem": "npm"}},
            )
            if resp.status_code != 200:
                return []
            vulns = resp.json().get("vulns", [])
            return [v.get("id") for v in vulns if v.get("id")]
    except Exception as e:
        errors.append(f"osv-lookup({library}): {e}")
        return []


def run_ffuf(scan_id, live_hosts, errors, max_hosts=10):
    hosts = [h.get("url") for h in live_hosts if h.get("url")][:max_hosts]
    if not hosts:
        return []
    directories = []
    for base_url in hosts:
        code, out, err = run_command_live(
            scan_id, ["ffuf", "-u", f"{base_url}/FUZZ", "-w", "/usr/local/share/wordlist-small.txt", "-fr", "-json", "-t", "20", "-ac"],
            timeout=300, tool_name="ffuf"
        )
        if code != 0:
            errors.append(f"ffuf({base_url}): exit {code}: {out[-300:]!r}")
            continue
        for line in out.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if data.get("status") is None:
                continue
            if data.get("status", 0) < 400:
                directories.append({
                    "path": data.get("url") or data.get("input", {}).get("URL"),
                    "status": data.get("status"),
                    "size": data.get("length"),
                })
    return directories


def checkpoint_scan(scan_id, domain, tools, status, user_id=None, project_id=None, **fields):
    """Persist a partial scan without replacing fields written by earlier stages."""
    fields.pop("progress", None)
    payload = {"status": status, **fields}
    if user_id is not None:
        payload["user_id"] = user_id
    if project_id is not None:
        payload["project_id"] = project_id
    if domain is not None:
        payload["domain"] = domain
    if tools is not None:
        payload["tools"] = list(tools) if isinstance(tools, (list, tuple, set)) else tools
    try:
        db.upsert_scan(scan_id, **payload)
    except Exception:
        print(f"[sqlite] failed to persist scan {scan_id}: {traceback.format_exc(limit=3)}")


def persist_to_sqlite(scan_id, domain, tools, status, user_id=None, project_id=None, **fields):
    checkpoint_scan(
        scan_id,
        domain,
        tools,
        status,
        user_id=user_id,
        project_id=project_id,
        completed_at=datetime.now(timezone.utc).isoformat(),
        **fields,
    )


def diff_asset_history(project_id, current_subdomains, errors):
    if not project_id:
        return [], []
    try:
        return db.diff_asset_history(project_id, current_subdomains, errors)
    except Exception:
        errors.append(f"asset-history-diff: {traceback.format_exc(limit=3)}")
        return [], []


def diff_js_dependencies(project_id, detected_libs, errors):
    if not detected_libs:
        return [], []

    cve_findings = []
    for lib in detected_libs:
        cves = lookup_osv_cves(lib["library"], lib["version"], errors)
        if cves:
            cve_findings.append({**lib, "cves": cves})

    if not project_id:
        return detected_libs, cve_findings

    try:
        return db.diff_js_dependencies(project_id, detected_libs, errors)
    except Exception:
        errors.append(f"js-deps-diff: {traceback.format_exc(limit=3)}")
        return detected_libs, cve_findings


def normalize_endpoint_candidates(*sources):
    merged = []
    seen = set()
    for source in sources:
        for item in source or []:
            if isinstance(item, dict):
                url = item.get("url") or item.get("endpoint")
                method = item.get("method") or "GET"
                status = item.get("status")
            else:
                url = item
                method = "GET"
                status = None
            normalized = normalize_http_url(url)
            if not normalized:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            merged.append({"url": normalized, "method": method or "GET", "status": status})
    return merged


def run_scan(scan_id, domain, tools, project_id=None, user_id=None):
    errors = []
    tools = set(tools or [])

    update(scan_id, status="running", progress="5")
    checkpoint_scan(scan_id, domain, tools, "running", user_id=user_id, project_id=project_id, progress=5, errors=errors)

    if should_stop(scan_id):
        return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=5)

    if not is_safe_target(domain):
        msg = f"refused: {domain} resolves to a disallowed address"
        update(scan_id, status="failed", progress="100", errors=json.dumps([msg]))
        checkpoint_scan(
            scan_id, domain, tools, "failed", user_id=user_id, project_id=project_id,
            progress=100, errors=[msg],
        )
        return

    blocked = sorted((tools & BLOCKED_TOOLS))
    for t in blocked:
        errors.append(f"{t}: disabled ? active exploit/payload development is not automated")

    update(scan_id, progress="8")
    if should_stop(scan_id):
        return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=8)
    all_assets = run_passive_sources(scan_id, domain, tools, errors)
    all_assets.add(domain)

    subdomains = sorted(
        x for x in all_assets
        if re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+" + re.escape(domain), x)
        or x == domain
    )
    update(scan_id, subdomains=json.dumps(subdomains), progress="18")
    checkpoint_scan(
        scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
        subdomains=subdomains, progress=18, errors=errors,
    )
    if should_stop(scan_id):
        return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=18)

    if "permutations" in tools:
        new_hosts = run_permutations(scan_id, domain, subdomains, errors)
        if new_hosts:
            subdomains = sorted(set(subdomains) | new_hosts)
    update(scan_id, subdomains=json.dumps(subdomains), progress="25")
    checkpoint_scan(
        scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
        subdomains=subdomains, progress=25, errors=errors,
    )
    if should_stop(scan_id):
        return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=25)

    added_assets, removed_assets = diff_asset_history(project_id, subdomains, errors)
    update(
        scan_id,
        added_assets=json.dumps(added_assets),
        removed_assets=json.dumps(removed_assets),
    )
    checkpoint_scan(
        scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
        added_assets=added_assets, removed_assets=removed_assets, progress=25, errors=errors,
    )

    resolved_map = {}
    unresolved = []
    if "dnsx" in tools:
        resolved_map, unresolved = run_dnsx(scan_id, subdomains, errors, domain=domain)
    else:
        resolved_map = {s: [] for s in subdomains}
    update(scan_id, unresolved=json.dumps(unresolved), progress="30")
    checkpoint_scan(
        scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
        unresolved=unresolved, progress=30, errors=errors,
    )
    if should_stop(scan_id):
        return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=30)

    cdn_by_ip = {}
    if "cdncheck" in tools:
        cdn_by_ip = run_cdncheck(resolved_map, errors)
    if cdn_by_ip:
        errors.append(f"cdncheck: {len(cdn_by_ip)} IP(s) identified as CDN/WAF-fronted")

    port_map = {}
    if "shodan" in tools and resolved_map and SHODAN_API_KEY:
        unique_ips = sorted({ip for ips in resolved_map.values() for ip in ips} - set(cdn_by_ip))
        port_map = shodan_host_ports(scan_id, unique_ips, errors)
    update(scan_id, ports=json.dumps(port_map), progress="35")
    checkpoint_scan(
        scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
        ports=port_map, progress=35, errors=errors,
    )
    if should_stop(scan_id):
        return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=35)

    live_hosts = []
    if "httpx" in tools:
        live_hosts = run_httpx(scan_id, resolved_map, port_map, errors)
    normalized_live_urls = normalize_httpx_targets(live_hosts, domain)
    update(scan_id, alive=json.dumps(live_hosts), progress="40")
    checkpoint_scan(
        scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
        alive=live_hosts, progress=40, errors=errors,
    )
    if should_stop(scan_id):
        return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=40)

    gau_urls = []
    if "gau" in tools:
        gau_urls = run_gau(scan_id, domain, normalized_live_urls, errors)
        if should_stop(scan_id):
            return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=45)
    update(scan_id, progress="45")
    checkpoint_scan(
        scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
        progress=45, errors=errors,
    )

    dorking = []
    if "dorking" in tools:
        dorking = run_dorking(scan_id, domain, errors)
        if should_stop(scan_id):
            return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=50)

    vulnerabilities = []
    endpoints = normalize_endpoint_candidates(gau_urls, normalized_live_urls)
    if "katana" in tools:
        katana_endpoints = run_katana(scan_id, live_hosts, errors)
        endpoints = normalize_endpoint_candidates(endpoints, katana_endpoints)
    update(scan_id, endpoints=json.dumps(endpoints), progress="60")
    checkpoint_scan(
        scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
        endpoints=endpoints, progress=60, errors=errors,
    )
    if should_stop(scan_id):
        return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=60)

    if "nuclei" in tools:
        vulnerabilities.extend(run_nuclei(scan_id, live_hosts, errors))
    update(scan_id, vulnerabilities=json.dumps(vulnerabilities), progress="75")
    checkpoint_scan(
        scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
        vulnerabilities=vulnerabilities, progress=75, errors=errors,
    )
    if should_stop(scan_id):
        return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=75)

    if "arjun" in tools:
        endpoints.extend(run_arjun(endpoints, domain, errors))
        endpoints = normalize_endpoint_candidates(endpoints)
        update(scan_id, endpoints=json.dumps(endpoints))
        checkpoint_scan(
            scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
            endpoints=endpoints, errors=errors,
        )

    secrets = []
    new_js_deps = []
    js_cve_findings = []
    if dorking:
        secrets.extend(dorking)
    if "trufflehog" in tools or "jsluice" in tools or project_id:
        js_dir = download_js_files(endpoints, scan_id)
        try:
            if "trufflehog" in tools:
                secrets.extend(run_trufflehog(js_dir, errors))
            if "jsluice" in tools:
                secrets.extend(run_jsluice(js_dir, errors))
            detected_libs = fingerprint_js_libraries(js_dir, errors)
            new_js_deps, js_cve_findings = diff_js_dependencies(project_id, detected_libs, errors)
        finally:
            if js_dir:
                for f in js_dir.glob("*"):
                    f.unlink(missing_ok=True)
                js_dir.rmdir()
    update(
        scan_id,
        secrets=json.dumps(secrets),
        new_js_dependencies=json.dumps(new_js_deps),
        js_cve_findings=json.dumps(js_cve_findings),
        progress="88",
    )
    checkpoint_scan(
        scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
        secrets=secrets, new_js_dependencies=new_js_deps,
        js_cve_findings=js_cve_findings, progress=88, errors=errors,
    )
    if should_stop(scan_id):
        return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=88)

    directories = []
    if "ffuf" in tools:
        directories = run_ffuf(scan_id, live_hosts, errors)
    update(scan_id, directories=json.dumps(directories), progress="97")
    checkpoint_scan(
        scan_id, domain, tools, "running", user_id=user_id, project_id=project_id,
        directories=directories, progress=97, errors=errors,
    )
    if should_stop(scan_id):
        return finalize_stopped_scan(scan_id, domain, tools, user_id=user_id, project_id=project_id, errors=errors, progress=97)

    update(
        scan_id,
        progress="100",
        status="completed",
        errors=json.dumps(errors),
    )

    persist_to_sqlite(
        scan_id, domain, tools, "completed",
        subdomains=subdomains, unresolved=unresolved, alive=live_hosts, ports=port_map,
        vulnerabilities=vulnerabilities, endpoints=endpoints,
        secrets=secrets, directories=directories,
        added_assets=added_assets, removed_assets=removed_assets,
        new_js_dependencies=new_js_deps, js_cve_findings=js_cve_findings,
        project_id=project_id,
        user_id=user_id,
        errors=errors,
    )


def main():
    print("PTaaS worker started")
    write_subfinder_provider_config()
    while True:
        item = r.blpop("ptaas:scans", timeout=0)
        if not item:
            continue
        _, payload = item
        job = json.loads(payload)
        scan_id = job["scan_id"]
        domain = job["domain"]
        tools = job.get("tools", [])
        project_id = job.get("project_id")
        user_id = job.get("user_id")
        try:
            run_scan(scan_id, domain, tools, project_id=project_id, user_id=user_id)
        except Exception:
            tb = traceback.format_exc(limit=5)
            update(scan_id, status="failed", errors=json.dumps([tb]))
            checkpoint_scan(
                scan_id, domain, tools, "failed", user_id=user_id, project_id=project_id,
                progress=100, errors=[tb],
            )


if __name__ == "__main__":
    main()