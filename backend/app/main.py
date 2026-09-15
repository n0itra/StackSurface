import ipaddress
import json
import logging
import os
import secrets
import socket
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import redis
from supabase import create_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("stacksurface.backend")

app = FastAPI(title="StackSurface", version="0.3.0")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

API_KEY = os.getenv("API_KEY")
if not API_KEY:
    # Fail loudly rather than silently running with no auth at all.
    raise RuntimeError(
        "API_KEY must be set in .env — this gates access to the scanning API. "
        "Generate one with: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )


def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    """Shared-secret gate on the API. This prevents anonymous network access
    to scan/project endpoints — it is NOT a per-user login system. If you
    need individual analyst accounts/audit trails later, this should be
    replaced with proper session-based auth."""
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Missing or invalid API key")

# Tools that are safe to run without explicit opt-in (passive / detection-only).
# Note: github, securitytrails, virustotal, censys, netlas, and c99 are no
# longer separate pipeline steps — subfinder natively queries them itself via
# its own provider-config.yaml when the corresponding API key env var is set
# server-side. urlscan needs no key at all; subfinder queries it by default.
DEFAULT_TOOLS = [
    "subfinder", "assetfinder", "findomain", "crt.sh", "waymore",
    "dnsx", "cdncheck", "shodan", "httpx",
]
# Active tools — must be explicitly requested by the caller since they send
# real traffic (crawling, brute-forcing, port scanning, takeover probing,
# bulk DNS resolution) to the target's infrastructure.
OPT_IN_TOOLS = {
    "nuclei", "katana", "arjun", "trufflehog", "jsluice",
    "feroxbuster", "permutations",
}
ALL_KNOWN_TOOLS = set(DEFAULT_TOOLS) | OPT_IN_TOOLS | {"anew"}

JSON_FIELDS = [
    "subdomains", "unresolved", "alive", "ports", "vulnerabilities",
    "endpoints", "secrets", "directories", "errors",
    "added_assets", "removed_assets", "new_js_dependencies", "js_cve_findings",
]


class ScanRequest(BaseModel):
    domain: str
    tools: Optional[List[str]] = None
    project_id: Optional[str] = None


class ProjectRequest(BaseModel):
    name: str
    domain: str
    monitoring: bool = False


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = domain.removeprefix("https://").removeprefix("http://")
    domain = domain.split("/")[0].split(":")[0]
    if not domain or "." not in domain or any(c.isspace() for c in domain):
        raise ValueError("Invalid domain")
    if len(domain) > 253:  # max valid DNS name length
        raise ValueError("Domain name too long")
    if "*" in domain or "@" in domain:
        raise ValueError("Wildcards and userinfo are not allowed")
    return domain


def assert_safe_target(domain: str) -> None:
    try:
        resolved_ips = {info[4][0] for info in socket.getaddrinfo(domain, None)}
    except socket.gaierror:
        raise ValueError(f"Could not resolve domain: {domain}")
    if not resolved_ips:
        raise ValueError(f"Could not resolve domain: {domain}")
    for ip_str in resolved_ips:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValueError(f"Invalid resolved address: {ip_str}")
        if (
            addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified
        ):
            raise ValueError(
                f"Domain resolves to a disallowed address ({ip_str}); "
                "internal, private, or reserved targets are not permitted"
            )


def resolve_tools(requested: Optional[List[str]]) -> List[str]:
    if not requested:
        return DEFAULT_TOOLS
    cleaned = [t for t in requested if t in ALL_KNOWN_TOOLS]
    # sqlmap and other exploit/payload tools are never included, regardless of request.
    cleaned = [t for t in cleaned if t != "sqlmap"]
    return cleaned or DEFAULT_TOOLS


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scans", dependencies=[Depends(require_api_key)])
def create_scan(req: ScanRequest):
    try:
        domain = normalize_domain(req.domain)
        assert_safe_target(domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if req.project_id:
        if not supabase:
            raise HTTPException(status_code=400, detail="Projects require Supabase to be configured")
        try:
            existing = (
                supabase.table("projects").select("project_id")
                .eq("project_id", req.project_id).execute()
            )
            if not existing.data:
                raise HTTPException(status_code=404, detail="Project not found")
        except HTTPException:
            raise
        except Exception:
            logger.exception("Supabase lookup failed while validating project_id")
            raise HTTPException(status_code=502, detail="Could not verify project — try again")

    tools = resolve_tools(req.tools)
    scan_id = uuid.uuid4().hex

    r.hset(
        f"scan:{scan_id}",
        mapping={
            "scan_id": scan_id,
            "domain": domain,
            "status": "queued",
            "progress": "0",
            "tools": json.dumps(tools),
            "project_id": req.project_id or "",
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    job = {"scan_id": scan_id, "domain": domain, "tools": tools}
    if req.project_id:
        job["project_id"] = req.project_id
    r.rpush("ptaas:scans", json.dumps(job))
    return {"scan_id": scan_id, "domain": domain, "tools": tools, "project_id": req.project_id}


@app.get("/api/scans/{scan_id}", dependencies=[Depends(require_api_key)])
def get_scan(scan_id: str):
    data = r.hgetall(f"scan:{scan_id}")
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")

    data.setdefault("status", "unknown")
    data.setdefault("progress", "0")
    for field in JSON_FIELDS:
        data[field] = json.loads(data.get(field, "[]"))
    if "tools" in data and isinstance(data["tools"], str):
        try:
            data["tools"] = json.loads(data["tools"])
        except json.JSONDecodeError:
            data["tools"] = []
            
    # --- السطران الجديدان لجلب السجلات الحية ---
    data["live_logs"] = r.lrange(f"scan:{scan_id}:live_logs", 0, -1)
    # ------------------------------------------
    
    return data


@app.post("/api/projects", dependencies=[Depends(require_api_key)])
def create_project(req: ProjectRequest):
    if not supabase:
        raise HTTPException(status_code=503, detail="Supabase is not configured")
    try:
        domain = normalize_domain(req.domain)
        assert_safe_target(domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not req.name.strip() or len(req.name) > 200:
        raise HTTPException(status_code=400, detail="Project name must be 1-200 characters")

    project_id = uuid.uuid4().hex
    try:
        supabase.table("projects").insert({
            "project_id": project_id,
            "name": req.name.strip(),
            "domain": domain,
            "monitoring": req.monitoring,
        }).execute()
    except Exception:
        logger.exception("Supabase insert failed while creating project")
        raise HTTPException(status_code=502, detail="Could not create project — try again")

    return {"project_id": project_id, "name": req.name.strip(), "domain": domain, "monitoring": req.monitoring}


@app.get("/api/projects", dependencies=[Depends(require_api_key)])
def list_projects():
    if not supabase:
        raise HTTPException(status_code=503, detail="Supabase is not configured")
    try:
        resp = supabase.table("projects").select("*").order("created_at", desc=True).execute()
        return resp.data
    except Exception:
        logger.exception("Supabase query failed while listing projects")
        raise HTTPException(status_code=502, detail="Could not load projects — try again")


@app.patch("/api/projects/{project_id}/monitoring", dependencies=[Depends(require_api_key)])
def toggle_monitoring(project_id: str, monitoring: bool):
    if not supabase:
        raise HTTPException(status_code=503, detail="Supabase is not configured")
    try:
        resp = (
            supabase.table("projects")
            .update({"monitoring": monitoring})
            .eq("project_id", project_id)
            .execute()
        )
        if not resp.data:
            raise HTTPException(status_code=404, detail="Project not found")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception:
        logger.exception("Supabase update failed while toggling monitoring")
        raise HTTPException(status_code=502, detail="Could not update project — try again")


@app.get("/api/history", dependencies=[Depends(require_api_key)])
def scan_history(limit: int = 20):
    if not supabase:
        raise HTTPException(status_code=503, detail="Supabase is not configured")
    try:
        resp = (
            supabase.table("scans")
            .select("scan_id,domain,status,tools,created_at,completed_at")
            .order("completed_at", desc=True)
            .limit(min(limit, 100))
            .execute()
        )
        return resp.data
    except Exception:
        logger.exception("Supabase query failed while loading history")
        raise HTTPException(status_code=502, detail="Could not load history — try again")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    index_path = os.path.join(STATIC_DIR, "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        html = f.read()
    # Inject the API key as a page-scoped JS variable so the frontend can
    # attach it to fetch() calls automatically. This is only as safe as the
    # dashboard's own access control — anyone who can load this page can see
    # the key. Fine for a single-team internal tool; if StackSurface is ever
    # exposed beyond your own team, put real session auth in front of this.
    injected = f'<script>window.__API_KEY__="{API_KEY}";</script>'
    return html.replace("</head>", f"{injected}</head>")


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
