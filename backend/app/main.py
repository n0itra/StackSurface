import ipaddress
import json
import logging
import os
import socket
import uuid
from datetime import datetime, timezone
from typing import List, Optional

import redis
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from supabase import create_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("stacksurface.backend")
app = FastAPI(title="StackSurface", version="0.4.0")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)
SUPABASE_URL = os.getenv("SUPABASE_URL")
# SUPABASE_SERVICE_ROLE_KEY is server-only. SUPABASE_KEY is retained as a
# backwards-compatible server-side alias, never sent to the browser.
SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
AUTH_KEY = os.getenv("SUPABASE_ANON_KEY") or SERVICE_KEY
data_client = create_client(SUPABASE_URL, SERVICE_KEY) if SUPABASE_URL and SERVICE_KEY else None
auth_client = create_client(SUPABASE_URL, AUTH_KEY) if SUPABASE_URL and AUTH_KEY else None
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

DEFAULT_TOOLS = ["subfinder", "assetfinder", "findomain", "crt.sh", "waymore",
                 "dnsx", "cdncheck", "shodan", "httpx"]
OPT_IN_TOOLS = {"nuclei", "katana", "arjun", "trufflehog", "jsluice",
                "feroxbuster", "permutations"}
ALL_KNOWN_TOOLS = set(DEFAULT_TOOLS) | OPT_IN_TOOLS | {"anew"}
JSON_FIELDS = ["subdomains", "unresolved", "alive", "ports", "vulnerabilities",
               "endpoints", "secrets", "directories", "errors", "added_assets",
               "removed_assets", "new_js_dependencies", "js_cve_findings"]


class Credentials(BaseModel):
    email: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class ScanRequest(BaseModel):
    domain: str
    tools: Optional[List[str]] = None
    project_id: Optional[str] = None


class ProjectRequest(BaseModel):
    name: str
    domain: str
    monitoring: bool = False


def require_user(authorization: Optional[str] = Header(default=None)):
    """Validate the Supabase access token server-side; never trust client IDs."""
    if not auth_client or not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        response = auth_client.auth.get_user(token)
        user = response.user
        if not user or not user.id:
            raise ValueError("invalid user")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired session")


def require_data_client():
    if not data_client:
        raise HTTPException(status_code=503, detail="Supabase is not configured")
    return data_client


@app.post("/api/auth/signup")
def signup(credentials: Credentials):
    if not auth_client:
        raise HTTPException(status_code=503, detail="Supabase is not configured")
    if "@" not in credentials.email or len(credentials.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    try:
        result = auth_client.auth.sign_up({"email": credentials.email, "password": credentials.password})
        return {"user": result.user.model_dump() if result.user else None,
                "session": result.session.model_dump() if result.session else None}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/auth/login")
def login(credentials: Credentials):
    if not auth_client:
        raise HTTPException(status_code=503, detail="Supabase is not configured")
    try:
        result = auth_client.auth.sign_in_with_password(
            {"email": credentials.email, "password": credentials.password})
        return {"user": result.user.model_dump(), "session": result.session.model_dump()}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid email or password")


@app.post("/api/auth/logout")
def logout(user=Depends(require_user)):
    # Access tokens are short-lived and are revoked/removed by the client.
    return {"ok": True}


@app.post("/api/auth/refresh")
def refresh_session(request: RefreshRequest):
    if not auth_client:
        raise HTTPException(status_code=503, detail="Supabase is not configured")
    try:
        result = auth_client.auth.refresh_session(request.refresh_token)
        if not result.session:
            raise ValueError("No session returned")
        return {"user": result.user.model_dump(), "session": result.session.model_dump()}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower().removeprefix("https://").removeprefix("http://")
    domain = domain.split("/")[0].split(":")[0]
    if not domain or "." not in domain or any(c.isspace() for c in domain) or len(domain) > 253:
        raise ValueError("Invalid domain")
    if "*" in domain or "@" in domain:
        raise ValueError("Wildcards and userinfo are not allowed")
    return domain


def assert_safe_target(domain: str) -> None:
    try:
        resolved_ips = {info[4][0] for info in socket.getaddrinfo(domain, None)}
    except socket.gaierror:
        raise ValueError(f"Could not resolve domain: {domain}")
    for ip_str in resolved_ips:
        addr = ipaddress.ip_address(ip_str)
        if (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
                or addr.is_multicast or addr.is_unspecified):
            raise ValueError(f"Domain resolves to a disallowed address ({ip_str})")


def resolve_tools(requested):
    if not requested:
        return DEFAULT_TOOLS
    cleaned = [tool for tool in requested if tool in ALL_KNOWN_TOOLS and tool != "sqlmap"]
    return cleaned or DEFAULT_TOOLS


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scans")
def create_scan(req: ScanRequest, user=Depends(require_user), db=Depends(require_data_client)):
    try:
        domain = normalize_domain(req.domain)
        assert_safe_target(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if req.project_id:
        result = db.table("projects").select("project_id,domain").eq(
            "project_id", req.project_id).eq("user_id", user.id).execute()
        if not result.data:
            raise HTTPException(status_code=404, detail="Project not found")
    tools, scan_id = resolve_tools(req.tools), uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    r.hset(f"scan:{scan_id}", mapping={"scan_id": scan_id, "user_id": user.id,
        "domain": domain, "status": "queued", "progress": "0",
        "tools": json.dumps(tools), "project_id": req.project_id or "", "created_at": now})
    job = {"scan_id": scan_id, "user_id": user.id, "domain": domain, "tools": tools}
    if req.project_id:
        job["project_id"] = req.project_id
    r.rpush("ptaas:scans", json.dumps(job))
    return {"scan_id": scan_id, "domain": domain, "tools": tools, "project_id": req.project_id}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, user=Depends(require_user)):
    data = r.hgetall(f"scan:{scan_id}")
    if not data or data.get("user_id") != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    for field in JSON_FIELDS:
        try:
            data[field] = json.loads(data.get(field, "[]"))
        except json.JSONDecodeError:
            data[field] = []
    try:
        data["tools"] = json.loads(data.get("tools", "[]"))
    except json.JSONDecodeError:
        data["tools"] = []
    data["live_logs"] = r.lrange(f"scan:{scan_id}:live_logs", 0, -1)
    return data


@app.post("/api/projects")
def create_project(req: ProjectRequest, user=Depends(require_user), db=Depends(require_data_client)):
    try:
        domain = normalize_domain(req.domain)
        assert_safe_target(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not req.name.strip() or len(req.name) > 200:
        raise HTTPException(status_code=400, detail="Project name must be 1-200 characters")
    row = {"project_id": uuid.uuid4().hex, "user_id": user.id, "name": req.name.strip(),
           "domain": domain, "monitoring": req.monitoring}
    try:
        result = db.table("projects").insert(row).execute()
        return result.data[0]
    except Exception:
        logger.exception("Project insert failed")
        raise HTTPException(status_code=502, detail="Could not create project — try again")


@app.get("/api/projects")
def list_projects(user=Depends(require_user), db=Depends(require_data_client)):
    try:
        return db.table("projects").select("*").eq("user_id", user.id).order(
            "created_at", desc=True).execute().data
    except Exception:
        raise HTTPException(status_code=502, detail="Could not load projects — try again")


@app.patch("/api/projects/{project_id}/monitoring")
def toggle_monitoring(project_id: str, monitoring: bool, user=Depends(require_user),
                       db=Depends(require_data_client)):
    result = db.table("projects").update({"monitoring": monitoring}).eq(
        "project_id", project_id).eq("user_id", user.id).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Project not found")
    return result.data[0]


@app.get("/api/history")
def scan_history(limit: int = 20, user=Depends(require_user), db=Depends(require_data_client)):
    result = db.table("scans").select(
        "scan_id,domain,status,tools,project_id,created_at,completed_at").eq(
        "user_id", user.id).order("completed_at", desc=True).limit(min(max(limit, 1), 100)).execute()
    return result.data


@app.get("/", response_class=HTMLResponse)
def dashboard():
    with open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8") as page:
        return page.read()


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
