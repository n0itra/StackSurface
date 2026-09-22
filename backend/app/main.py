import ipaddress
import json
import logging
import os
import socket
import uuid
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import redis
from supabase import create_client
# احذف استدعاء google.genai القديم وحط مكانه:
import google.generativeai as genai

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("stacksurface.backend")

app = FastAPI(title="StackSurface", version="0.5.0")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

# الإضافة: قراءة مفتاح Gemini
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# ---------------------------------------------------------------------------
# Background Task: Continuous Monitoring
# ---------------------------------------------------------------------------
async def monitoring_task():
    """
    دالة تعمل في الخلفية لاكتشاف المشاريع التي تحتاج لفحص دوري
    """
    logger.info("Started Background Monitoring Scheduler...")
    while True:
        try:
            if not supabase:
                await asyncio.sleep(60)
                continue
                
            # البحث عن المشاريع التي تم تفعيل المراقبة لها
            resp = supabase.table("projects").select("*").eq("monitoring", True).execute()
            projects = resp.data
            
            for proj in projects:
                project_id = proj["project_id"]
                domain = proj["domain"]
                user_id = proj["user_id"]
                
                # جلب آخر فحص تم لهذا المشروع لمعرفة وقته
                last_scan_resp = (
                    supabase.table("scans")
                    .select("created_at")
                    .eq("project_id", project_id)
                    .order("created_at", desc=True)
                    .limit(1)
                    .execute()
                )
                
                should_scan = True
                if last_scan_resp.data:
                    last_scan_time_str = last_scan_resp.data[0]["created_at"]
                    # تحويل الوقت لفورمات بايثون ومعالجة الـ Timezone
                    last_scan_time = datetime.fromisoformat(last_scan_time_str.replace("Z", "+00:00"))
                    
                    # إذا كان الفحص الأخير منذ أقل من 24 ساعة، لا نقم بفحص جديد
                    if datetime.now(timezone.utc) - last_scan_time < timedelta(days=1):
                        should_scan = False
                        
                if should_scan:
                    logger.info(f"Triggering scheduled scan for {domain} (Project: {project_id})")
                    scan_id = uuid.uuid4().hex
                    
                    tools = DEFAULT_TOOLS + ["nuclei"] # الأدوات الافتراضية للفحص الدوري
                    
                    # إنشاء سجل فحص جديد
                    r.hset(
                        f"scan:{scan_id}",
                        mapping={
                            "scan_id": scan_id,
                            "domain": domain,
                            "status": "queued",
                            "progress": "0",
                            "tools": json.dumps(tools),
                            "project_id": project_id,
                            "discord_webhook": "",
                            "user_id": user_id,
                            "created_at": datetime.now(timezone.utc).isoformat(),
                        },
                    )
                    
                    job = {
                        "scan_id": scan_id,
                        "domain": domain,
                        "tools": tools,
                        "user_id": user_id,
                        "project_id": project_id,
                        "custom_wordlist": None
                    }
                    r.rpush("ptaas:scans", json.dumps(job))
                    
        except Exception as e:
            logger.error(f"Monitoring task error: {e}")
            
        # ينام البرنامج 12 ساعة ثم يعاود الفحص
        await asyncio.sleep(12 * 3600)

@app.on_event("startup")
async def startup_event():
    # تشغيل المنبه مع بداية تشغيل السيرفر
    asyncio.create_task(monitoring_task())


# ---------------------------------------------------------------------------
# Auth System
# ---------------------------------------------------------------------------
def get_current_user(authorization: str = Header(None)):
    if not supabase:
        raise HTTPException(status_code=503, detail="Supabase is not configured")
    
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authentication token")
    
    token = authorization.split(" ")[1]
    try:
        res = supabase.auth.get_user(token)
        if not res or not res.user:
            raise HTTPException(status_code=401, detail="Invalid session. Please log in again.")
        return res.user.id
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Auth error: {str(e)}")

# Tools Update: Added gau, removed sqlmap & waymore
DEFAULT_TOOLS = [
    "subfinder", "assetfinder", "findomain", "crt.sh", "gau",
    "dnsx", "cdncheck", "shodan", "httpx",
]

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
    discord_webhook: Optional[str] = None
    force_refresh: bool = False  
    custom_wordlist: Optional[str] = None  


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
    if len(domain) > 253:  
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
            raise ValueError("Domain resolves to a disallowed address (internal/private).")


def resolve_tools(requested: Optional[List[str]]) -> List[str]:
    if not requested: 
        return DEFAULT_TOOLS
        
    cleaned = [t for t in requested if t in ALL_KNOWN_TOOLS]
    return cleaned or DEFAULT_TOOLS


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scans")
def create_scan(req: ScanRequest, user_id: str = Depends(get_current_user)):
    try:
        domain = normalize_domain(req.domain)
        assert_safe_target(domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # التحقق من المشروع
    if req.project_id:
        try:
            existing = (
                supabase.table("projects")
                .select("project_id")
                .eq("project_id", req.project_id)
                .eq("user_id", user_id)
                .execute()
            )
            if not existing.data:
                raise HTTPException(status_code=404, detail="Project not found or access denied")
        except HTTPException:
            raise
        except Exception:
            logger.exception("Supabase lookup failed while validating project_id")
            raise HTTPException(status_code=502, detail="Could not verify project — try again")

    # --- نظام التخزين المؤقت (Caching) ---
    if not req.force_refresh and supabase:
        try:
            existing_scan = (
                supabase.table("scans")
                .select("*")
                .eq("domain", domain)
                .eq("user_id", user_id)
                .eq("status", "completed")
                .order("completed_at", desc=True)
                .limit(1)
                .execute()
            )
            
            if existing_scan.data:
                cached_data = existing_scan.data[0]
                scan_id = cached_data["scan_id"]
                
                # استعادة البيانات في Redis لكي تقرأها الواجهة فوراً
                r_mapping = {
                    "scan_id": scan_id,
                    "domain": domain,
                    "status": "completed",
                    "progress": "100",
                    "user_id": user_id,
                    "tools": json.dumps(cached_data.get("tools", [])),
                }
                
                for field in JSON_FIELDS:
                    val = cached_data.get(field)
                    r_mapping[field] = json.dumps(val if val is not None else [])
                
                r.hset(f"scan:{scan_id}", mapping=r_mapping)
                return {
                    "scan_id": scan_id, 
                    "domain": domain, 
                    "tools": cached_data.get("tools", []), 
                    "cached": True
                }
                
        except Exception as e:
            logger.warning(f"Cache check failed: {e}")

    # --- بدء فحص جديد ---
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
            "discord_webhook": req.discord_webhook or "",
            "user_id": user_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    
    job = {
        "scan_id": scan_id, 
        "domain": domain, 
        "tools": tools, 
        "user_id": user_id
    }
    
    if req.project_id: 
        job["project_id"] = req.project_id
    if req.discord_webhook: 
        job["discord_webhook"] = req.discord_webhook
    if req.custom_wordlist:  
        job["custom_wordlist"] = req.custom_wordlist
        
    r.rpush("ptaas:scans", json.dumps(job))
    
    return {
        "scan_id": scan_id, 
        "domain": domain, 
        "tools": tools, 
        "project_id": req.project_id, 
        "cached": False
    }


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, user_id: str = Depends(get_current_user)):
    data = r.hgetall(f"scan:{scan_id}")
    
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if data.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Access denied to this scan")

    data.setdefault("status", "unknown")
    data.setdefault("progress", "0")
    
    for field in JSON_FIELDS:
        data[field] = json.loads(data.get(field, "[]"))
        
    if "tools" in data and isinstance(data["tools"], str):
        try: 
            data["tools"] = json.loads(data["tools"])
        except json.JSONDecodeError: 
            data["tools"] = []
            
    data["live_logs"] = r.lrange(f"scan:{scan_id}:live_logs", 0, -1)
    
    return data

# ===========================================================================
# الإضافة الجديدة: مسار تقرير الذكاء الاصطناعي (AI Report)
# ===========================================================================
@app.post("/api/scans/{scan_id}/ai-report")
def generate_ai_report(scan_id: str, user_id: str = Depends(get_current_user)):
    if not GEMINI_API_KEY:
        raise HTTPException(status_code=500, detail="Gemini API Key is not configured on the server.")

    # 1. جلب بيانات الفحص من Redis
    scan_data = r.hgetall(f"scan:{scan_id}")
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if scan_data.get("user_id") and scan_data.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Access denied to this scan")

    clean_data = {}
    for field in ["domain", "status", "tools", "subdomains", "alive", "endpoints", "secrets", "vulnerabilities", "directories"]:
        val = scan_data.get(field)
        if val:
            try:
                clean_data[field] = json.loads(val) if field in JSON_FIELDS else val
            except:
                pass

    prompt = f"""
    Act as a Senior Application Security Engineer. 
    Analyze the following reconnaissance and vulnerability scan results from 'StackSurface' automated pipeline.
    Write a concise, professional executive security report. 
    Format the output nicely using Markdown.
    
    Scan Data:
    {json.dumps(clean_data, indent=2)[:30000]}
    """

    try:
        # إعداد الطريقة القديمة والمستقرة
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-1.5-flash") # أو gemini-pro
        response = model.generate_content(prompt)
        
        return {"report": response.text}
    except Exception as e:
        logger.exception("Failed to generate AI report using legacy SDK")
        raise HTTPException(status_code=502, detail=f"AI generation failed: {str(e)}")
# ===========================================================================


@app.post("/api/projects")
def create_project(req: ProjectRequest, user_id: str = Depends(get_current_user)):
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
            "user_id": user_id, 
            "name": req.name.strip(),
            "domain": domain, 
            "monitoring": req.monitoring,
        }).execute()
    except Exception: 
        logger.exception("Supabase insert failed while creating project")
        raise HTTPException(status_code=502, detail="Could not create project")
        
    return {"project_id": project_id, "name": req.name.strip(), "domain": domain, "monitoring": req.monitoring}


@app.get("/api/projects")
def list_projects(user_id: str = Depends(get_current_user)):
    try:
        resp = (
            supabase.table("projects")
            .select("*")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )
        return resp.data
    except Exception: 
        logger.exception("Supabase query failed while listing projects")
        raise HTTPException(status_code=502, detail="Could not load projects")


@app.patch("/api/projects/{project_id}/monitoring")
def toggle_monitoring(project_id: str, monitoring: bool, user_id: str = Depends(get_current_user)):
    try:
        resp = (
            supabase.table("projects")
            .update({"monitoring": monitoring})
            .eq("project_id", project_id)
            .eq("user_id", user_id)
            .execute()
        )
        if not resp.data: 
            raise HTTPException(status_code=404, detail="Project not found")
        return resp.data[0]
    except HTTPException: 
        raise
    except Exception: 
        logger.exception("Supabase update failed while toggling monitoring")
        raise HTTPException(status_code=502, detail="Could not update project")


@app.get("/api/history")
def scan_history(limit: int = 50, user_id: str = Depends(get_current_user)):
    try:
        # بنطلب الداتا الخاصة بالـ subdomains و vulnerabilities عشان نعدهم
        resp = (
            supabase.table("scans")
            .select("scan_id,domain,status,created_at,completed_at,subdomains,vulnerabilities")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .limit(min(limit, 100))
            .execute()
        )
        
        results = []
        for row in resp.data:
            # معالجة وتحويل الـ JSON وعد العناصر
            subs = row.get("subdomains") or []
            vulns = row.get("vulnerabilities") or []
            
            if isinstance(subs, str):
                try: subs = json.loads(subs)
                except: subs = []
            if isinstance(vulns, str):
                try: vulns = json.loads(vulns)
                except: vulns = []
                
            results.append({
                "scan_id": row["scan_id"],
                "domain": row["domain"],
                "status": row["status"],
                "created_at": row["created_at"],
                "completed_at": row["completed_at"],
                "subdomains_count": len(subs),
                "vulnerabilities_count": len(vulns)
            })
            
        return results
    except Exception: 
        logger.exception("Supabase query failed while loading history")
        raise HTTPException(status_code=502, detail="Could not load history")


# مسار جديد (API) هيجيب إحصائيات سريعة للـ Dashboard في المرحلة الجاية
@app.get("/api/stats")
def get_stats(user_id: str = Depends(get_current_user)):
    try:
        resp = supabase.table("scans").select("status,subdomains,vulnerabilities").eq("user_id", user_id).execute()
        total_scans = len(resp.data)
        completed_scans = sum(1 for r in resp.data if r.get("status") == "completed")
        
        total_subs = 0
        total_vulns = 0
        for row in resp.data:
            subs = row.get("subdomains") or "[]"
            vulns = row.get("vulnerabilities") or "[]"
            
            if isinstance(subs, str):
                try: total_subs += len(json.loads(subs))
                except: pass
            elif isinstance(subs, list): total_subs += len(subs)
            
            if isinstance(vulns, str):
                try: total_vulns += len(json.loads(vulns))
                except: pass
            elif isinstance(vulns, list): total_vulns += len(vulns)

        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "total_subdomains": total_subs,
            "total_vulnerabilities": total_vulns
        }
    except Exception:
        raise HTTPException(status_code=502, detail="Could not load stats")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    index_path = os.path.join(STATIC_DIR, "index.html")
    with open(index_path, "r", encoding="utf-8") as f: 
        html = f.read()
        
    injected = f'<script>window.__SUPABASE_URL__="{SUPABASE_URL}"; window.__SUPABASE_ANON_KEY__="{SUPABASE_KEY}";</script>'
    return html.replace("</head>", f"{injected}</head>")


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
