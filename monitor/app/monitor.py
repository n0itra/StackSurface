import ipaddress
import json
import os
import socket
import time
import traceback
import uuid
from datetime import datetime, timezone

import httpx
import redis
from supabase import create_client

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

POLL_INTERVAL_SECONDS = int(os.getenv("MONITOR_POLL_INTERVAL_SECONDS", "1800"))  # 30 min default

# A drift-triggered scan only runs safe, passive-by-default tools. It should
# never silently kick off active tools (nuclei, feroxbuster, etc.) without a
# human explicitly starting that from the dashboard.
DRIFT_SCAN_TOOLS = [
    "subfinder", "assetfinder", "findomain", "crt.sh", "waymore",
    "dnsx", "cdncheck", "shodan", "httpx",
]


def is_safe_target(domain: str) -> bool:
    """Same SSRF-style check used by the backend/worker — re-verified here
    since the monitor also queues scan jobs directly."""
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


def crtsh_subdomains(domain):
    """Lightweight crt.sh-only check — deliberately not the full OSINT source
    set, so continuous background polling doesn't burn API quota or hammer
    external services on every cycle. Full breadth still happens when a human
    starts a real scan from the dashboard."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        with httpx.Client(timeout=30, follow_redirects=True) as client:
            data = client.get(url).json()
        names = set()
        for row in data:
            for name in row.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name == domain or name.endswith("." + domain):
                    names.add(name)
        return names
    except Exception as e:
        print(f"[monitor] crt.sh check failed for {domain}: {e}")
        return set()


def get_known_subdomains(project_id):
    try:
        resp = (
            supabase.table("asset_history")
            .select("subdomain")
            .eq("project_id", project_id)
            .execute()
        )
        return {row["subdomain"] for row in resp.data}
    except Exception:
        print(f"[monitor] failed to read asset_history for {project_id}: {traceback.format_exc(limit=2)}")
        return set()


def trigger_drift_scan(project_id, domain, new_subdomains, user_id):
    """Queues a scoped scan on the exact same Redis queue the dashboard
    uses — the worker doesn't know or care whether a scan was started by a
    human or by this monitor."""
    scan_id = uuid.uuid4().hex
    r.hset(
        f"scan:{scan_id}",
        mapping={
            "scan_id": scan_id,
            "domain": domain,
            "status": "queued",
            "progress": "0",
            "tools": json.dumps(DRIFT_SCAN_TOOLS),
            "project_id": project_id,
            "user_id": user_id,
            "trigger": "drift",
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    r.rpush("ptaas:scans", json.dumps({
        "scan_id": scan_id, "domain": domain,
        "tools": DRIFT_SCAN_TOOLS, "project_id": project_id, "user_id": user_id,
    }))
    print(f"[monitor] drift detected for {domain}: {len(new_subdomains)} new subdomain(s) "
          f"— queued scan {scan_id}")


def check_project(project):
    project_id = project["project_id"]
    domain = project["domain"]

    if not is_safe_target(domain):
        print(f"[monitor] skipping {domain}: fails safety check")
        return

    current = crtsh_subdomains(domain)
    if not current:
        return

    known = get_known_subdomains(project_id)
    new_subdomains = current - known

    if new_subdomains:
        trigger_drift_scan(project_id, domain, new_subdomains, project["user_id"])

    try:
        supabase.table("projects").update({
            "last_checked_at": datetime.now(timezone.utc).isoformat()
        }).eq("project_id", project_id).execute()
    except Exception:
        pass


def poll_cycle():
    if not supabase:
        print("[monitor] Supabase not configured — nothing to do")
        return
    try:
        resp = supabase.table("projects").select("*").eq("monitoring", True).execute()
        projects = resp.data
    except Exception:
        print(f"[monitor] failed to fetch monitored projects: {traceback.format_exc(limit=2)}")
        return

    print(f"[monitor] checking {len(projects)} monitored project(s)")
    for project in projects:
        try:
            check_project(project)
        except Exception:
            print(f"[monitor] error checking project {project.get('project_id')}: "
                  f"{traceback.format_exc(limit=3)}")


def main():
    print(f"StackSurface monitor started — polling every {POLL_INTERVAL_SECONDS}s")
    while True:
        poll_cycle()
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
