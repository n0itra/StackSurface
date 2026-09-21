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

from app.sqlite_store import SQLiteStore

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
r = redis.from_url(REDIS_URL, decode_responses=True)
db = SQLiteStore()
POLL_INTERVAL_SECONDS = int(os.getenv("MONITOR_POLL_INTERVAL_SECONDS", "1800"))

DRIFT_SCAN_TOOLS = [
    "subfinder", "assetfinder", "findomain", "crt.sh", "gau",
    "dnsx", "cdncheck", "shodan", "httpx",
]


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


def crtsh_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        with httpx.Client(timeout=30, follow_redirects=True) as client:
            response = client.get(url)
            response.raise_for_status()
            data = response.json()
        names = set()
        for row in data:
            for name in row.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.").rstrip(".")
                if name == domain or name.endswith("." + domain):
                    names.add(name)
        return names
    except Exception as exc:
        print(f"[monitor] crt.sh check failed for {domain}: {exc}")
        return set()


def trigger_drift_scan(project_id, domain, new_subdomains, user_id):
    scan_id = uuid.uuid4().hex
    tools = list(DRIFT_SCAN_TOOLS)
    db.create_scan(
        scan_id=scan_id,
        user_id=user_id,
        domain=domain,
        tools=tools,
        project_id=project_id,
    )
    r.hset(
        f"scan:{scan_id}",
        mapping={
            "scan_id": scan_id,
            "domain": domain,
            "status": "queued",
            "progress": "0",
            "tools": json.dumps(tools),
            "project_id": project_id,
            "user_id": user_id,
            "trigger": "drift",
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    r.rpush("ptaas:scans", json.dumps({
        "scan_id": scan_id, "domain": domain, "tools": tools,
        "project_id": project_id, "user_id": user_id,
    }))
    print(
        f"[monitor] drift detected for {domain}: {len(new_subdomains)} new "
        f"subdomain(s) — queued scan {scan_id}"
    )


def check_project(project):
    project_id = project["project_id"]
    domain = project["domain"]
    if not is_safe_target(domain):
        print(f"[monitor] skipping {domain}: fails safety check")
        return

    current = crtsh_subdomains(domain)
    if current:
        known = db.get_project_asset_history(project_id)
        new_subdomains = current - known
        if new_subdomains:
            trigger_drift_scan(project_id, domain, new_subdomains, project["user_id"])
    db.update_project_last_checked(project_id)


def poll_cycle():
    try:
        projects = db.list_monitored_projects()
    except Exception:
        print(f"[monitor] failed to fetch monitored projects: {traceback.format_exc(limit=2)}")
        return
    print(f"[monitor] checking {len(projects)} monitored project(s)")
    for project in projects:
        try:
            check_project(project)
        except Exception:
            print(
                f"[monitor] error checking project {project.get('project_id')}: "
                f"{traceback.format_exc(limit=3)}"
            )


def main():
    print(f"StackSurface monitor started — polling every {POLL_INTERVAL_SECONDS}s")
    while True:
        poll_cycle()
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
