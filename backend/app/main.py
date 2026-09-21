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

from sqlite_store import get_db, validate_bearer_token

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('stacksurface.backend')
app = FastAPI(title='StackSurface', version='0.4.0')

REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
r = redis.from_url(REDIS_URL, decode_responses=True)
db = get_db()
STATIC_DIR = os.path.join(os.path.dirname(__file__), 'static')

DEFAULT_TOOLS = ['subfinder', 'assetfinder', 'findomain', 'crt.sh', 'gau',
                 'dnsx', 'cdncheck', 'shodan', 'httpx']
OPT_IN_TOOLS = {'nuclei', 'katana', 'arjun', 'trufflehog', 'jsluice',
                'ffuf', 'permutations'}
ALL_KNOWN_TOOLS = set(DEFAULT_TOOLS) | OPT_IN_TOOLS | {'anew'}
JSON_FIELDS = ['subdomains', 'unresolved', 'alive', 'ports', 'vulnerabilities',
               'endpoints', 'secrets', 'directories', 'errors', 'added_assets',
               'removed_assets', 'new_js_dependencies', 'js_cve_findings']


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
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='Authentication required')
    token = authorization.split(' ', 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail='Authentication required')
    user = validate_bearer_token(token)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid or expired session')
    return user


def public_user(user):
    return {"id": user["id"], "email": user["email"], "created_at": user["created_at"]}


def require_data_client():
    return db


@app.post('/api/auth/signup')
def signup(credentials: Credentials):
    try:
        user = db.create_user(credentials.email, credentials.password)
        session = db.create_session_for_user(user['id'])
        return {'user': public_user(user), 'session': session.model_dump()}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        logger.exception('Signup failed')
        raise HTTPException(status_code=400, detail='Could not create user')


@app.post('/api/auth/login')
def login(credentials: Credentials):
    try:
        user = db.verify_password(credentials.email, credentials.password)
        if not user:
            raise ValueError('Invalid email or password')
        session = db.create_session_for_user(user['id'])
        return {'user': public_user(user), 'session': session.model_dump()}
    except Exception:
        raise HTTPException(status_code=401, detail='Invalid email or password')


@app.post('/api/auth/logout')
def logout(authorization: Optional[str] = Header(default=None), user=Depends(require_user)):
    token = authorization.split(" ", 1)[1].strip()
    db.revoke_session_by_access_token(token)
    return {'ok': True}


@app.post('/api/auth/refresh')
def refresh_session(request: RefreshRequest):
    try:
        session = db.refresh_session(request.refresh_token)
        user = db.get_user(session['user_id'])
        return {'user': public_user(user), 'session': session.model_dump()}
    except Exception:
        raise HTTPException(status_code=401, detail='Invalid or expired refresh token')


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower().removeprefix('https://').removeprefix('http://')
    domain = domain.split('/')[0].split(':')[0]
    if not domain or '.' not in domain or any(c.isspace() for c in domain) or len(domain) > 253:
        raise ValueError('Invalid domain')
    if '*' in domain or '@' in domain:
        raise ValueError('Wildcards and userinfo are not allowed')
    return domain


def assert_safe_target(domain: str) -> None:
    try:
        resolved_ips = {info[4][0] for info in socket.getaddrinfo(domain, None)}
    except socket.gaierror:
        raise ValueError(f'Could not resolve domain: {domain}')
    for ip_str in resolved_ips:
        addr = ipaddress.ip_address(ip_str)
        if (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
                or addr.is_multicast or addr.is_unspecified):
            raise ValueError(f'Domain resolves to a disallowed address ({ip_str})')


def resolve_tools(requested):
    if not requested:
        return DEFAULT_TOOLS
    cleaned = [tool for tool in requested if tool in ALL_KNOWN_TOOLS]
    return cleaned or DEFAULT_TOOLS


@app.get('/health')
def health():
    return {'status': 'ok'}


@app.post('/api/scans')
def create_scan(req: ScanRequest, user=Depends(require_user), db_client=Depends(require_data_client)):
    try:
        domain = normalize_domain(req.domain)
        assert_safe_target(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if req.project_id:
        project = db_client.get_project(req.project_id, user.id)
        if not project:
            raise HTTPException(status_code=404, detail='Project not found')
    tools, scan_id = resolve_tools(req.tools), uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    db_client.create_scan(
        scan_id=scan_id,
        user_id=user.id,
        domain=domain,
        tools=tools,
        project_id=req.project_id,
    )
    r.hset(f'scan:{scan_id}', mapping={
        'scan_id': scan_id,
        'user_id': user.id,
        'domain': domain,
        'status': 'queued',
        'progress': '0',
        'tools': json.dumps(tools),
        'project_id': req.project_id or '',
        'created_at': now,
    })
    job = {'scan_id': scan_id, 'user_id': user.id, 'domain': domain, 'tools': tools}
    if req.project_id:
        job['project_id'] = req.project_id
    r.rpush('ptaas:scans', json.dumps(job))
    return {'scan_id': scan_id, 'domain': domain, 'tools': tools, 'project_id': req.project_id}


@app.get('/api/scans/{scan_id}')
def get_scan(scan_id: str, user=Depends(require_user)):
    data = r.hgetall(f'scan:{scan_id}')
    if not data or data.get('user_id') != user.id:
        row = db.get_scan(scan_id)
        if not row or row.get('user_id') != user.id:
            raise HTTPException(status_code=404, detail='Scan not found')
        data = row
    for field in JSON_FIELDS:
        if not isinstance(data.get(field), (list, dict)):
            try:
                data[field] = json.loads(data.get(field, '[]'))
            except (TypeError, ValueError):
                data[field] = []
    if not isinstance(data.get('tools'), list):
        try:
            data['tools'] = json.loads(data.get('tools', '[]'))
        except (TypeError, ValueError):
            data['tools'] = []
    data['live_logs'] = r.lrange(f'scan:{scan_id}:live_logs', 0, -1)
    return data


@app.post('/api/projects')
def create_project(req: ProjectRequest, user=Depends(require_user), db_client=Depends(require_data_client)):
    try:
        domain = normalize_domain(req.domain)
        assert_safe_target(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not req.name.strip() or len(req.name) > 200:
        raise HTTPException(status_code=400, detail='Project name must be 1-200 characters')
    row = db_client.create_project(user.id, req.name, domain, req.monitoring)
    return row


@app.get('/api/projects')
def list_projects(user=Depends(require_user), db_client=Depends(require_data_client)):
    try:
        return db_client.list_projects_for_user(user.id)
    except Exception:
        raise HTTPException(status_code=502, detail='Could not load projects â€” try again')


@app.patch('/api/projects/{project_id}/monitoring')
def toggle_monitoring(project_id: str, monitoring: bool, user=Depends(require_user), db_client=Depends(require_data_client)):
    row = db_client.set_project_monitoring(project_id, user.id, monitoring)
    if not row:
        raise HTTPException(status_code=404, detail='Project not found')
    return row


@app.get('/api/history')
def scan_history(limit: int = 20, user=Depends(require_user), db_client=Depends(require_data_client)):
    return db_client.list_scans_for_user(user.id, limit)


@app.get('/', response_class=HTMLResponse)
def dashboard():
    with open(os.path.join(STATIC_DIR, 'index.html'), encoding='utf-8') as page:
        return page.read()


if os.path.isdir(STATIC_DIR):
    app.mount('/static', StaticFiles(directory=STATIC_DIR), name='static')
