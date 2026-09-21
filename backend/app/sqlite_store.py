import hashlib
import json
import os
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

DEFAULT_SQLITE_PATH = "/data/stacksurface.db"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_utc(dt: Optional[datetime] = None) -> str:
    if dt is None:
        dt = utc_now()
    return dt.astimezone(timezone.utc).isoformat()


def json_dumps(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def json_loads(raw: Any) -> Any:
    if raw in (None, ""):
        return None
    if isinstance(raw, (dict, list, tuple)):
        return raw
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return raw


class AttrDict(dict):
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError as exc:
            raise AttributeError(key) from exc

    def __setattr__(self, key, value):
        self[key] = value

    def model_dump(self):
        return dict(self)


class SQLiteStore:
    def __init__(self, path: Optional[str] = None):
        self.path = path or os.getenv("SQLITE_PATH", DEFAULT_SQLITE_PATH)
        self._lock = threading.RLock()
        directory = os.path.dirname(self.path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_schema(self) -> None:
        schema = """
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            access_token TEXT UNIQUE NOT NULL,
            refresh_token TEXT UNIQUE NOT NULL,
            token_type TEXT NOT NULL DEFAULT 'bearer',
            expires_at TEXT NOT NULL,
            refresh_expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS projects (
            project_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            domain TEXT NOT NULL,
            monitoring INTEGER NOT NULL DEFAULT 0,
            last_checked_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            user_id TEXT,
            project_id TEXT,
            domain TEXT,
            status TEXT NOT NULL DEFAULT 'queued',
            tools TEXT,
            progress INTEGER NOT NULL DEFAULT 0,
            subdomains TEXT,
            unresolved TEXT,
            alive TEXT,
            ports TEXT,
            vulnerabilities TEXT,
            endpoints TEXT,
            secrets TEXT,
            directories TEXT,
            errors TEXT,
            added_assets TEXT,
            removed_assets TEXT,
            new_js_dependencies TEXT,
            js_cve_findings TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS asset_history (
            project_id TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (project_id, subdomain)
        );

        CREATE TABLE IF NOT EXISTS js_dependencies (
            project_id TEXT NOT NULL,
            script_url TEXT NOT NULL,
            library_name TEXT NOT NULL,
            library_version TEXT NOT NULL,
            known_cves TEXT,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (project_id, script_url)
        );
        """
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(schema)
            finally:
                conn.close()

    def _normalize_email(self, email: str) -> str:
        return email.strip().lower()

    def _normalize_scan_column(self, key: str, value: Any) -> Any:
        if key in {"tools", "subdomains", "unresolved", "alive", "ports", "vulnerabilities",
                   "endpoints", "secrets", "directories", "errors", "added_assets",
                   "removed_assets", "new_js_dependencies", "js_cve_findings"}:
            if value is None:
                return None
            return json_dumps(value)
        if isinstance(value, bool):
            return int(value)
        return value

    def _scan_row_to_dict(self, row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        data = dict(row)
        for key in ["tools", "subdomains", "unresolved", "alive", "ports", "vulnerabilities",
                    "endpoints", "secrets", "directories", "errors", "added_assets",
                    "removed_assets", "new_js_dependencies", "js_cve_findings"]:
            value = data.get(key)
            if value is None:
                data[key] = [] if key in {"tools", "subdomains", "unresolved", "alive", "ports",
                                           "vulnerabilities", "endpoints", "secrets",
                                           "directories", "added_assets", "removed_assets",
                                           "new_js_dependencies", "js_cve_findings"} else None
            else:
                parsed = json_loads(value)
                data[key] = parsed if parsed is not None else []
        data["monitoring"] = bool(data.get("monitoring")) if "monitoring" in data else False
        return data

    def _project_row_to_dict(self, row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        data = dict(row)
        data["monitoring"] = bool(data.get("monitoring"))
        return data

    def get_user(self, user_id: str) -> Optional[AttrDict]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                if row is None:
                    return None
                return AttrDict(dict(row))
            finally:
                conn.close()

    def get_user_by_email(self, email: str) -> Optional[AttrDict]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM users WHERE email = ?", (self._normalize_email(email),)).fetchone()
                if row is None:
                    return None
                return AttrDict(dict(row))
            finally:
                conn.close()

    def create_user(self, email: str, password: str) -> AttrDict:
        normalized = self._normalize_email(email)
        if "@" not in normalized or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if self.get_user_by_email(normalized):
            raise ValueError("User already exists")
        user_id = uuid.uuid4().hex
        now = isoformat_utc()
        password_salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), password_salt.encode("utf-8"), 200000).hex()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO users (id, email, password_salt, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, normalized, password_salt, password_hash, now, now),
                )
            finally:
                conn.close()
        return self.get_user(user_id)

    def verify_password(self, email: str, password: str) -> Optional[AttrDict]:
        user = self.get_user_by_email(email)
        if user is None:
            return None
        salt = user.get("password_salt")
        if not salt:
            return None
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000).hex()
        if derived != user.get("password_hash"):
            return None
        return user

    def create_session_for_user(self, user_id: str) -> AttrDict:
        access_token = f"at_{secrets.token_urlsafe(32)}"
        refresh_token = f"rt_{secrets.token_urlsafe(32)}"
        now = isoformat_utc()
        expires_at = (utc_now() + timedelta(hours=12)).isoformat()
        refresh_expires_at = (utc_now() + timedelta(days=30)).isoformat()
        session_id = uuid.uuid4().hex
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO sessions (id, user_id, access_token, refresh_token, token_type, expires_at, refresh_expires_at, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (session_id, user_id, access_token, refresh_token, "bearer", expires_at, refresh_expires_at, now, now),
                )
            finally:
                conn.close()
        return self.get_session_by_access_token(access_token)

    def get_session_by_access_token(self, token: str) -> Optional[AttrDict]:
        if not token:
            return None
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM sessions WHERE access_token = ? AND revoked_at IS NULL AND expires_at > ?",
                    (token, isoformat_utc()),
                ).fetchone()
                if row is None:
                    return None
                session = AttrDict(dict(row))
                conn.execute("UPDATE sessions SET last_used_at = ? WHERE id = ?", (isoformat_utc(), session["id"]))
                return session
            finally:
                conn.close()

    def get_session_by_refresh_token(self, token: str) -> Optional[AttrDict]:
        if not token:
            return None
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM sessions WHERE refresh_token = ? AND revoked_at IS NULL AND refresh_expires_at > ?",
                    (token, isoformat_utc()),
                ).fetchone()
                if row is None:
                    return None
                return AttrDict(dict(row))
            finally:
                conn.close()

    def revoke_session_by_access_token(self, token: str) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("UPDATE sessions SET revoked_at = ? WHERE access_token = ?", (isoformat_utc(), token))
            finally:
                conn.close()

    def refresh_session(self, refresh_token: str) -> AttrDict:
        session = self.get_session_by_refresh_token(refresh_token)
        if session is None:
            raise ValueError("Invalid or expired refresh token")
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (isoformat_utc(), session["id"]))
            finally:
                conn.close()
        return self.create_session_for_user(session["user_id"])

    def get_project(self, project_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                if user_id is None:
                    row = conn.execute("SELECT * FROM projects WHERE project_id = ?", (project_id,)).fetchone()
                else:
                    row = conn.execute(
                        "SELECT * FROM projects WHERE project_id = ? AND user_id = ?",
                        (project_id, user_id),
                    ).fetchone()
                return self._project_row_to_dict(row)
            finally:
                conn.close()

    def create_project(self, user_id: str, name: str, domain: str, monitoring: bool = False) -> Dict[str, Any]:
        project_id = uuid.uuid4().hex
        now = isoformat_utc()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO projects (project_id, user_id, name, domain, monitoring, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (project_id, user_id, name.strip(), domain, int(bool(monitoring)), now, now),
                )
            finally:
                conn.close()
        return self.get_project(project_id, user_id)

    def list_projects_for_user(self, user_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC",
                    (user_id,),
                ).fetchall()
                return [self._project_row_to_dict(row) for row in rows]
            finally:
                conn.close()

    def set_project_monitoring(self, project_id: str, user_id: str, monitoring: bool) -> Optional[Dict[str, Any]]:
        now = isoformat_utc()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE projects SET monitoring = ?, updated_at = ? WHERE project_id = ? AND user_id = ?",
                    (int(bool(monitoring)), now, project_id, user_id),
                )
                return self.get_project(project_id, user_id)
            finally:
                conn.close()

    def list_monitored_projects(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT * FROM projects WHERE monitoring = 1").fetchall()
                return [self._project_row_to_dict(row) for row in rows]
            finally:
                conn.close()

    def update_project_last_checked(self, project_id: str, checked_at: Optional[str] = None) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE projects SET last_checked_at = ?, updated_at = ? WHERE project_id = ?",
                    (checked_at or isoformat_utc(), isoformat_utc(), project_id),
                )
            finally:
                conn.close()

    def upsert_scan(self, scan_id: str, **fields: Any) -> Dict[str, Any]:
        now = isoformat_utc()
        with self._lock:
            conn = self._connect()
            try:
                existing = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
                existing_data = dict(existing) if existing is not None else {}
                data = dict(existing_data)
                for key, value in fields.items():
                    if value is not None:
                        data[key] = value
                data.setdefault("scan_id", scan_id)
                data.setdefault("created_at", now)
                data.setdefault("status", "queued")
                if "tools" in data and data.get("tools") is not None:
                    data["tools"] = json_dumps(data.get("tools") or [])
                for key in ["subdomains", "unresolved", "alive", "ports", "vulnerabilities",
                            "endpoints", "secrets", "directories", "errors", "added_assets",
                            "removed_assets", "new_js_dependencies", "js_cve_findings"]:
                    if key in data:
                        data[key] = self._normalize_scan_column(key, data.get(key))
                if existing is None:
                    columns = ["scan_id", "user_id", "project_id", "domain", "status", "tools", "progress",
                                "subdomains", "unresolved", "alive", "ports", "vulnerabilities",
                                "endpoints", "secrets", "directories", "errors", "added_assets",
                                "removed_assets", "new_js_dependencies", "js_cve_findings", "created_at", "completed_at"]
                    values = [data.get(key) for key in columns]
                    placeholders = ", ".join(["?" for _ in columns])
                    conn.execute(f"INSERT INTO scans ({', '.join(columns)}) VALUES ({placeholders})", values)
                else:
                    update_columns = []
                    params: List[Any] = []
                    for key in ["user_id", "project_id", "domain", "status", "tools", "progress",
                                "subdomains", "unresolved", "alive", "ports", "vulnerabilities",
                                "endpoints", "secrets", "directories", "errors", "added_assets",
                                "removed_assets", "new_js_dependencies", "js_cve_findings",
                                "completed_at"]:
                        if key in data and data.get(key) != existing_data.get(key):
                            update_columns.append(f"{key} = ?")
                            params.append(data.get(key))
                    if update_columns:
                        params.extend([scan_id])
                        conn.execute(f"UPDATE scans SET {', '.join(update_columns)} WHERE scan_id = ?", params)
                row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
                return self._scan_row_to_dict(row)
            finally:
                conn.close()

    def create_scan(self, *, user_id: str, domain: str, tools: Optional[Iterable[str]] = None, project_id: Optional[str] = None, scan_id: Optional[str] = None) -> Dict[str, Any]:
        scan_guid = scan_id or uuid.uuid4().hex
        now = isoformat_utc()
        payload = {
            "user_id": user_id,
            "domain": domain,
            "status": "queued",
            "tools": list(tools) if tools else [],
            "project_id": project_id,
            "progress": 0,
            "created_at": now,
        }
        return self.upsert_scan(scan_guid, **payload)

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
                return self._scan_row_to_dict(row)
            finally:
                conn.close()

    def list_scans_for_user(self, user_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT scan_id, domain, status, tools, project_id, created_at, completed_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
                    (user_id, max(1, min(limit, 100))),
                ).fetchall()
                return [self._scan_row_to_dict(row) for row in rows]
            finally:
                conn.close()

    def get_project_asset_history(self, project_id: str) -> set:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT subdomain FROM asset_history WHERE project_id = ?", (project_id,)).fetchall()
                return {row["subdomain"] for row in rows}
            finally:
                conn.close()

    def diff_asset_history(self, project_id: str, current_subdomains: Iterable[str], errors: Optional[List[str]] = None) -> tuple:
        if not project_id:
            return [], []
        current_set = set(current_subdomains)
        now = isoformat_utc()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute("SELECT subdomain FROM asset_history WHERE project_id = ?", (project_id,)).fetchall()
                previously_known = {row["subdomain"] for row in rows}
                added = sorted(current_set - previously_known)
                removed = sorted(previously_known - current_set)
                for subdomain in current_set:
                    conn.execute(
                        "INSERT INTO asset_history (project_id, subdomain, last_seen) VALUES (?, ?, ?) ON CONFLICT(project_id, subdomain) DO UPDATE SET last_seen = excluded.last_seen",
                        (project_id, subdomain, now),
                    )
                return added, removed
            except Exception as exc:  # pragma: no cover
                if errors is not None:
                    errors.append(f"asset-history-diff: {exc}")
                return [], []
            finally:
                conn.close()

    def diff_js_dependencies(self, project_id: str, detected_libs: List[Dict[str, Any]], errors: Optional[List[str]] = None) -> tuple:
        if not detected_libs:
            return [], []
        cve_findings = []
        for lib in detected_libs:
            cves = []
            try:
                import httpx
                with httpx.Client(timeout=15) as client:
                    resp = client.post(
                        "https://api.osv.dev/v1/query",
                        json={"version": lib.get("version"), "package": {"name": lib.get("library"), "ecosystem": "npm"}},
                    )
                    if resp.status_code == 200:
                        cves = [v.get("id") for v in resp.json().get("vulns", []) if v.get("id")]
            except Exception as exc:  # pragma: no cover
                if errors is not None:
                    errors.append(f"osv-lookup({lib.get('library')}): {exc}")
            if cves:
                cve_findings.append({**lib, "cves": cves})
        if not project_id:
            return detected_libs, cve_findings
        now = isoformat_utc()
        new_libs = []
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT library_name, library_version FROM js_dependencies WHERE project_id = ?",
                    (project_id,),
                ).fetchall()
                known = {(row["library_name"], row["library_version"]) for row in rows}
                for lib in detected_libs:
                    key = (lib.get("library"), lib.get("version"))
                    if key not in known:
                        new_libs.append(lib)
                    matching_cves = next(
                        (
                            item["cves"]
                            for item in cve_findings
                            if item.get("library") == lib.get("library") and item.get("version") == lib.get("version")
                        ),
                        [],
                    )
                    conn.execute(
                        "INSERT INTO js_dependencies (project_id, script_url, library_name, library_version, known_cves, last_seen) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(project_id, script_url) DO UPDATE SET library_name = excluded.library_name, library_version = excluded.library_version, known_cves = excluded.known_cves, last_seen = excluded.last_seen",
                        (
                            project_id,
                            lib.get("script"),
                            lib.get("library"),
                            lib.get("version"),
                            json_dumps(matching_cves),
                            now,
                        ),
                    )
                return new_libs, cve_findings
            except Exception as exc:  # pragma: no cover
                if errors is not None:
                    errors.append(f"js-deps-diff: {exc}")
                return detected_libs, cve_findings
            finally:
                conn.close()


sql_store = SQLiteStore()


def hash_password(password: str, salt: str = "stacksurface-local") -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200000).hex()


def verify_password(password: str, password_hash: str, salt: str = "stacksurface-local") -> bool:
    return hash_password(password, salt) == password_hash


def create_user(email: str, password: str) -> AttrDict:
    return sql_store.create_user(email, password)


def authenticate_user(email: str, password: str) -> Optional[AttrDict]:
    return sql_store.verify_password(email, password)


def create_session(user_id: str) -> AttrDict:
    return sql_store.create_session_for_user(user_id)


def validate_bearer_token(token: str) -> Optional[AttrDict]:
    session = sql_store.get_session_by_access_token(token)
    if session is None:
        return None
    return sql_store.get_user(session["user_id"])


def get_db() -> SQLiteStore:
    return sql_store

