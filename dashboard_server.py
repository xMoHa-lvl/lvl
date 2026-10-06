# -*- coding: utf-8 -*-
"""
FreeFire Level Up Bot - Professional Web Dashboard & Real-Time EXP Tracker
Embedded Async Web Server (aiohttp) with Admin / User accounts
"""

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from typing import Dict, List, Any, Optional
from aiohttp import web

# ============================================================
#  ADMIN LOGIN (fixed in code) - change these two values, then restart the bot
# ============================================================
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin@84FF"

ACCOUNTS_FILE = "accounts.json"
USERS_FILE = "users.json"
BASELINE_FILE = "exp_baseline.json"


def _read_json(path: str, default: Any):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default


def _write_json(path: str, data: Any):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


# ==================== PASSWORDS / USERS / SESSIONS ====================

PBKDF2_ITERATIONS = 200_000
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LEN = 6


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt, digest = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False


DUMMY_HASH = hash_password(secrets.token_hex(8))  # equalises timing for unknown usernames


class UserStore:
    def __init__(self, path: str = USERS_FILE):
        self.path = path
        self.users: List[Dict[str, Any]] = []
        self.load()

    def load(self):
        data = _read_json(self.path, [])
        self.users = data if isinstance(data, list) else []

    def save(self):
        _write_json(self.path, self.users)

    def find(self, username: str) -> Optional[Dict[str, Any]]:
        name = str(username or "").strip().lower()
        for u in self.users:
            if str(u.get("username", "")).lower() == name:
                return u
        return None

    def admin_username(self) -> str:
        for u in self.users:
            if u.get("role") == "admin":
                return u["username"]
        return "admin"

    def exp_limit(self, username: Optional[str]) -> int:
        u = self.find(username or "")
        if not u or u.get("role") != "user":
            return 0
        try:
            return max(0, int(u.get("exp_limit") or 0))
        except Exception:
            return 0

    def ensure_admin(self):
        """The admin is always the one defined by ADMIN_USERNAME / ADMIN_PASSWORD at the top of this file."""
        name = ADMIN_USERNAME.strip()
        # only one admin exists: the one written in the code
        self.users = [u for u in self.users if u.get("role") != "admin" or str(u.get("username", "")).lower() == name.lower()]
        admin = self.find(name)
        if admin is None:
            self.users.append({
                "username": name, "role": "admin", "password_hash": hash_password(ADMIN_PASSWORD),
                "exp_limit": 0, "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
        else:
            admin["username"] = name
            admin["role"] = "admin"
            admin["exp_limit"] = 0
            if not verify_password(ADMIN_PASSWORD, admin.get("password_hash", "")):
                admin["password_hash"] = hash_password(ADMIN_PASSWORD)
        self.save()
        print(f"\033[92m[+] Admin login ready -> username: {name}\033[0m")


user_store = UserStore()

SESSION_TTL = 7 * 24 * 3600
COOKIE_NAME = "ffbot_session"
sessions: Dict[str, Dict[str, Any]] = {}

LOGIN_WINDOW = 300
LOGIN_MAX_FAILS = 8
login_failures: Dict[str, List[float]] = {}


def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    sessions[token] = {"username": username, "expires": time.time() + SESSION_TTL}
    return token


def drop_sessions_of(username: str):
    for t in [t for t, s in sessions.items() if str(s["username"]).lower() == str(username).lower()]:
        sessions.pop(t, None)


def current_user(request) -> Optional[Dict[str, Any]]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    s = sessions.get(token)
    if not s:
        return None
    if s["expires"] < time.time():
        sessions.pop(token, None)
        return None
    return user_store.find(s["username"])


def throttled(ip: str) -> bool:
    now = time.time()
    fails = [t for t in login_failures.get(ip, []) if now - t < LOGIN_WINDOW]
    login_failures[ip] = fails
    return len(fails) >= LOGIN_MAX_FAILS


# ==================== BOT STATE ====================

class BotState:
    def __init__(self):
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.logs: List[Dict[str, Any]] = []
        self.max_logs = 200
        self.total_matches = 0
        self.total_gained_exp = 0
        self.start_time = time.time()
        self.account_workers: Dict[str, asyncio.Task] = {}
        self.refresh_callbacks: Dict[str, Any] = {}
        self.account_credentials: Dict[str, Dict[str, Any]] = {}
        self.paused_accounts: set = set()
        self.login_waiters: Dict[str, Any] = {}
        # ownership + EXP limits
        self.account_owners: Dict[str, str] = {}   # game account id -> username
        self.login_owners: Dict[str, str] = {}     # login key (uid / token[:10]) -> username
        self.login_added: Dict[str, str] = {}      # login key -> time the account was added
        self.account_added: Dict[str, str] = {}    # game account id -> time the account was added
        self.limit_blocked: set = set()
        # EXP baselines survive restarts AND account deletion (so a limit can't be reset by re-adding)
        data = _read_json(BASELINE_FILE, {})
        self.baselines: Dict[str, int] = data if isinstance(data, dict) else {}

    def log(self, message: str, level: str = "info", uid: Optional[str] = None):
        entry = {
            "time": time.strftime("%H:%M:%S"),
            "level": level,
            "message": message,
            "uid": uid
        }
        self.logs.append(entry)
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    # ---------- ownership / limits ----------
    def default_owner(self) -> str:
        return user_store.admin_username()

    def bind_owner(self, login_key: str, acc_id: str) -> bool:
        """Attach a game account to the user who logged it in. False if another user already owns it."""
        acc_id = str(acc_id)
        owner = self.login_owners.get(str(login_key)) or self.default_owner()
        existing = self.account_owners.get(acc_id)
        if existing and existing != owner:
            return False
        self.account_owners[acc_id] = owner
        added = self.login_added.get(str(login_key))
        if added:
            self.account_added[acc_id] = added
        self.enforce_limit(acc_id)
        return True

    def limit_for(self, uid_str: str) -> int:
        return user_store.exp_limit(self.account_owners.get(str(uid_str)))

    def _release(self, acc: Optional[Dict[str, Any]], uid_str: str):
        if acc and acc.get("status") == "LIMIT_REACHED":
            acc["status"] = "PAUSED" if uid_str in self.paused_accounts else "ONLINE"

    def enforce_limit(self, uid_str: str):
        uid_str = str(uid_str)
        acc = self.accounts.get(uid_str)
        limit = self.limit_for(uid_str)
        if not acc or not limit:
            if uid_str in self.limit_blocked:
                self.limit_blocked.discard(uid_str)
                self._release(acc, uid_str)
            return
        if acc.get("gained_exp", 0) >= limit:
            if uid_str not in self.limit_blocked:
                self.limit_blocked.add(uid_str)
                self.log(f"Account {acc['nickname']} reached the EXP limit ({limit:,}). Leveling stopped.", "warning", uid_str)
            acc["status"] = "LIMIT_REACHED"
        elif uid_str in self.limit_blocked:
            self.limit_blocked.discard(uid_str)
            self._release(acc, uid_str)

    def apply_limits_for_user(self, username: str):
        for acc_id, owner in list(self.account_owners.items()):
            if str(owner).lower() == str(username).lower():
                self.enforce_limit(acc_id)

    def should_hold(self, uid_str: str) -> bool:
        """Stop launching matches once the matches already running are expected to reach the limit."""
        limit = self.limit_for(uid_str)
        acc = self.accounts.get(str(uid_str))
        if not limit or not acc:
            return False
        gained = acc.get("gained_exp", 0)
        played = acc.get("matches_played", 0)
        active = acc.get("active_matches", 0)
        avg = (gained / played) if (played > 0 and gained > 0) else 0
        if avg <= 0:
            return active >= 1   # EXP per match unknown yet: one match at a time
        return gained + active * avg >= limit

    def can_start(self, uid_str: str) -> bool:
        uid_str = str(uid_str)
        if uid_str in self.paused_accounts or uid_str in self.limit_blocked:
            return False
        return not self.should_hold(uid_str)

    def near_limit(self, uid_str: str) -> bool:
        limit = self.limit_for(uid_str)
        acc = self.accounts.get(str(uid_str))
        return bool(limit and acc and acc.get("gained_exp", 0) >= limit * 0.7)

    def refresh_interval(self, uid_str: str) -> int:
        return 15 if self.near_limit(uid_str) else 90

    # ---------- accounts ----------
    def register_account(self, uid: str, nickname: str, region: str, level: int, exp: int, likes: int = 0):
        uid_str = str(uid)
        if uid_str not in self.accounts:
            if uid_str not in self.baselines:
                self.baselines[uid_str] = exp
                try:
                    _write_json(BASELINE_FILE, self.baselines)
                except Exception:
                    pass
            base = self.baselines[uid_str]
            self.accounts[uid_str] = {
                "uid": uid_str,
                "nickname": nickname or f"Player_{uid_str[:6]}",
                "region": region or "BD",
                "level": level or 1,
                "initial_exp": base,
                "current_exp": exp,
                "gained_exp": max(0, exp - base),
                "likes": likes or 0,
                "status": "ONLINE",
                "matches_played": 0,
                "active_matches": 0,
                "last_match_time": None,
                "last_updated": time.strftime("%H:%M:%S")
            }
        else:
            acc = self.accounts[uid_str]
            if nickname:
                acc["nickname"] = nickname
            if region:
                acc["region"] = region
            if level:
                acc["level"] = level
            acc["current_exp"] = exp
            acc["gained_exp"] = max(0, exp - acc["initial_exp"])
            acc["likes"] = likes
            acc["status"] = "ONLINE"
            acc["last_updated"] = time.strftime("%H:%M:%S")
        self.recalc_totals()
        self.enforce_limit(uid_str)

    def update_exp(self, uid: str, current_exp: int, level: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            acc = self.accounts[uid_str]
            old_exp = acc["current_exp"]
            acc["current_exp"] = current_exp
            if level is not None and level > 0:
                acc["level"] = level
            acc["gained_exp"] = max(0, current_exp - acc["initial_exp"])
            acc["last_updated"] = time.strftime("%H:%M:%S")
            diff = current_exp - old_exp
            if diff > 0:
                self.log(f"Account {acc['nickname']} ({uid_str}) gained +{diff} EXP! Total Gained: +{acc['gained_exp']}", "success", uid_str)
            self.recalc_totals()
            self.enforce_limit(uid_str)

    def update_status(self, uid: str, status: str, active_matches: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            if uid_str in self.limit_blocked:
                status = "LIMIT_REACHED"
            elif uid_str in self.paused_accounts:
                status = "PAUSED"
            self.accounts[uid_str]["status"] = status
            if active_matches is not None:
                self.accounts[uid_str]["active_matches"] = active_matches
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")

    def increment_match(self, uid: str):
        uid_str = str(uid)
        self.total_matches += 1
        if uid_str in self.accounts:
            self.accounts[uid_str]["matches_played"] += 1
            self.accounts[uid_str]["last_match_time"] = time.strftime("%H:%M:%S")
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")
            self.log(f"Account {self.accounts[uid_str]['nickname']} finished Match #{self.accounts[uid_str]['matches_played']}", "info", uid_str)

    def login_result(self, key: str, success: bool, label: str = "", account_id: Optional[str] = None, error: str = ""):
        """Report the FIRST login attempt of an account to whoever is waiting (the Add Account request)."""
        fut = self.login_waiters.pop(str(key), None)
        if fut is not None and not fut.done():
            fut.set_result({"success": success, "label": label, "account_id": account_id, "error": error})

    def recalc_totals(self):
        self.total_gained_exp = sum(acc.get("gained_exp", 0) for acc in self.accounts.values())


bot_state = BotState()


# ==================== HELPERS ====================

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


def read_template(name: str) -> str:
    path = os.path.join(TEMPLATES_DIR, name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return f"<h1>templates/{name} not found!</h1>"


def html_response(text: str) -> web.Response:
    return web.Response(text=text, content_type="text/html", charset="utf-8")


def json_err(message: str, status: int = 200) -> web.Response:
    return web.json_response({"status": "error", "error": message}, status=status)


def api_auth(admin_only: bool = False):
    def deco(handler):
        async def wrapper(request):
            user = current_user(request)
            if not user:
                return json_err("Not logged in", 401)
            if admin_only and user.get("role") != "admin":
                return json_err("Admin only", 403)
            request["user"] = user
            return await handler(request)
        return wrapper
    return deco


def can_access(user: Dict[str, Any], acc_id: str) -> bool:
    if user.get("role") == "admin":
        return True
    return bot_state.account_owners.get(str(acc_id)) == user.get("username")


def purge_account(acc_id: str):
    """Remove a game account everywhere: accounts.json, running worker, dashboard state."""
    acc_id = str(acc_id)
    creds = bot_state.account_credentials.get(acc_id) or {}
    login_uid = str(creds.get("auth_uid") or "").strip()
    login_token = str(creds.get("auth_token") or "").strip()
    owner = bot_state.account_owners.get(acc_id) or bot_state.default_owner()

    def is_target(entry: Dict[str, Any]) -> bool:
        if (entry.get("owner") or bot_state.default_owner()) != owner:
            return False
        if str(entry.get("uid", "")).strip() in ({acc_id, login_uid} - {""}):
            return True
        tok = str(entry.get("token", "")).strip()
        return bool(login_token) and tok == login_token

    existing = _read_json(ACCOUNTS_FILE, [])
    if os.path.exists(ACCOUNTS_FILE):
        _write_json(ACCOUNTS_FILE, [e for e in existing if not is_target(e)])

    keys = {acc_id}
    if login_uid:
        keys.add(login_uid)
    if login_token:
        keys.add(login_token[:10])
    for key in keys:
        task = bot_state.account_workers.pop(key, None)
        if task:
            task.cancel()
        bot_state.login_owners.pop(key, None)

    bot_state.accounts.pop(acc_id, None)
    bot_state.paused_accounts.discard(acc_id)
    bot_state.limit_blocked.discard(acc_id)
    bot_state.account_owners.pop(acc_id, None)
    bot_state.account_added.pop(acc_id, None)
    for k in [k for k, v in bot_state.account_credentials.items() if creds and v is creds]:
        bot_state.account_credentials.pop(k, None)
    bot_state.recalc_totals()
    bot_state.log(f"Account {acc_id} removed from rotation.", "warning", acc_id)


# ==================== PAGES ====================

async def handle_index(request: web.Request) -> web.Response:
    if not current_user(request):
        raise web.HTTPFound("/login")
    return html_response(read_template("index.html"))


def _login_page(role: str):
    async def handler(request: web.Request) -> web.Response:
        user = current_user(request)
        if user and user.get("role") == role:
            raise web.HTTPFound("/admin" if role == "admin" else "/")
        page = read_template("login.html")
        if role == "admin":
            repl = {
                "__TITLE__": "Admin Login",
                "__SUBTITLE__": "Restricted area - administrators only",
                "__ENDPOINT__": "/api/admin/login",
                "__BADGE__": '<i class="fa-solid fa-shield-halved"></i> ADMIN',
                "__ALT__": '<a href="/login">&larr; User login</a>',
            }
        else:
            repl = {
                "__TITLE__": "Sign In",
                "__SUBTITLE__": "Log in to manage your accounts",
                "__ENDPOINT__": "/api/login",
                "__BADGE__": '<i class="fa-solid fa-user"></i> USER',
                "__ALT__": "",
            }
        for k, v in repl.items():
            page = page.replace(k, v)
        return html_response(page)
    return handler


async def handle_admin_page(request: web.Request) -> web.Response:
    user = current_user(request)
    if not user or user.get("role") != "admin":
        raise web.HTTPFound("/admin/login")
    return html_response(read_template("admin.html"))


async def handle_health(request: web.Request) -> web.Response:
    return web.Response(text="ok", content_type="text/plain")


# ==================== AUTH API ====================

async def _do_login(request: web.Request, role: str) -> web.Response:
    ip = request.remote or "?"
    if throttled(ip):
        return json_err("Too many failed attempts. Try again in a few minutes.", 429)
    try:
        data = await request.json()
    except Exception:
        return json_err("Invalid request", 400)
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    user = user_store.find(username)
    loop = asyncio.get_running_loop()
    ok = False
    if user and user.get("role") == role:
        ok = await loop.run_in_executor(None, verify_password, password, user.get("password_hash", ""))
    else:
        await loop.run_in_executor(None, verify_password, password, DUMMY_HASH)
    if not ok:
        login_failures.setdefault(ip, []).append(time.time())
        return json_err("Invalid username or password", 401)
    login_failures.pop(ip, None)
    token = create_session(user["username"])
    resp = web.json_response({"status": "ok", "redirect": "/admin" if role == "admin" else "/"})
    resp.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL, httponly=True, samesite="Lax", secure=bool(request.secure), path="/")
    return resp


async def handle_login(request: web.Request) -> web.Response:
    return await _do_login(request, "user")


async def handle_admin_login(request: web.Request) -> web.Response:
    return await _do_login(request, "admin")


async def handle_logout(request: web.Request) -> web.Response:
    token = request.cookies.get(COOKIE_NAME)
    user = current_user(request)
    if token:
        sessions.pop(token, None)
    resp = web.json_response({"status": "ok", "redirect": "/admin/login" if (user and user.get("role") == "admin") else "/login"})
    resp.del_cookie(COOKIE_NAME, path="/")
    return resp


# ==================== DASHBOARD API ====================

@api_auth()
async def handle_get_stats(request: web.Request) -> web.Response:
    user = request["user"]
    is_admin = user.get("role") == "admin"
    owners = bot_state.account_owners
    accs = [a for uid, a in bot_state.accounts.items() if is_admin or owners.get(uid) == user["username"]]
    accounts_data = [
        dict(a,
             is_paused=(a["uid"] in bot_state.paused_accounts),
             limit_reached=(a["uid"] in bot_state.limit_blocked),
             owner=owners.get(a["uid"], ""))
        for a in accs
    ]
    accounts_data.sort(key=lambda x: x.get("gained_exp", 0), reverse=True)
    return web.json_response({
        "username": user["username"],
        "role": user.get("role", "user"),
        "exp_limit": user_store.exp_limit(user["username"]),
        "total_accounts": len(accounts_data),
        "total_matches": bot_state.total_matches if is_admin else sum(a.get("matches_played", 0) for a in accs),
        "total_gained_exp": sum(a.get("gained_exp", 0) for a in accs),
        "accounts": accounts_data,
        "logs": bot_state.logs[-60:] if is_admin else [],
        "uptime": int(time.time() - bot_state.start_time)
    })


@api_auth()
async def handle_add_account(request: web.Request) -> web.Response:
    try:
        user = request["user"]
        owner = user["username"]
        admin_name = bot_state.default_owner()
        data = await request.json()
        existing = _read_json(ACCOUNTS_FILE, [])
        if not isinstance(existing, list):
            existing = []

        if "uid" in data and "password" in data:
            uid = str(data["uid"]).strip()
            pwd = str(data["password"]).strip()
            if not uid or not pwd:
                return json_err("UID and Password are required")
            key, label, token = uid, uid, ""
            same = lambda a: str(a.get("uid")) == uid
            new_entry = {"uid": uid, "password": pwd, "owner": owner, "added_at": time.strftime("%Y-%m-%d %H:%M")}
        elif "token" in data:
            token = str(data["token"]).strip()
            if not token:
                return json_err("Token is required")
            key, label, uid = token[:10], f"Token {token[:10]}...", ""
            same = lambda a: a.get("token") == token
            new_entry = {"token": token, "owner": owner, "added_at": time.strftime("%Y-%m-%d %H:%M")}
        else:
            return json_err("Invalid payload")

        for a in existing:
            if same(a) and (a.get("owner") or admin_name) != owner:
                return json_err("This account is already added")

        existing = [a for a in existing if not same(a)]
        existing.append(new_entry)
        _write_json(ACCOUNTS_FILE, existing)
        bot_state.login_owners[key] = owner
        bot_state.login_added[key] = new_entry["added_at"]
        bot_state.log(f"New account added by {owner}: {data.get('uid') or 'Token'}", "success")

        if "on_account_added" not in bot_state.refresh_callbacks:
            return web.json_response({"status": "ok"})

        # Launch the worker and wait for its FIRST login attempt (single attempt, no retry)
        waiter = asyncio.get_running_loop().create_future()
        bot_state.login_waiters[key] = waiter
        asyncio.create_task(bot_state.refresh_callbacks["on_account_added"](data))

        try:
            result = await asyncio.wait_for(waiter, timeout=120)
        except asyncio.TimeoutError:
            bot_state.login_waiters.pop(key, None)
            result = {"success": False, "error": "Login timed out"}

        if result.get("success"):
            acc = bot_state.accounts.get(str(result.get("account_id")), {})
            return web.json_response({"status": "ok", "login": "success", "label": label, "account": acc})

        # Failed: do not keep the account in accounts.json
        try:
            saved = _read_json(ACCOUNTS_FILE, [])
            saved = [a for a in saved if not (same(a) and (a.get("owner") or admin_name) == owner)]
            _write_json(ACCOUNTS_FILE, saved)
        except Exception:
            pass
        bot_state.login_owners.pop(key, None)
        return web.json_response({
            "status": "error", "login": "failed", "label": label,
            "error": result.get("error") or "Login failed"
        })
    except Exception as e:
        return json_err(str(e))


@api_auth()
async def handle_delete_account(request: web.Request) -> web.Response:
    try:
        user = request["user"]
        data = await request.json()
        uid = str(data.get("uid")).strip()
        if not can_access(user, uid):
            return json_err("Account not found")
        purge_account(uid)
        return web.json_response({"status": "ok"})
    except Exception as e:
        return json_err(str(e))


@api_auth()
async def handle_refresh_account(request: web.Request) -> web.Response:
    try:
        user = request["user"]
        data = await request.json()
        uid = str(data.get("uid")).strip()
        if not can_access(user, uid):
            return json_err("Account not found")
        if "on_refresh_account" in bot_state.refresh_callbacks:
            asyncio.create_task(bot_state.refresh_callbacks["on_refresh_account"](uid))
        return web.json_response({"status": "ok"})
    except Exception as e:
        return json_err(str(e))


@api_auth()
async def handle_pause_account(request: web.Request) -> web.Response:
    try:
        user = request["user"]
        data = await request.json()
        uid = str(data.get("uid")).strip()
        if uid not in bot_state.accounts or not can_access(user, uid):
            return json_err("Account not found")
        if uid in bot_state.limit_blocked:
            return json_err("EXP limit reached - leveling is stopped for this account")
        if uid in bot_state.paused_accounts:
            bot_state.paused_accounts.discard(uid)
            bot_state.accounts[uid]["status"] = "ONLINE"
            bot_state.log(f"Account {bot_state.accounts[uid]['nickname']} resumed.", "success", uid)
            paused = False
        else:
            bot_state.paused_accounts.add(uid)
            bot_state.accounts[uid]["status"] = "PAUSED"
            bot_state.log(f"Account {bot_state.accounts[uid]['nickname']} paused.", "warning", uid)
            paused = True
        return web.json_response({"status": "ok", "is_paused": paused})
    except Exception as e:
        return json_err(str(e))


# ==================== ADMIN API ====================

def _parse_limit(value: Any) -> Optional[int]:
    try:
        n = int(str(value).strip() or "0")
    except Exception:
        return None
    return n if 0 <= n <= 1_000_000_000 else None


@api_auth(admin_only=True)
async def handle_admin_users(request: web.Request) -> web.Response:
    rows = []
    for u in user_store.users:
        if u.get("role") != "user":
            continue
        ids = [i for i, o in bot_state.account_owners.items() if str(o).lower() == u["username"].lower()]
        live = [bot_state.accounts[i] for i in ids if i in bot_state.accounts]
        rows.append({
            "username": u["username"],
            "exp_limit": int(u.get("exp_limit") or 0),
            "created_at": u.get("created_at", ""),
            "accounts": len(live),
            "limit_reached": sum(1 for i in ids if i in bot_state.limit_blocked),
            "gained_exp": sum(a.get("gained_exp", 0) for a in live),
        })
    return web.json_response({
        "status": "ok",
        "admin": request["user"]["username"],
        "users": rows,
        "total_accounts": len(bot_state.accounts),
        "total_gained_exp": sum(a.get("gained_exp", 0) for a in bot_state.accounts.values()),
    })


@api_auth(admin_only=True)
async def handle_admin_accounts(request: web.Request) -> web.Response:
    """Every running game account and the user (or admin) who opened it."""
    rows = []
    for uid, a in bot_state.accounts.items():
        owner = bot_state.account_owners.get(uid, "")
        ou = user_store.find(owner)
        rows.append({
            "uid": uid,
            "nickname": a.get("nickname", ""),
            "region": a.get("region", ""),
            "level": a.get("level", 1),
            "status": a.get("status", ""),
            "is_paused": uid in bot_state.paused_accounts,
            "limit_reached": uid in bot_state.limit_blocked,
            "gained_exp": a.get("gained_exp", 0),
            "current_exp": a.get("current_exp", 0),
            "matches_played": a.get("matches_played", 0),
            "active_matches": a.get("active_matches", 0),
            "last_match_time": a.get("last_match_time"),
            "owner": owner,
            "owner_role": (ou.get("role") if ou else "unknown"),
            "exp_limit": user_store.exp_limit(owner),
            "added_at": bot_state.account_added.get(uid, ""),
        })
    rows.sort(key=lambda r: (r["owner_role"] != "admin", r["owner"].lower(), -r["gained_exp"]))
    live = [r for r in rows if not r["is_paused"] and not r["limit_reached"]]
    return web.json_response({
        "status": "ok",
        "accounts": rows,
        "total": len(rows),
        "running": len(live),
        "in_match": sum(1 for r in live if r["status"] == "IN_MATCH"),
        "paused": sum(1 for r in rows if r["is_paused"]),
        "limit_reached": sum(1 for r in rows if r["limit_reached"]),
        "admin_accounts": sum(1 for r in rows if r["owner_role"] == "admin"),
        "user_accounts": sum(1 for r in rows if r["owner_role"] == "user"),
    })


@api_auth(admin_only=True)
async def handle_admin_user_pause(request: web.Request) -> web.Response:
    """Pause / resume every account that belongs to one person."""
    try:
        data = await request.json()
        owner = user_store.find(str(data.get("username", "")))
        action = str(data.get("action", ""))
        if not owner or action not in ("pause", "resume"):
            return json_err("Invalid request")
        changed = 0
        for uid, o in list(bot_state.account_owners.items()):
            if str(o).lower() != owner["username"].lower() or uid not in bot_state.accounts or uid in bot_state.limit_blocked:
                continue
            if action == "pause" and uid not in bot_state.paused_accounts:
                bot_state.paused_accounts.add(uid)
                bot_state.accounts[uid]["status"] = "PAUSED"
                changed += 1
            elif action == "resume" and uid in bot_state.paused_accounts:
                bot_state.paused_accounts.discard(uid)
                bot_state.accounts[uid]["status"] = "ONLINE"
                changed += 1
        bot_state.log(f"Admin {action}d {changed} account(s) of '{owner['username']}'.", "info")
        return web.json_response({"status": "ok", "changed": changed})
    except Exception as e:
        return json_err(str(e))


@api_auth(admin_only=True)
async def handle_admin_create_user(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        limit = _parse_limit(data.get("exp_limit", 0))
        if not USERNAME_RE.match(username):
            return json_err("Username must be 3-32 characters: letters, numbers, . _ -")
        if len(password) < MIN_PASSWORD_LEN:
            return json_err(f"Password must be at least {MIN_PASSWORD_LEN} characters")
        if limit is None:
            return json_err("EXP limit must be a number (0 = unlimited)")
        if user_store.find(username):
            return json_err("Username already exists")
        pw_hash = await asyncio.get_running_loop().run_in_executor(None, hash_password, password)
        user_store.users.append({
            "username": username,
            "role": "user",
            "password_hash": pw_hash,
            "exp_limit": limit,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        user_store.save()
        bot_state.log(f"User '{username}' created (EXP limit {limit:,}).", "success")
        return web.json_response({"status": "ok"})
    except Exception as e:
        return json_err(str(e))


@api_auth(admin_only=True)
async def handle_admin_update_user(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        user = user_store.find(str(data.get("username", "")))
        if not user or user.get("role") != "user":
            return json_err("User not found")
        if "exp_limit" in data:
            limit = _parse_limit(data.get("exp_limit"))
            if limit is None:
                return json_err("EXP limit must be a number (0 = unlimited)")
            user["exp_limit"] = limit
        if data.get("password"):
            password = str(data["password"])
            if len(password) < MIN_PASSWORD_LEN:
                return json_err(f"Password must be at least {MIN_PASSWORD_LEN} characters")
            user["password_hash"] = await asyncio.get_running_loop().run_in_executor(None, hash_password, password)
            drop_sessions_of(user["username"])
        user_store.save()
        bot_state.apply_limits_for_user(user["username"])
        return web.json_response({"status": "ok"})
    except Exception as e:
        return json_err(str(e))


@api_auth(admin_only=True)
async def handle_admin_delete_user(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        user = user_store.find(str(data.get("username", "")))
        if not user or user.get("role") != "user":
            return json_err("User not found")
        name = user["username"]
        for acc_id in [i for i, o in bot_state.account_owners.items() if str(o).lower() == name.lower()]:
            purge_account(acc_id)
        # entries that never logged in (still sitting in accounts.json)
        saved = _read_json(ACCOUNTS_FILE, [])
        _write_json(ACCOUNTS_FILE, [a for a in saved if str(a.get("owner", "")).lower() != name.lower()])
        for key in [k for k, v in bot_state.login_owners.items() if str(v).lower() == name.lower()]:
            task = bot_state.account_workers.pop(key, None)
            if task:
                task.cancel()
            bot_state.login_owners.pop(key, None)
        user_store.users = [u for u in user_store.users if u is not user]
        user_store.save()
        drop_sessions_of(name)
        bot_state.log(f"User '{name}' deleted with all their accounts.", "warning")
        return web.json_response({"status": "ok"})
    except Exception as e:
        return json_err(str(e))


# ==================== SERVER ====================

async def start_web_dashboard(host: str = "0.0.0.0", port: int = 5000):
    user_store.ensure_admin()
    app = web.Application()
    app.router.add_get("/health", handle_health)
    app.router.add_get("/", handle_index)
    app.router.add_get("/login", _login_page("user"))
    app.router.add_get("/admin/login", _login_page("admin"))
    app.router.add_get("/admin", handle_admin_page)
    app.router.add_post("/api/login", handle_login)
    app.router.add_post("/api/admin/login", handle_admin_login)
    app.router.add_post("/api/logout", handle_logout)
    app.router.add_get("/api/stats", handle_get_stats)
    app.router.add_post("/api/account/add", handle_add_account)
    app.router.add_post("/api/account/delete", handle_delete_account)
    app.router.add_post("/api/account/refresh", handle_refresh_account)
    app.router.add_post("/api/account/pause", handle_pause_account)
    app.router.add_get("/api/admin/users", handle_admin_users)
    app.router.add_get("/api/admin/accounts", handle_admin_accounts)
    app.router.add_post("/api/admin/users/pause", handle_admin_user_pause)
    app.router.add_post("/api/admin/users/create", handle_admin_create_user)
    app.router.add_post("/api/admin/users/update", handle_admin_update_user)
    app.router.add_post("/api/admin/users/delete", handle_admin_delete_user)

    runner = web.AppRunner(app)
    await runner.setup()

    # None = every network interface (IPv4 + IPv6), so the site is reachable from outside, not only locally
    bind_host = None if host in ("0.0.0.0", "::", "", None) else host
    ports = [int(port)]
    env_port = os.environ.get("PORT", "").strip()      # Railway / Render / Heroku style hosts set this
    if env_port.isdigit() and int(env_port) not in ports:
        ports.append(int(env_port))

    listening = []
    for p in ports:
        try:
            await web.TCPSite(runner, bind_host, p).start()
            listening.append(p)
        except OSError as e:
            print(f"\033[93m[!] Could not listen on port {p}: {e}\033[0m")
    if not listening:
        raise OSError(f"Web Dashboard could not listen on any port ({ports})")
    shown = ", ".join(str(p) for p in listening)
    print(f"\033[92m[+] Web Dashboard listening on all interfaces, port {shown} (public - not local only)\033[0m")
