#!/usr/bin/env python3
"""
HaFunnel - a token-protected HTTPS funnel in front of Home Assistant.

Design guarantees
-----------------
* Every endpoint requires a client bearer token (checked against SHA-256 hashes).
* Read endpoints are GET/HEAD only.
* Writes are limited by construction to the regular oven only
  (switch.oven_*, select.oven_*, number.oven_*). No other entity or service
  can be written. The upstream client never receives an unconstrained POST.
* Only entities in allowed domains are visible; entity ids are strictly validated.
* The server refuses to start without a TLS certificate and key.
* Optional e-mail alert whenever someone attempts a disallowed write method/path.
* Optional access gate: requests are only served outside the night window AND
  while the alarm reports DISARMED (fails closed if the alarm cannot be read).

Usage
-----
    python hafunnel.py gen-token                    # create a client token (+ its hash)
    python hafunnel.py serve [--config config.json] # run the server
"""
import argparse
import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import smtplib
import ssl
import stat
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from datetime import time as dt_time
from email.message import EmailMessage
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

log = logging.getLogger("hafunnel")

DEFAULT_ALLOWED_DOMAINS = [
    "sensor", "binary_sensor", "weather", "sun", "climate", "light", "switch",
    "cover", "fan", "input_boolean", "input_number", "input_select", "input_text",
    "humidifier", "media_player", "vacuum", "water_heater", "number", "select",
]
# Deliberately NOT in the defaults: camera (entity_picture URLs carry access
# tokens), lock, alarm_control_panel, person, device_tracker (privacy/security).

# --------------------------------------------------------------------------- #
# Configuration (loaded from config.json by load_config())
# --------------------------------------------------------------------------- #
HA_URL = ""
HA_TOKEN = ""
HA_VERIFY_TLS = True
CLIENT_TOKEN_HASHES: set[str] = set()
ALLOWED_DOMAINS: set[str] = set(DEFAULT_ALLOWED_DOMAINS)
BIND_HOST = "0.0.0.0"
BIND_PORT = 8443
TLS_CERT = ""
TLS_KEY = ""
MAX_HISTORY_DAYS = 7

# Access gate (optional, configured by the "access_gate" section)
GATE_ENABLED = False
GATE_ALARM_URL = ""
GATE_STATE_KEY = "alarm_state"
GATE_DISARMED_VALUE = "DISARMED"
GATE_NIGHT_START: Optional[dt_time] = None
GATE_NIGHT_END: Optional[dt_time] = None
GATE_TZ: Optional[ZoneInfo] = None
GATE_TIMEOUT = 5.0

# E-mail alerts for write attempts (optional, "alerts" section)
ALERT_ENABLED = False
ALERT_HOST = ""
ALERT_PORT = 587
ALERT_SECURITY = "starttls"  # starttls | ssl | none
ALERT_USER = ""
ALERT_PASSWORD = ""
ALERT_FROM = ""
ALERT_TO: list[str] = []
ALERT_MAX_PER_HOUR = 10
ALERT_PREFIX = "[HaFunnel]"

# Brute-force protection: max failed auth attempts per IP per window.
MAX_FAILURES = 10
FAIL_WINDOW_SECONDS = 60

ENTITY_ID_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ConfigError(Exception):
    pass


def load_config(path: Path) -> None:
    """Read and validate config.json, populating the module-level settings."""
    global HA_URL, HA_TOKEN, HA_VERIFY_TLS, CLIENT_TOKEN_HASHES, ALLOWED_DOMAINS
    global BIND_HOST, BIND_PORT, TLS_CERT, TLS_KEY, MAX_HISTORY_DAYS
    global GATE_ENABLED, GATE_ALARM_URL, GATE_STATE_KEY, GATE_DISARMED_VALUE
    global GATE_NIGHT_START, GATE_NIGHT_END, GATE_TZ, GATE_TIMEOUT
    global ALERT_ENABLED, ALERT_HOST, ALERT_PORT, ALERT_SECURITY, ALERT_USER
    global ALERT_PASSWORD, ALERT_FROM, ALERT_TO, ALERT_MAX_PER_HOUR, ALERT_PREFIX

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"Config file not found: {path}")
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Config file is not valid JSON: {exc}")
    if not isinstance(raw, dict):
        raise ConfigError("Config root must be a JSON object")

    # The file holds secrets; warn if other users can read it.
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            log.warning("%s is readable by other users; run: chmod 600 %s", path, path)
    except OSError:
        pass

    ha = raw.get("home_assistant", {})
    srv = raw.get("server", {})
    base = path.resolve().parent  # relative cert paths are relative to the config file

    def resolve(p: str) -> str:
        return str((base / p).resolve()) if p else ""

    HA_URL = str(ha.get("url", "")).rstrip("/")
    HA_TOKEN = str(ha.get("token", ""))
    HA_VERIFY_TLS = bool(ha.get("verify_tls", True))

    BIND_HOST = str(srv.get("host", "0.0.0.0"))
    BIND_PORT = int(srv.get("port", 8443))
    TLS_CERT = resolve(str(srv.get("tls_cert", "")))
    TLS_KEY = resolve(str(srv.get("tls_key", "")))

    hashes = raw.get("client_token_hashes", [])
    if not isinstance(hashes, list):
        raise ConfigError("client_token_hashes must be a list")
    CLIENT_TOKEN_HASHES = {str(h).strip().lower() for h in hashes if str(h).strip()}

    domains = raw.get("allowed_domains", DEFAULT_ALLOWED_DOMAINS)
    if not isinstance(domains, list):
        raise ConfigError("allowed_domains must be a list")
    ALLOWED_DOMAINS = {str(d).strip() for d in domains if str(d).strip()}

    MAX_HISTORY_DAYS = int(raw.get("max_history_days", 7))

    problems = []

    # Optional access gate. Remove the "access_gate" section to disable it.
    GATE_ENABLED = False
    gate = raw.get("access_gate")
    if gate is not None:
        if not isinstance(gate, dict):
            problems.append("access_gate must be an object")
        else:
            GATE_ALARM_URL = str(gate.get("alarm_url", ""))
            GATE_STATE_KEY = str(gate.get("state_key", "alarm_state"))
            GATE_DISARMED_VALUE = str(gate.get("disarmed_value", "DISARMED"))
            GATE_TIMEOUT = float(gate.get("timeout_seconds", 5))
            if not GATE_ALARM_URL.startswith(("http://", "https://")):
                problems.append("access_gate.alarm_url must start with http:// or https://")
            try:
                GATE_NIGHT_START = datetime.strptime(str(gate.get("night_start", "")), "%H:%M").time()
                GATE_NIGHT_END = datetime.strptime(str(gate.get("night_end", "")), "%H:%M").time()
                if GATE_NIGHT_START == GATE_NIGHT_END:
                    problems.append("access_gate.night_start and night_end must differ")
            except ValueError:
                problems.append('access_gate.night_start / night_end must be "HH:MM" (24h)')
            tzname = gate.get("timezone")
            try:
                GATE_TZ = ZoneInfo(str(tzname)) if tzname else None  # None = server local time
            except ZoneInfoNotFoundError:
                problems.append(f"access_gate.timezone is not a valid IANA timezone: {tzname}")
            GATE_ENABLED = True

    # Optional e-mail alerts. Remove the "alerts" section to disable them.
    ALERT_ENABLED = False
    alerts = raw.get("alerts")
    if alerts is not None:
        if not isinstance(alerts, dict):
            problems.append("alerts must be an object")
        else:
            ALERT_HOST = str(alerts.get("smtp_host", ""))
            ALERT_PORT = int(alerts.get("smtp_port", 587))
            ALERT_SECURITY = str(alerts.get("smtp_security", "starttls")).lower()
            ALERT_USER = str(alerts.get("smtp_username", ""))
            ALERT_PASSWORD = str(alerts.get("smtp_password", ""))
            ALERT_FROM = str(alerts.get("from", ""))
            to = alerts.get("to", [])
            ALERT_TO = [str(t).strip() for t in to if str(t).strip()] if isinstance(to, list) else []
            ALERT_MAX_PER_HOUR = int(alerts.get("max_emails_per_hour", 10))
            ALERT_PREFIX = str(alerts.get("subject_prefix", "[HaFunnel]"))
            if not ALERT_HOST:
                problems.append("alerts.smtp_host is required")
            if not ALERT_FROM:
                problems.append("alerts.from is required")
            if not ALERT_TO:
                problems.append("alerts.to must be a non-empty list of e-mail addresses")
            if ALERT_SECURITY not in ("starttls", "ssl", "none"):
                problems.append('alerts.smtp_security must be "starttls", "ssl" or "none"')
            if ALERT_USER and ALERT_SECURITY == "none":
                problems.append("alerts: refusing to send SMTP credentials without TLS "
                                '(set smtp_security to "starttls" or "ssl")')
            if ALERT_MAX_PER_HOUR < 1:
                problems.append("alerts.max_emails_per_hour must be at least 1")
            ALERT_ENABLED = True
    if not HA_URL.startswith(("http://", "https://")):
        problems.append("home_assistant.url must start with http:// or https://")
    if not HA_TOKEN or HA_TOKEN.startswith("PASTE_"):
        problems.append("home_assistant.token is not set")
    if not CLIENT_TOKEN_HASHES:
        problems.append("client_token_hashes is empty (run: hafunnel.py gen-token)")
    for h in CLIENT_TOKEN_HASHES:
        if not SHA256_RE.match(h):
            problems.append(f"client_token_hashes entry is not a SHA-256 hex digest: {h[:12]}...")
    if not (TLS_CERT and TLS_KEY and Path(TLS_CERT).is_file() and Path(TLS_KEY).is_file()):
        problems.append("server.tls_cert / server.tls_key must point to existing files")
    if problems:
        raise ConfigError("\n  - ".join(["Invalid configuration:"] + problems))


# --------------------------------------------------------------------------- #
# Upstream Home Assistant client
# --------------------------------------------------------------------------- #
# ha_get is unrestricted (subject to domain filter on the way out).
# ha_post is only callable for oven write paths; the allow-list is enforced
# before any request leaves this process.
# --------------------------------------------------------------------------- #
_ha_client: Optional[httpx.AsyncClient] = None

# Regular oven only (not microwave_oven / dishwasher / induction_cooktop).
OVEN_WRITE_ENTITIES = frozenset({
    "switch.oven_power",
    "switch.oven_child_lock",
    "select.oven_selected_programme",
    "select.oven_active_programme",
    "number.oven_alarm_clock",
})

# domain -> set of services we will proxy for the oven entities above.
OVEN_WRITE_SERVICES = {
    "switch": frozenset({"turn_on", "turn_off", "toggle"}),
    "select": frozenset({"select_option"}),
    "number": frozenset({"set_value"}),
}


def _client() -> httpx.AsyncClient:
    global _ha_client
    if _ha_client is None:
        _ha_client = httpx.AsyncClient(
            base_url=HA_URL,
            headers={"Authorization": f"Bearer {HA_TOKEN}"},
            verify=HA_VERIFY_TLS,
            timeout=15.0,
        )
    return _ha_client


async def ha_get(path: str, params: Optional[dict] = None):
    """GET against Home Assistant."""
    try:
        r = await _client().get(path, params=params)
    except httpx.HTTPError as exc:
        log.error("Home Assistant unreachable: %s", exc)
        raise HTTPException(502, "Home Assistant unreachable")
    if r.status_code == 404:
        raise HTTPException(404, "Not found")
    if r.status_code >= 400:
        log.error("Home Assistant returned %s for %s", r.status_code, path)
        raise HTTPException(502, "Upstream error")
    return r.json()


async def ha_post(path: str, body: dict):
    """POST against Home Assistant. Caller must already have enforced the oven allow-list."""
    try:
        r = await _client().post(path, json=body)
    except httpx.HTTPError as exc:
        log.error("Home Assistant unreachable: %s", exc)
        raise HTTPException(502, "Home Assistant unreachable")
    if r.status_code == 404:
        raise HTTPException(404, "Not found")
    if r.status_code >= 400:
        # Surface HA's message when present; still do not leak arbitrary upstream bodies.
        detail = "Upstream error"
        try:
            j = r.json()
            if isinstance(j, dict) and j.get("message"):
                detail = str(j["message"])[:200]
        except Exception:
            pass
        log.error("Home Assistant returned %s for %s: %s", r.status_code, path, detail)
        raise HTTPException(502, detail)
    # Many HA service calls return 200 with empty body.
    if not r.content:
        return {"ok": True}
    try:
        return r.json()
    except Exception:
        return {"ok": True}


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
bearer = HTTPBearer(auto_error=False)
_failures: dict[str, deque] = defaultdict(deque)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _token_is_valid(token: str) -> bool:
    if not token:
        return False
    digest = hashlib.sha256(token.encode()).hexdigest()
    ok = False
    for allowed in CLIENT_TOKEN_HASHES:  # compare against every hash, no short-circuit
        if hmac.compare_digest(digest, allowed):
            ok = True
    return ok


def _check_throttle(ip: str) -> None:
    now = time.monotonic()
    q = _failures[ip]
    while q and now - q[0] > FAIL_WINDOW_SECONDS:
        q.popleft()
    if len(q) >= MAX_FAILURES:
        raise HTTPException(429, "Too many failed attempts", headers={"Retry-After": str(FAIL_WINDOW_SECONDS)})


async def require_token(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
) -> None:
    ip = _client_ip(request)
    _check_throttle(ip)

    ok = bool(creds and creds.scheme.lower() == "bearer" and _token_is_valid(creds.credentials))
    if not ok:
        _failures[ip].append(time.monotonic())
        log.warning("Rejected request from %s", ip)
        raise HTTPException(401, "Invalid or missing token", headers={"WWW-Authenticate": "Bearer"})


# --------------------------------------------------------------------------- #
# Access gate: allowed only when it is NOT night AND the alarm is DISARMED
# --------------------------------------------------------------------------- #
def _in_night(t: dt_time) -> bool:
    """True if t is inside the night window [start, end). Handles windows crossing midnight."""
    start, end = GATE_NIGHT_START, GATE_NIGHT_END
    if start < end:
        return start <= t < end
    return t >= start or t < end


async def _alarm_is_disarmed() -> bool:
    """Ask the alarm's HTTP endpoint. Any failure raises 503 (fail closed).

    Uses its own client so the Home Assistant token is never sent to this URL.
    """
    try:
        async with httpx.AsyncClient(timeout=GATE_TIMEOUT) as c:
            r = await c.get(GATE_ALARM_URL)
        r.raise_for_status()
        state = r.json()[GATE_STATE_KEY]
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        log.error("Alarm status check failed: %s", exc)
        raise HTTPException(503, "Access check unavailable")
    return isinstance(state, str) and state.strip().upper() == GATE_DISARMED_VALUE.upper()


async def require_access(_: None = Depends(require_token)) -> None:
    """Token check first, then the gate: allowed only outside the night window
    AND while the alarm is DISARMED. Anything else is denied."""
    if not GATE_ENABLED:
        return
    if _in_night(datetime.now(GATE_TZ).time()):
        log.info("Request denied: inside night window")
        raise HTTPException(403, "Access not allowed right now")
    if await _alarm_is_disarmed():
        return
    log.info("Request denied: alarm not disarmed")
    raise HTTPException(403, "Access not allowed right now")


# --------------------------------------------------------------------------- #
# E-mail alerts for write attempts
# --------------------------------------------------------------------------- #
_alert_times: deque = deque()
_alert_suppressed = 0
_background_tasks: set = set()


def _clean(value: str, limit: int = 300) -> str:
    """Escape control/non-ASCII characters and truncate (request data is attacker-controlled)."""
    return value.encode("unicode_escape").decode("ascii")[:limit]


def _source_ip(request: Request) -> tuple[str, str]:
    """Return (best-guess client IP, how it was determined).

    Behind a local reverse proxy (e.g. Tailscale Funnel) the TCP peer is
    127.0.0.1, so the proxy's X-Forwarded-For is used when the peer is loopback.
    The LAST entry is taken, because that is the one the nearest proxy added.
    """
    peer = request.client.host if request.client else "unknown"
    xff = request.headers.get("x-forwarded-for", "")
    if xff and peer in ("127.0.0.1", "::1"):
        candidate = xff.split(",")[-1].strip()
        try:
            return str(ipaddress.ip_address(candidate)), "X-Forwarded-For"
        except ValueError:
            pass
    return peer, "direct connection"


def _send_email(subject: str, body: str) -> None:
    """Blocking SMTP send; run in a worker thread. Never raises."""
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = ALERT_FROM
        msg["To"] = ", ".join(ALERT_TO)
        msg.set_content(body)
        ctx = ssl.create_default_context()
        if ALERT_SECURITY == "ssl":
            smtp = smtplib.SMTP_SSL(ALERT_HOST, ALERT_PORT, timeout=10, context=ctx)
        else:
            smtp = smtplib.SMTP(ALERT_HOST, ALERT_PORT, timeout=10)
        with smtp:
            if ALERT_SECURITY == "starttls":
                smtp.starttls(context=ctx)
            if ALERT_USER:
                smtp.login(ALERT_USER, ALERT_PASSWORD)
            smtp.send_message(msg)
        log.info("Alert e-mail sent to %s", ", ".join(ALERT_TO))
    except (OSError, smtplib.SMTPException, ValueError) as exc:
        log.error("Failed to send alert e-mail: %s", exc)


def notify_write_attempt(request: Request) -> None:
    """Queue an alert e-mail for a non-GET request (rate limited, non-blocking)."""
    global _alert_suppressed
    if not ALERT_ENABLED:
        return
    now = time.monotonic()
    while _alert_times and now - _alert_times[0] > 3600:
        _alert_times.popleft()
    if len(_alert_times) >= ALERT_MAX_PER_HOUR:
        _alert_suppressed += 1
        return
    suppressed, _alert_suppressed = _alert_suppressed, 0
    _alert_times.append(now)

    ip, how = _source_ip(request)
    peer = request.client.host if request.client else "unknown"
    auth = request.headers.get("authorization", "")
    scheme, _, cred = auth.partition(" ")
    token_valid = scheme.lower() == "bearer" and _token_is_valid(cred.strip())

    subject = f"{ALERT_PREFIX} Blocked {_clean(request.method, 12)} request from {ip}"
    lines = [
        "A disallowed write request was attempted against HaFunnel and was blocked.",
        "Only POST /v1/oven (regular oven entities) is permitted for writes.",
        "",
        f"Time (UTC):       {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"Method:           {_clean(request.method, 12)}",
        f"URL:              {_clean(str(request.url), 500)}",
        f"Source IP:        {ip}  (from {how})",
        f"Direct peer:      {peer}",
        f"X-Forwarded-For:  {_clean(request.headers.get('x-forwarded-for', '-'), 200)}",
        f"User-Agent:       {_clean(request.headers.get('user-agent', '-'), 200)}",
        f"Valid API token:  {'YES' if token_valid else 'no'}",
    ]
    if suppressed:
        lines += ["", f"{suppressed} further alert(s) were suppressed by the hourly limit since the last e-mail."]
    task = asyncio.create_task(asyncio.to_thread(_send_email, subject, "\n".join(lines) + "\n"))
    _background_tasks.add(task)  # keep a reference until it finishes
    task.add_done_callback(_background_tasks.discard)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _domain(entity_id: str) -> str:
    return entity_id.split(".", 1)[0]


def _visible(entity_id: str) -> bool:
    return _domain(entity_id) in ALLOWED_DOMAINS


def _validate_entity(entity_id: str) -> str:
    if not ENTITY_ID_RE.match(entity_id) or not _visible(entity_id):
        # Same response for "bad" and "hidden" so existence is not leaked.
        raise HTTPException(404, "Not found")
    return entity_id


def _parse_time(value: str, name: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, f"{name} must be an ISO 8601 timestamp")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
# Interactive docs are disabled: they would be unauthenticated.
app = FastAPI(title="HaFunnel", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def method_guard(request: Request, call_next):
    # GET/HEAD always OK (subject to auth + gate).
    # POST only for the oven control endpoint; everything else is blocked.
    path = request.url.path.rstrip("/") or "/"
    if request.method in ("GET", "HEAD"):
        pass
    elif request.method == "POST" and path == "/v1/oven":
        pass
    else:
        notify_write_attempt(request)
        return JSONResponse(
            {"detail": "Method not allowed (writes limited to POST /v1/oven)"},
            status_code=405,
            headers={"Allow": "GET, HEAD, POST"},
        )
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=63072000"
    return response


@app.get("/v1/states", dependencies=[Depends(require_access)])
async def list_states(domain: Optional[str] = Query(None, pattern=r"^[a-z0-9_]+$")):
    """All visible entity states, optionally filtered by domain."""
    states = await ha_get("/api/states")
    out = [s for s in states if _visible(s["entity_id"])]
    if domain:
        out = [s for s in out if _domain(s["entity_id"]) == domain]
    return out


@app.get("/v1/states/{entity_id}", dependencies=[Depends(require_access)])
async def get_state(entity_id: str):
    """State of one entity."""
    _validate_entity(entity_id)
    return await ha_get(f"/api/states/{entity_id}")


@app.get("/v1/history/{entity_id}", dependencies=[Depends(require_access)])
async def get_history(
    entity_id: str,
    start: Optional[str] = Query(None, description="ISO 8601, default: 24h ago"),
    end: Optional[str] = Query(None, description="ISO 8601, default: now"),
    minimal: bool = True,
):
    """State history of one entity (max range is set by max_history_days)."""
    _validate_entity(entity_id)
    now = datetime.now(timezone.utc)
    end_dt = _parse_time(end, "end") if end else now
    start_dt = _parse_time(start, "start") if start else end_dt - timedelta(hours=24)
    if start_dt >= end_dt:
        raise HTTPException(400, "start must be before end")
    if end_dt - start_dt > timedelta(days=MAX_HISTORY_DAYS):
        raise HTTPException(400, f"Range may not exceed {MAX_HISTORY_DAYS} days")

    params = {"filter_entity_id": entity_id, "end_time": end_dt.isoformat()}
    if minimal:
        params["minimal_response"] = "1"
        params["no_attributes"] = "1"
    data = await ha_get(f"/api/history/period/{start_dt.isoformat()}", params)
    return data[0] if data else []


@app.post("/v1/oven", dependencies=[Depends(require_access)])
async def control_oven(request: Request):
    """
    Control the regular oven only.

    Body (JSON) — one of:

      Power:
        {"entity_id": "switch.oven_power", "service": "turn_on"}
        {"entity_id": "switch.oven_power", "service": "turn_off"}
        {"entity_id": "switch.oven_power", "service": "toggle"}

      Child lock:
        {"entity_id": "switch.oven_child_lock", "service": "turn_on"}
        {"entity_id": "switch.oven_child_lock", "service": "turn_off"}

      Programme (selected = queue, active = start immediately when remote start allows):
        {"entity_id": "select.oven_selected_programme", "service": "select_option",
         "option": "cooking_oven_program_heating_mode_hot_air"}
        {"entity_id": "select.oven_active_programme", "service": "select_option",
         "option": "cooking_oven_program_heating_mode_hot_air"}

      Alarm clock (seconds):
        {"entity_id": "number.oven_alarm_clock", "service": "set_value", "value": 300}

    Only the five oven entity_ids listed in OVEN_WRITE_ENTITIES are accepted.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(400, "Body must be a JSON object")

    entity_id = str(body.get("entity_id", "")).strip()
    service = str(body.get("service", "")).strip()
    if entity_id not in OVEN_WRITE_ENTITIES:
        raise HTTPException(400, f"entity_id not allowed for write (oven only): {entity_id or '(missing)'}")
    domain = entity_id.split(".", 1)[0]
    allowed_services = OVEN_WRITE_SERVICES.get(domain, frozenset())
    if service not in allowed_services:
        raise HTTPException(400, f"service '{service}' not allowed for {domain}")

    # Build the payload Home Assistant expects for the service.
    payload: dict = {"entity_id": entity_id}
    if domain == "select":
        option = body.get("option")
        if not isinstance(option, str) or not option.strip():
            raise HTTPException(400, "select requires string 'option'")
        payload["option"] = option.strip()
    elif domain == "number":
        if "value" not in body:
            raise HTTPException(400, "number requires 'value'")
        try:
            payload["value"] = float(body["value"])
        except (TypeError, ValueError):
            raise HTTPException(400, "'value' must be a number")

    log.info("Oven write: %s.%s entity_id=%s", domain, service, entity_id)
    return await ha_post(f"/api/services/{domain}/{service}", payload)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def gen_token() -> None:
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    print(f"Client token (give to the client, shown once): {token}")
    print(f'Add this to "client_token_hashes" in config.json: "{digest}"')


def serve(config_path: Path) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        load_config(config_path)
    except ConfigError as exc:
        log.error("%s", exc)
        sys.exit(1)

    uvicorn.run(
        app,
        host=BIND_HOST,
        port=BIND_PORT,
        ssl_certfile=TLS_CERT,
        ssl_keyfile=TLS_KEY,
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        server_header=False,
        proxy_headers=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="HaFunnel: token-protected HTTPS API for Home Assistant (writes limited to oven)")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("gen-token", help="generate a client token and its hash")
    p_serve = sub.add_parser("serve", help="run the server (default)")
    p_serve.add_argument("--config", "-c", default="config.json", help="path to config.json")
    args = parser.parse_args()

    if args.cmd == "gen-token":
        gen_token()
    else:
        serve(Path(getattr(args, "config", "config.json")))


if __name__ == "__main__":
    main()
