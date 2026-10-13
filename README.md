# HaFunnel

A read-only, token-protected HTTPS REST API in front of Home Assistant.

## Install

Use a virtual environment (required on Raspberry Pi OS / Debian 12+, where system-wide `pip install` is blocked):

```bash
python3 -m venv venv        # if this fails: sudo apt install python3-venv
./venv/bin/pip install "fastapi>=0.110" "uvicorn>=0.29" "httpx>=0.27"
```

Run every command below with `./venv/bin/python` (or run `source venv/bin/activate` once and use `python`).

## Setup

1. **Home Assistant token**: in HA, Profile -> Security -> Long-lived access tokens.
   Tip: create a dedicated, non-admin user for this token.
2. **Client token**:
   ```bash
   python hafunnel.py gen-token
   ```
   Give the token to the client; put the printed hash in `client_token_hashes`.
3. **TLS certificate** (self-signed example; use a real cert/Let's Encrypt if exposed publicly):
   ```bash
   openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
     -keyout key.pem -out cert.pem -subj "/CN=hafunnel" \
     -addext "subjectAltName=DNS:localhost,DNS:hafunnel.local,IP:127.0.0.1"
   ```
   Clients verify the hostname against the SANs, so list every name or IP they will connect to.
4. **Config**:
   ```bash
   cp config.example.json config.json
   chmod 600 config.json      # it contains secrets
   # edit config.json
   ```
5. **Run**:
   ```bash
   python hafunnel.py serve                    # uses ./config.json
   python hafunnel.py serve --config /etc/hafunnel/config.json
   ```

## config.json

| Key | Default | Purpose |
|---|---|---|
| `home_assistant.url` | required | Home Assistant base URL |
| `home_assistant.token` | required | HA long-lived access token |
| `home_assistant.verify_tls` | `true` | Set `false` for a self-signed HA certificate |
| `server.host` / `server.port` | `0.0.0.0` / `8443` | Bind address |
| `server.tls_cert` / `server.tls_key` | required | TLS cert and key (relative paths resolve from the config file's folder; server won't start without them) |
| `client_token_hashes` | required | List of SHA-256 hashes of accepted client tokens |
| `allowed_domains` | see `config.example.json` | Visible entity domains |
| `max_history_days` | `7` | Max history range |

### Access gate (optional)

Restricts access by time of day and alarm state. A request is **allowed only when it is outside the night window AND the alarm is `DISARMED`**. It is denied if it is night, or if the alarm is in any other state. Remove the `access_gate` section to turn the gate off.

| Key | Default | Purpose |
|---|---|---|
| `access_gate.alarm_url` | required | Plain HTTP(S) URL that returns JSON such as `{"alarm_state": "DISARMED"}` |
| `access_gate.state_key` | `alarm_state` | JSON field holding the state |
| `access_gate.disarmed_value` | `DISARMED` | Value that counts as disarmed (case-insensitive) |
| `access_gate.night_start` / `night_end` | required | `"HH:MM"` 24h. Start is inclusive, end exclusive. Windows crossing midnight work (`23:00`-`06:00`) |
| `access_gate.timezone` | server local time | IANA name, e.g. `Europe/Stockholm`. Set it, since a Pi is often on UTC |
| `access_gate.timeout_seconds` | `5` | Timeout for the alarm query |

Behaviour:
* The token is checked first; the gate only applies to requests with a valid token.
* During the night window every request is denied (`403`) and the alarm is not queried.
* Outside the night window the alarm is queried on each request; anything other than the disarmed value gives `403`.
* **Fails closed:** if the alarm URL is unreachable, times out or returns something unexpected, the API returns `503` instead of serving data.
* The response never reveals the alarm state.
* The Home Assistant token is never sent to the alarm URL.

The server validates the config at startup and exits with a clear message if anything is missing or invalid. It also warns if `config.json` is readable by other users.

## API (all calls need `Authorization: Bearer <client token>`)

| Method | Path | Description |
|---|---|---|
| GET | `/v1/states[?domain=sensor]` | All visible entity states |
| GET | `/v1/states/{entity_id}` | One entity's state |
| GET | `/v1/history/{entity_id}?start=&end=&minimal=true` | History (ISO 8601 times, default last 24h) |

```bash
curl --cacert cert.pem -H "Authorization: Bearer $TOKEN" \
  https://localhost:8443/v1/states/sensor.living_room_temperature
```

## Why it can't change anything

* Routes are GET-only; a middleware answers 405 to any other HTTP method.
* The sole upstream function, `ha_get`, only performs GET against Home Assistant.
  Nothing calls `/api/services/...`, so no service (turn on/off, etc.) can be invoked.
* Entity domains are allowlisted; cameras, locks, alarm panels, persons and device
  trackers are hidden unless you add them.
* Entity IDs are regex-validated, so clients cannot inject paths into upstream calls.

## Notes

* Attributes of allowed entities are returned as-is; trim `allowed_domains` if some contain data you don't want shared.
* Failed auth attempts are throttled per IP (10 per minute). For internet exposure, also put it behind a firewall or reverse proxy.
* Never commit `config.json` to version control.
