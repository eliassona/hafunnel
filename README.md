# HaFunnel

A token-protected HTTPS REST API in front of Home Assistant.
Reads are open for allow-listed domains; writes are limited by construction to the regular oven only.

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

### E-mail alerts for write attempts (optional)

Whenever someone sends anything other than GET/HEAD (POST, PUT, DELETE, ...), the request is refused with `405` and an e-mail is sent to the configured recipients with the **method, full URL, source IP**, user agent, and whether a valid API token was presented. Remove the `alerts` section to disable it.

| Key | Default | Purpose |
|---|---|---|
| `alerts.smtp_host` / `smtp_port` | required / `587` | Mail server |
| `alerts.smtp_security` | `starttls` | `starttls`, `ssl` (port 465) or `none` |
| `alerts.smtp_username` / `smtp_password` | empty | SMTP login (refused when `smtp_security` is `none`) |
| `alerts.from` | required | Sender address |
| `alerts.to` | required | List of recipient addresses |
| `alerts.max_emails_per_hour` | `10` | Flood protection; extra alerts are counted and reported in the next e-mail |
| `alerts.subject_prefix` | `[HaFunnel]` | Prefix for the subject line |

Notes:
* Mail is sent in the background, so a slow or broken mail server never delays or breaks the API response. Failures are logged (`journalctl -u hafunnel`).
* Alerts are sent for **any** non-GET request, with or without a token. Public scanners will trigger them, which is what the hourly limit is for. "Valid API token: YES" in an alert means someone holding a real token tried to write.
* **Source IP behind Tailscale Funnel:** the TCP peer is then `127.0.0.1`, so HaFunnel uses the last entry of the `X-Forwarded-For` header when the peer is loopback. Both the derived IP and the raw header are included in the e-mail, so you can verify it. Send a test POST from outside and check that your real public IP appears.
* Request data in the e-mail (URL, headers) is escaped and truncated, since it is attacker-controlled.
* Gmail and similar services need an app password, not your normal password.

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
| POST | `/v1/oven` | Control the **regular oven only** (see below) |

```bash
curl --cacert cert.pem -H "Authorization: Bearer $TOKEN" \
  https://localhost:8443/v1/states/sensor.living_room_temperature
```

### Oven control (`POST /v1/oven`)

Writes are restricted by construction to these five entities of the regular oven
(not the microwave oven, dishwasher or induction cooktop):

| entity_id | allowed services | extra body fields |
|---|---|---|
| `switch.oven_power` | `turn_on`, `turn_off`, `toggle` | — |
| `switch.oven_child_lock` | `turn_on`, `turn_off` | — |
| `select.oven_selected_programme` | `select_option` | `"option": "<programme key>"` |
| `select.oven_active_programme` | `select_option` | `"option": "<programme key>"` |
| `number.oven_alarm_clock` | `set_value` | `"value": <seconds>` |

Any other `entity_id`, domain or service is rejected with `400`. Any other path
or HTTP method that would write is rejected with `405` and (if configured)
triggers an alert e-mail.

**Examples** (replace host/cert/token as needed):

```bash
# Turn oven power on
curl --cacert cert.pem -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_id":"switch.oven_power","service":"turn_on"}' \
  https://localhost:8443/v1/oven

# Turn oven power off
curl --cacert cert.pem -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_id":"switch.oven_power","service":"turn_off"}' \
  https://localhost:8443/v1/oven

# Select a programme (queues it; does not always start it)
curl --cacert cert.pem -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_id":"select.oven_selected_programme","service":"select_option","option":"cooking_oven_program_heating_mode_hot_air"}' \
  https://localhost:8443/v1/oven

# Start / set active programme (when remote start is allowed on the appliance)
curl --cacert cert.pem -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_id":"select.oven_active_programme","service":"select_option","option":"cooking_oven_program_heating_mode_hot_air"}' \
  https://localhost:8443/v1/oven

# Child lock on
curl --cacert cert.pem -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_id":"switch.oven_child_lock","service":"turn_on"}' \
  https://localhost:8443/v1/oven

# Alarm clock = 5 minutes
curl --cacert cert.pem -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entity_id":"number.oven_alarm_clock","service":"set_value","value":300}' \
  https://localhost:8443/v1/oven
```

Programme keys currently exposed by the oven (from `select.oven_*_programme`
options):  
`cooking_oven_program_heating_mode_slow_cook`,  
`cooking_oven_program_heating_mode_hot_air_eco`,  
`cooking_oven_program_heating_mode_hot_air`,  
`cooking_oven_program_heating_mode_hot_air_grilling`,  
`cooking_oven_program_heating_mode_top_bottom_heating`,  
`cooking_oven_program_heating_mode_pizza_setting`,  
`cooking_oven_program_heating_mode_top_bottom_heating_eco`,  
`cooking_oven_program_heating_mode_preheat_ovenware`,  
`cooking_oven_program_heating_mode_sabbath_programme`,  
`cooking_oven_program_heating_mode_keep_warm`,  
`cooking_oven_program_heating_mode_bottom_heating`,  
`cooking_oven_program_steam_modes_steam`.

Notes for real use:

* `binary_sensor.oven_remote_control` must be `on` and, for starting a programme,
  `binary_sensor.oven_remote_start` is often required to be `on` (set on the
  appliance itself).
* Selecting `select.oven_active_programme` typically starts the programme when
  the appliance allows remote start; `select.oven_selected_programme` only
  queues it.
* Temperature / duration options for a running programme are not exposed as
  simple entities in the state dump you shared; they would need the Home Connect
  `set_program_and_options` service (device_id based), which is intentionally
  not opened here.

## What can still not be changed

* Middleware allows POST only to `/v1/oven`. Every other non-GET method returns 405.
* The write path hard-codes the five oven entity_ids and the three service domains
  above; there is no way to reach `/api/services` for any other entity.
* Entity domains for reads are still allowlisted; cameras, locks, alarm panels,
  persons and device trackers stay hidden unless you add them.
* Entity IDs are regex-validated, so clients cannot inject paths into upstream calls.

## Notes

* Attributes of allowed entities are returned as-is; trim `allowed_domains` if some contain data you don't want shared.
* Failed auth attempts are throttled per IP (10 per minute). For internet exposure, also put it behind a firewall or reverse proxy.
* Never commit `config.json` to version control.
