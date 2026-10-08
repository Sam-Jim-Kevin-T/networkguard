# NetworkGuard backend MVP

A Flask API for user accounts, owner-isolated Linux servers, monitoring data, and security alerts. SQLite is the local default; for PostgreSQL, install `psycopg` (included in `requirements.txt`) and set `DATABASE_URL` using SQLAlchemy's `postgresql+psycopg://user:password@host:5432/database` format.

## Run locally (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `SECRET_KEY` in `.env` to a private random value before starting:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Copy the generated value into `.env`, then run:

```powershell
python run.py
```

The development server listens on `http://127.0.0.1:5000`; open that address to use the browser dashboard. Create an account, register a Linux server, then copy the one-time agent token into the agent's environment file. The dashboard refreshes automatically every 30 seconds. For an HTTPS deployment, set `COOKIE_SECURE=true` and run Flask behind a production WSGI server and reverse proxy. Do not expose Flask's development server to the public internet.

The dashboard includes account sign-in/registration, server enrollment and removal, a one-time token display, CPU/memory and connection summaries, recent network traffic, per-process connection rankings, connection review labels, recent detection logs, alert/event resolution, and per-server IP allow/block lists. A newly seen IP, uncommon remote port, high connection count, or unavailable process name is only a review hint; these observations are not proof of malicious activity. IP rules are informational labels only: they do not modify or block Linux firewall traffic.

## Connect a VirtualBox Linux VM securely (local development)

This optional setup serves the development app only on the VirtualBox host-only adapter at `192.168.148.1`; it does not listen on the Wi-Fi address. Mint must have its host-only adapter address set to `192.168.148.10`. Create a self-signed certificate with an IP subject alternative name, then trust its public certificate in Windows and Mint. The private key is saved under `%LOCALAPPDATA%\NetworkGuard`, outside the OneDrive project folder:

```powershell
python -m pip install -r dev-requirements.txt
python scripts/create_dev_cert.py
certutil -user -addstore -f Root .\certs\host-only.crt
```

Copy **only** `certs/host-only.crt` into Mint using a VirtualBox shared folder. Never copy `host-only.key` off Windows. In Mint, install the public certificate into the system trust store:

```bash
sudo install -m 0644 /path/to/shared/host-only.crt /usr/local/share/ca-certificates/networkguard-host-only.crt
sudo update-ca-certificates
```

In an elevated Windows PowerShell (Run as administrator), add a firewall rule limited to this VM and the host-only address:

```powershell
New-NetFirewallRule -DisplayName "NetworkGuard VirtualBox VM" -Direction Inbound -Action Allow -Protocol TCP -LocalAddress 192.168.148.1 -LocalPort 5000 -RemoteAddress 192.168.148.10 -Profile Any
```

Start the web app from the project directory in a normal PowerShell window. Make sure `.env` contains a stable `SECRET_KEY` first:

```powershell
$env:NETWORKGUARD_HOST = "192.168.148.1"
$env:NETWORKGUARD_TLS_CERT = (Resolve-Path .\certs\host-only.crt).Path
$env:NETWORKGUARD_TLS_KEY = Join-Path $env:LOCALAPPDATA "NetworkGuard\host-only.key"
$env:COOKIE_SECURE = "true"
python run.py
```

Open `https://192.168.148.1:5000` in Windows. In Mint, test `curl https://192.168.148.1:5000/api/csrf`; a JSON response confirms reachability and certificate trust. Set the agent's `NETWORKGUARD_URL` to `https://192.168.148.1:5000`. This is a local development configuration, not a production server; stop the app with Ctrl+C when finished and remove the narrowly scoped firewall rule with `Remove-NetFirewallRule -DisplayName "NetworkGuard VirtualBox VM"` when no longer needed.

## Deploy publicly with GitHub and Render

`render.yaml` describes the public web service, HTTPS-safe cookies, a generated secret, and an application/database health check. Before connecting the repository, create a GitHub repository and upload the project using GitHub Desktop or the GitHub website. Never upload `.env`, agent tokens, `certs/host-only.key`, TLS certificates, local database files, or virtual-environment folders; `.gitignore` excludes them.

On Render, choose **New → Blueprint**, connect the GitHub repository, and apply `render.yaml`. When prompted for `DATABASE_URL`, provide the connection URL for a persistent PostgreSQL database (Render's internal connection URL if using Render Postgres, or another provider). The application rewrites PostgreSQL URLs to the `psycopg` driver and refuses to start on Render if a persistent PostgreSQL URL is missing. Deploy only after the database is available and its URL is configured. The app currently creates tables at startup; back up production data and do not change the schema without a migration plan.

Login and registration endpoints have per-IP rate limits. The initial in-memory limiter is suitable for this single-worker MVP but resets on restart; for multi-instance production, configure shared Redis-backed rate-limit storage before scaling. Render's free web service may sleep when idle, delaying a heartbeat and temporarily showing the server offline. Use a hosting/database plan appropriate for continuous monitoring. Once deployed, open the HTTPS URL, register an account and server, then configure the Mint agent with that public HTTPS base URL and the new server's token. Keep the agent token private. The local VirtualBox HTTPS/firewall setup is not needed for a public deployment.

## API

All API endpoints use JSON. User-facing state-changing requests require a CSRF token: first call `GET /api/csrf`, then send its `csrf_token` value in the `X-CSRFToken` header. The browser must keep the session cookie. Agent heartbeats use bearer-token authentication instead.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/csrf` | Get a CSRF token |
| `POST` | `/api/auth/register` | Create an account and start a session |
| `POST` | `/api/auth/login` | Start an account session |
| `POST` | `/api/auth/logout` | End the session |
| `GET` | `/api/auth/me` | Current account |
| `GET` | `/api/dashboard` | Owner's summary, active alerts, and recent traffic |
| `GET`, `POST` | `/api/servers` | List servers / register a server |
| `GET`, `DELETE` | `/api/servers/<id>` | Read or delete an owned server |
| `GET` | `/api/alerts` | List owned alerts; optional `?status=active` or `?status=resolved` |
| `POST` | `/api/alerts/<id>/resolve` | Resolve an owned alert |
| `GET` | `/api/events` | List owned anomaly and detection log events |
| `POST` | `/api/events/<id>/resolve` | Resolve an owned event |
| `GET`, `POST` | `/api/servers/<id>/ip-rules` | List or add informational per-server IP labels |
| `DELETE` | `/api/servers/<id>/ip-rules/<rule_id>` | Remove an informational IP label |
| `POST` | `/api/agent/heartbeat` | Submit a monitoring report |

Register a server using `POST /api/servers`:

```json
{"name": "Ubuntu Web", "hostname": "web-01"}
```

The response includes `agent_token` once. Store it securely on the monitored host; the database stores only its SHA-256 hash. The agent sends `Authorization: Bearer <agent_token>` with each heartbeat. Example:

```json
{
  "cpu_percent": 18.4,
  "memory_percent": 61.2,
  "tcp_connections": 25,
  "udp_connections": 7,
  "network_in_bytes": 120000,
  "network_out_bytes": 84000,
  "failed_ssh_attempts": 0,
  "listening_ports": [22, 443],
  "connections": [
    {
      "process": "nginx",
      "remote_ip": "203.0.113.7",
      "remote_port": 443,
      "protocol": "tcp",
      "status": "ESTABLISHED"
    }
  ]
}
```

CPU/memory percentages are required. Other numeric fields default to zero; `listening_ports` and `connections` default to empty lists. Network byte counts and `failed_ssh_attempts` are measured for each reporting interval. Connection objects may also contain `pid`, `local_ip`, and `local_port`. Reports are size- and range-validated. Initial anomaly rules alert on at least five failed SSH attempts in a report, a listening port newly appearing after the first report, and traffic at least 10 MiB and four times the average of the most recent three to ten reports. The event log also records first-seen remote IPs, unavailable process names, uncommon remote ports, and connection counts of 80 or more. These rules are heuristic and can produce benign review events.

Per-server IP allow/block lists change how a connection is labelled in the dashboard only. No firewall commands or network enforcement are run by the backend or monitoring agent.

## Install the Linux agent

First register the Linux server in the web API (`POST /api/servers`) and securely copy the returned `agent_token`; it is only shown at creation. The monitored machine must be Linux with Python 3.10+ and access to the backend over HTTPS. Copy the `agent` directory to the Linux machine, then install the agent in a virtual environment:

```bash
sudo install -d -m 0755 /opt/networkguard-agent
sudo cp -R agent/. /opt/networkguard-agent/
sudo python3 -m venv /opt/networkguard-agent/.venv
sudo /opt/networkguard-agent/.venv/bin/pip install /opt/networkguard-agent
```

Create `/etc/networkguard-agent.env` using the registered server token and the backend's base URL (do not include `/api/agent/heartbeat`):

```bash
sudo sh -c 'umask 077; cat > /etc/networkguard-agent.env <<EOF
NETWORKGUARD_URL=https://your-app.example.com
NETWORKGUARD_TOKEN=PASTE_THE_SERVER_TOKEN_HERE
NETWORKGUARD_INTERVAL=60
EOF'
```

Install and start the included systemd unit:

```bash
sudo install -m 0644 /opt/networkguard-agent/networkguard-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now networkguard-agent
sudo systemctl status networkguard-agent
sudo journalctl -u networkguard-agent -f
```

The service sends its first heartbeat after the configured interval, then reports at that interval. To check connectivity and credentials before enabling the service, run a one-time report. It waits for one full interval so network byte deltas and SSH events cover the same period:

```bash
sudo bash -c 'set -a; . /etc/networkguard-agent.env; set +a; /opt/networkguard-agent/.venv/bin/networkguard-agent --once'
```

It exits with status 0 after an accepted report, or logs the connection or authentication error and exits nonzero. The agent gathers CPU/memory, network byte deltas, TCP/UDP sockets, listening ports, established connection details, and recent failed SSH logins from journald. Root privileges allow process names and system journal events to be collected; if connection inspection or journald access fails, the agent logs a warning and reports what it can. Keep the token file readable only by root and never paste a real token into tickets or source control. The agent requires HTTPS except for local loopback development URLs.

To upgrade an existing installation after copying the updated `agent` directory onto the Linux host, run these commands from the project directory, then restart the service:

```bash
sudo cp -R agent/. /opt/networkguard-agent/
sudo /opt/networkguard-agent/.venv/bin/pip install /opt/networkguard-agent
sudo systemctl restart networkguard-agent
```

This refreshes optional connection details such as process ID and local address shown in the server detail view. Older agents remain compatible but do not send those fields.

## Tests

```powershell
python -m unittest discover -s tests -v
```

This also runs the agent collector and configuration tests. This MVP creates its tables on app startup. Before a production launch, add managed database migrations, rate limiting, email verification/password recovery, agent-token rotation, and an operational HTTPS deployment configuration.
