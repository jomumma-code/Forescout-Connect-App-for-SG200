# SG200 Collector + Forescout Connect Apps

This repository contains:

- **Playwright-based collector** for Cisco SG200 switches.
- **Forescout Connect app package** for SG200 that calls the external collector.
- Packaged zip artifacts for each app version.


![Architecture diagram](docs/architecture.svg)

This project provides an HTTP collector service that Forescout Connect apps can call to inventory Cisco SG200 switches and enrich endpoint records in the Forescout eyeSight console.

Primary outcomes in eyeSight:
- Switch attribution for endpoints (which switch observed the MAC).
- Network attachment context (VLAN and switch interface name) mapped into device properties for policy, tagging, and response workflows.

## Key capabilities (value in Forescout eyeSight)

- Enriches eyeSight endpoint records with switch-derived context for device identification and response workflows.
- Publishes the following as device properties in the eyeSight console:
  - Switch identity (hostname, serial number, model, firmware)
  - Network attachment context from the SG200 MAC table:
    - VLAN
    - Switch interface name (e.g., GE1, GE2, …)
- Enables Connect-based policies, tags, and automation actions that depend on “where the device is connected” (interface/VLAN) and “what infrastructure reported it” (switch identity).

![Device Properties in Forescout eyeSight console](docs/properties.png)


## Components

- Collector service: `collector.py` (Flask app) and SG200 scraper: `scrapers/sg200_client.py` (Playwright-based), downloadable as a **collector.zip** file
- Cisco SG200 Connect app for Forescout eyeSight, downloadable as a **CiscoSG200ConnectApp.zip** file

---

## System requirements

Windows:
- Windows 10/11 or Windows Server 2019+
- Python 3.10+
- Network reachability from the collector host to the SG200 management UI

---

# Deployment (Windows)

This deployment flow is ordered as follows:
1) Deploy and run the collector.
2) Test the collector against your SG200 using CLI.
3) Only after successful CLI validation, install/configure the Forescout Connect app.

## Step 1 — Deploy the collector

### 1.1 Extract files

Create directories:
- `C:\SG200Collector\current\`
- `C:\SG200Collector\logs\`

Extract the collector release zip into `C:\SG200Collector\current\` and confirm:
- `collector.py`
- `scrapers\` directory

### 1.2 Create virtual environment and install dependencies

Open PowerShell:

```powershell
cd C:\SG200Collector\current
py -m venv venv
.\venv\Scripts\activate
python -m pip install --upgrade pip
pip install flask waitress playwright requests beautifulsoup4
python -m playwright install chromium
```

### 1.3 Configure request controls (optional)

Create `C:\SG200Collector\current\collector_security.json`:

```json
{
  "allowed_ips": ["127.0.0.1", "192.168.0.35"],
  "token": "replace-with-a-long-random-string"
}
```

Operational guidance:
- The `allowed_ips` list should include the eyeSight appliance(s) that will run the Connect app polling.
  - In Forescout, these are the appliance(s) selected in the app configuration panel typically labeled “Assign eyeSight Devices”.
- While validating from an admin workstation, add that workstation’s IP temporarily, or run the CLI tests locally on the collector host using `127.0.0.1`.

### 1.4 Run the collector interactively (initial validation)

Start the collector on localhost:

Windows (PowerShell):
```powershell
cd C:\SG200Collector\current
.\venv\Scripts\activate
waitress-serve --host=127.0.0.1 --port=8081 collector:app
```

macOS/Linux (bash/zsh):
```bash
cd /path/to/collector
. venv/bin/activate
waitress-serve --host=127.0.0.1 --port=8081 collector:app
```

Verify the collector is reachable (run in a second terminal on the same host):

macOS/Linux (bash/zsh):
```bash
curl -fsS "http://127.0.0.1:8081/health"
```

Windows (PowerShell):
```powershell
curl.exe -fsS "http://127.0.0.1:8081/health"
```

Keep the collector running for Step 2.

---

## Step 2 — Validate switch communication via CLI

This step proves the collector can authenticate to the SG200 and scrape the required pages. Do not proceed to Forescout until these calls succeed.

POST body fields:
- `ip`: SG200 switch management IP address (the same IP you use in the browser to manage the switch)
- `user`: SG200 web UI username
- `pass`: SG200 web UI password

Authentication header:
- `X-Collector-Token`: must match the `token` value configured in `collector_security.json`

### 2.1 Test system identity

macOS/Linux (bash/zsh):
```bash
curl -fsS -X POST "http://127.0.0.1:8081/sg200/system-summary"   -H "Content-Type: application/json"   -H "X-Collector-Token: your-token-here"   -d '{"ip":"192.168.0.221","user":"cisco","pass":"cisco"}'
```

Windows (PowerShell, one line):
```powershell
curl.exe -fsS -X POST "http://127.0.0.1:8081/sg200/system-summary" -H "Content-Type: application/json" -H "X-Collector-Token: your-token-here" -d "{\"ip\":\"192.168.0.221\",\"user\":\"cisco\",\"pass\":\"cisco\"}"
```

### 2.2 Test MAC table and interface name mapping

macOS/Linux (bash/zsh):
```bash
curl -fsS -X POST "http://127.0.0.1:8081/sg200/mac-table"   -H "Content-Type: application/json"   -H "X-Collector-Token: your-token-here"   -d '{"ip":"192.168.0.221","user":"cisco","pass":"cisco"}'
```

Windows (PowerShell, one line):
```powershell
curl.exe -fsS -X POST "http://127.0.0.1:8081/sg200/mac-table" -H "Content-Type: application/json" -H "X-Collector-Token: your-token-here" -d "{\"ip\":\"192.168.0.221\",\"user\":\"cisco\",\"pass\":\"cisco\"}"
```

Validation checks:
- Both endpoints return HTTP 200.
- `/sg200/mac-table` returns entries where `port_index` is an interface label (GE1, GE2, …).
- `/sg200/system-summary` returns the switch identity fields.

If either endpoint fails:
- Review the collector console output.
- Confirm SG200 IP/credentials.
- Confirm the collector host can reach the SG200 management UI.

---

## Step 3 — Deploy as a Windows Service (NSSM)

After Step 2 succeeds, deploy the collector as a service.

### 3.1 Download and install NSSM

Download NSSM from:
- https://nssm.cc/download

Extract and place `nssm.exe` in a stable location, for example:
- `C:\Tools\nssm.exe`

### 3.2 Create a dedicated service account

Playwright/Chromium is typically more reliable under a real user profile than LocalSystem.

Create a local user (example using elevated PowerShell):
```powershell
net user sg200svc "StrongPasswordHere" /add
```

Grant “Log on as a service”:
1. Run `secpol.msc`
2. Local Policies → User Rights Assignment
3. Open “Log on as a service”
4. Add the user `sg200svc`

NTFS permissions:
- `C:\SG200Collector\current\` : Read/Execute for `sg200svc`
- `C:\SG200Collector\logs\` : Modify for `sg200svc`

### 3.3 Install the service

Run PowerShell as Administrator:

```powershell
C:\Tools\nssm.exe install SG200Collector
```

In the NSSM GUI, set:

Application
- Path: `C:\SG200Collector\current\venv\Scripts\python.exe`
- Startup directory: `C:\SG200Collector\current`
- Arguments:
  - `-m waitress --listen=0.0.0.0:8081 collector:app`

I/O
- Stdout: `C:\SG200Collector\logs\stdout.log`
- Stderr: `C:\SG200Collector\logs\stderr.log`

Process
- Enable “Kill process tree”

Then set the service Log On account:
- Services → SG200Collector → Properties → Log On → `.\sg200svc`

Startup + Recovery:
- Startup type: Automatic
- Recovery tab:
  - Restart the service on failures

Start/stop:
```powershell
sc start SG200Collector
sc stop SG200Collector
```

### 3.4 Firewall

When you start the collector in an interactive user session (terminal) and bind to 0.0.0.0:8081, Windows Defender Firewall may display the “Windows Defender Firewall has blocked some features of this app” prompt the first time it detects inbound listening/traffic for that executable (often python.exe)
Do not rely on a Windows prompt to open the port. Create an explicit inbound rule for TCP 8081.

Example (PowerShell):
```powershell
New-NetFirewallRule -DisplayName "SG200 Collector (TCP 8081)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8081


---

## Step 4 — Install and configure the Forescout Connect app

Only proceed after Step 2 succeeds.

### 4.1 Allow unsigned Connect apps (Enterprise Manager)

This app is unofficial/unsigned. On the Enterprise Manager, enable unsigned app import:

```text
fstool allow_unsigned_connect_app_install true
```

After importing the app, you can revert enforcement:

```text
fstool allow_unsigned_connect_app_install false
```

### 4.2 Import and configure the app

High-level:
1. Import the Connect app package in the Forescout Console.
2. Configure:
   - Collector Host and Port (Windows collector host and 8081)
   - Collector Token (must match `collector_security.json`)
   - Switch definitions: up to 16 switches can be configured in the app
3. In “Assign eyeSight Devices”, select the appliance(s) that will run the app.
4. Enable discovery options and set the interval:
   - Recommended polling interval: 10 minutes or longer (to reduce scraping load and avoid overlapping sessions).
5. Run a manual Refresh/Test once and confirm properties populate in eyeSight.

---

## Monitoring

Tail logs:
```powershell
Get-Content C:\SG200Collector\logs\stdout.log -Tail 200 -Wait
```

---

## Log retention (24 hours)

Use a Scheduled Task to delete log files older than 24 hours:

```powershell
powershell.exe -NoProfile -Command ^
  "Get-ChildItem 'C:\SG200Collector\logs\*.log' -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-24) } | Remove-Item -Force"
```
