# SG200 / Netgear Collector + Forescout Connect Apps

This repository contains:

- **Playwright-based collectors** for Cisco SG200 switches and Netgear routers.
- **Forescout Connect app packages** for SG200 and Netgear that call the external collector.
- Packaged zip artifacts for each app version.

## Architecture overview

![Architecture diagram](docs/architecture.svg)

## Repository layout (high level)

```
.
├── scraper/                # Collector service + scraper client modules
│   ├── collector.py        # Flask API for SG200 + Netgear
│   ├── scrapers/           # Scraper client modules loaded lazily
│   │   ├── sg200_client.py # Playwright scraper for SG200 dynamic MAC table
│   │   └── netgear_client.py # HTTP scraper for Netgear access control list
│   └── dev/                # HAR/capture references for development
├── SG200/                  # SG200 Connect app artifacts
│   └── app/
│       ├── data/           # system.conf, property.conf, sg200_test.py, sg200_poll.py
│       └── SG200-*.zip     # Versioned packaged app bundles
└── NETGEAR/                # Netgear Connect app artifacts
    ├── data/               # system.conf, property.conf, netgear_ac_test.py, netgear_ac_poll.py
    └── NETGEAR-*.zip       # Versioned packaged app bundles
```

## Quick start

1. Install Python 3.8+ and Playwright dependencies (see below).
2. Start the collector (`python collector.py`).
3. Configure the SG200/NETGEAR Connect app to point at the collector.

## Collector service

The collector is a Flask API that uses Playwright for SG200 web scraping and HTTP requests for Netgear.

## Installation (Windows & Linux)

Install the collector on a system that can reach the switches/routers.
Use Python **3.8+** (3.9+ recommended).

### Windows (PowerShell)

```powershell
cd C:\path\to\SG200\scraper
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install flask requests playwright beautifulsoup4
python -m playwright install chromium
```

Run the collector:

```powershell
$env:SG200_COLLECTOR_HOST="0.0.0.0"
$env:SG200_COLLECTOR_PORT="8080"
# optional
$env:SG200_COLLECTOR_ALLOWED_IPS="192.168.1.10,192.168.1.11"
$env:SG200_COLLECTOR_TOKEN="shared-secret"

python collector.py
```

### Linux (bash)

```bash
cd /path/to/SG200/scraper
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install flask requests playwright beautifulsoup4
python -m playwright install chromium
```

Run the collector:

```bash
export SG200_COLLECTOR_HOST=0.0.0.0
export SG200_COLLECTOR_PORT=8080
# optional
export SG200_COLLECTOR_ALLOWED_IPS="192.168.1.10,192.168.1.11"
export SG200_COLLECTOR_TOKEN="shared-secret"

python collector.py
```

## API endpoints

- `POST /sg200/mac-table`
  - Body:
    ```json
    {
      "ip": "192.168.0.221",
      "user": "cisco",
      "pass": "cisco"
    }
    ```
  - Response:
    ```json
    {
      "switch_ip": "192.168.0.221",
      "entries": [
        {
          "switch_ip": "192.168.0.221",
          "vlan": 1,
          "mac": "aa:bb:cc:dd:ee:ff",
          "port_index": 52,
          "interface": "GE1",
          "description": "Server"
        }
      ]
    }
    ```

- `POST /sg200/system-summary`
  - Body:
    ```json
    {
      "ip": "192.168.0.221",
      "user": "cisco",
      "pass": "cisco"
    }
    ```
  - Response:
    ```json
    {
      "switch_ip": "192.168.0.221",
      "host_name": "GARAGE-SG200",
      "model_description": "26-port Gigabit Smart Switch",
      "serial_number": "DNI161702F3"
    }
    ```

- `POST /netgear/access-control`
  - Body:
    ```json
    {
      "ip": "192.168.1.7",
      "user": "admin",
      "pass": "password"
    }
    ```
  - Response:
    ```json
    {
      "router_ip": "192.168.1.7",
      "entries": [
        {
          "router_ip": "192.168.1.7",
          "ip": "192.168.1.199",
          "mac": "00:0c:29:b2:94:c0",
          "status": "Allowed",
          "conn_type": "wired",
          "name": "DESKTOP-EXAMPLE"
        }
      ]
    }
    ```

## Auth controls (optional)

The collector always runs over HTTP, so you can optionally restrict who can call it.

### 1) IP allowlist (collector-side)

Set an environment variable on the **collector host**:

**Windows (PowerShell)**
```
$env:SG200_COLLECTOR_ALLOWED_IPS="192.168.1.10,192.168.1.11"
```

**Linux (bash)**
```
export SG200_COLLECTOR_ALLOWED_IPS="192.168.1.10,192.168.1.11"
```

When set, the collector will only accept requests from those source IPs.

### 2) Shared token (collector-side + Connect app)

**Collector host:** set the environment variable:

**Windows (PowerShell)**
```
$env:SG200_COLLECTOR_TOKEN="shared-secret"
```

**Linux (bash)**
```
export SG200_COLLECTOR_TOKEN="shared-secret"
```

**Connect app:** enter the same value in **Collector Token** (system.conf field
`connect_ciscosg200_collector_token`). The app sends it as the `X-Collector-Token`
HTTP header.

If the token is set on the collector but missing/wrong in the request, the
collector returns HTTP 401.

## Running the collector

From the repo root:

```bash
export SG200_COLLECTOR_HOST=0.0.0.0
export SG200_COLLECTOR_PORT=8080
# optional
export SG200_COLLECTOR_ALLOWED_IPS="192.168.1.10,192.168.1.11"
export SG200_COLLECTOR_TOKEN="shared-secret"

python scraper/collector.py
```

## Forescout Connect apps

### SG200 app

Configuration files live in:

```
SG200/app/data/
  system.conf
  property.conf
  sg200_test.py
  sg200_poll.py
```

Key settings in `system.conf`:

- Collector host / port / token
- Optional collector token
- Inventory list of switches (one per line): `ip,username,password`

### Netgear app

Configuration files live in:

```
NETGEAR/data/
  system.conf
  property.conf
  netgear_ac_test.py
  netgear_ac_poll.py
```

## Deploy to Forescout eyeSight (unsigned app)

These Connect app packages are **unsigned**. You must allow unsigned apps on the
Enterprise Manager (EM) before importing.

### 1) Allow unsigned Connect apps on the EM

On the **Enterprise Manager**:

1. SSH or console in as `cliadmin`.
2. At the `FS-CLI` prompt, run:

```
fstool allow_unsigned_connect_app_install true
```

This disables signature validation for all apps you import after running it. It is
global, so treat it as a **dev-only** setting.

When you’re done testing, re-enable enforcement with:

```
fstool allow_unsigned_connect_app_install false
```

### 2) Import your app in the Console

In the **Forescout Console**:

1. Go to **Tools → Options → Connect** (or **Configurations → Connect**, depending on version).
2. Click **Import**.
3. Select your app file:
   - Either a `.eca`, or a `.zip` built per the App Builder guide.
4. Click **Import** and acknowledge the invalid/missing signature warning.
6. After import completes, click **Apply**.

Your unsigned app should now appear on the **Apps** tab and be usable for config/policies.

## Packaging

The `SG200-*.zip` and `NETGEAR-*.zip` files are packaged Connect apps ready for import.

### Create SG200 Connect app package

From the repo root:

```bash
cd SG200/app
zip -r SG200-0.2.0.zip data signature -x "__MACOSX/*" "*.DS_Store"
```

### Create Netgear Connect app package

From the repo root:

```bash
cd NETGEAR
zip -r NETGEAR-0.1.1.zip data signature -x "__MACOSX/*" "*.DS_Store"
```

Adjust the version number in the filename to match the `system.conf` version and
your desired release tag.

## Notes

- SG200 scraping is HTTP-based because some firmware builds do not support SNMP.
- The Playwright scraper discovers the `csbXXXXXX` prefix after login, then directly loads
  the dynamic MAC table page and parses VLAN/MAC/port index from hidden form fields.
