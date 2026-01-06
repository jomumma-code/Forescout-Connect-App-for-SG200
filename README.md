# SG200 / Netgear Collector + Forescout Connect Apps

This repository contains:

- **Playwright-based collectors** for Cisco SG200 switches and Netgear routers.
- **Forescout Connect app packages** for SG200 and Netgear that call the external collector.
- Packaged zip artifacts for each app version.

## Repository layout (high level)

```
.
├── scraper/                # Collector service + scraper client modules
│   ├── collector.py        # Flask API for SG200 + Netgear
│   ├── scrapers/           # Scraper client modules loaded lazily
│   │   ├── sg200_client.py # Playwright scraper for SG200 dynamic MAC table
│   │   └── netgear_client.py # HTTP scraper for Netgear access control list
│   └── *.har.txt           # HTTP capture references
├── SG200/                  # SG200 Connect app artifacts
│   └── app/
│       ├── data/           # system.conf, property.conf, sg200_test.py, sg200_poll.py
│       └── SG200-*.zip     # Versioned packaged app bundles
└── NETGEAR/                # Netgear Connect app artifacts
    ├── data/               # system.conf, property.conf, netgear_ac_test.py, netgear_ac_poll.py
    └── NETGEAR-*.zip       # Versioned packaged app bundles
```

## Collector service

The collector is a Flask API that runs Playwright (for SG200) and HTTP scraping (for Netgear).

### Endpoints

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
        {"switch_ip": "192.168.0.221", "vlan": 1, "mac": "aa:bb:cc:dd:ee:ff", "port_index": 52}
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

### Auth controls (optional)

This deployment uses HTTP between Connect and the collector. You can enable two optional controls:

- **IP allowlist**: set `SG200_COLLECTOR_ALLOWED_IPS` to a comma-separated list of allowed client IPs.
- **Shared token**: set `SG200_COLLECTOR_TOKEN`, and send `X-Collector-Token` in requests.

The Connect SG200 app exposes a `Collector Token` field that maps to the `X-Collector-Token` header.

### Running the collector

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

## Packaging

The `SG200-*.zip` and `NETGEAR-*.zip` files are packaged Connect apps ready for import.

## Notes

- SG200 scraping is HTTP-based because some firmware builds do not support SNMP.
- The Playwright scraper discovers the `csbXXXXXX` prefix after login, then directly loads
  the dynamic MAC table page and parses VLAN/MAC/port index from hidden form fields.
