# Wi‑Fi Traffic Sniffer

Lightweight Wi‑Fi traffic monitor with a PyQt GUI, packet capture (Scapy), simple JSON storage and CSV/JSON export.

Features
- Live packet capture (IPv4/IPv6) using Scapy
- GUI showing active IPs and per‑IP traffic records
- Domain extraction: HTTP `Host`, TLS SNI (ClientHello), then reverse DNS (cached)
- Normalizes IPv4-mapped and common NAT64 addresses to dotted IPv4 when possible
- Simple persistent storage in `traffic.json` and CSV/JSON export via `exporter.py`

Quickstart
1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the app with sufficient privileges (Scapy needs raw socket access):

Option A — run as root (quick):
```bash
sudo python3 main.py
```

Option B — grant Python capability (preferred for security):
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
IFACE=wlan0 python3 main.py
```

Notes on `IFACE`
- `sniffer.py` respects an `IFACE` environment variable — set it to your capture interface (e.g. `wlan0`) to focus capture. If unset, Scapy will choose a default interface.

How the UI works
- Left pane: active IPs captured. Click an IP to view traffic details in the right pane.
- Right pane: traffic entries show timestamp and a domain-like name. Names come from HTTP Host or TLS SNI when available; otherwise a reverse DNS or the raw IP is stored.
- Use the Export buttons to save CSV/JSON snapshots.

Developer notes
- Key files:
  - `sniffer.py`: packet processing, domain extraction (HTTP Host, TLS SNI), IP normalization, and listener interface.
  - `main.py`: PyQt GUI, buffered IP updates (throttled), UI handlers.
  - `storage.py`: JSON-backed storage (`traffic.json`) and helper functions; matching tolerant of IPv4/IPv6 variants.
  - `exporter.py`: CSV/JSON export of stored data.

- Performance/behavior notes:
  - Reverse DNS runs are cached to avoid repeated blocking calls in the sniffing path.
  - UI updates are buffered and flushed once per second to avoid costly plot redraws under high traffic.
  - SNI extraction is best-effort from raw TCP payloads; HTTPS identification depends on seeing the TLS ClientHello.

Troubleshooting
- `traffic.json` remains empty: likely lacking capture privileges — run with `sudo` or `setcap`.
- No other hosts visible: ensure you're on the correct interface and (if needed) enable promiscuous mode or capture on an AP/monitor interface.
- Export CSV fails: ensure `csv` is available (standard library) and disk writable.

Extending the project
- Consider adding async name resolution, a small LRU cache, or passive HTTP/TLS parsing for richer metadata (SNI + Host + headers).
- Tests are not included — add unit tests for `storage.py` and payload parsers before refactoring.

