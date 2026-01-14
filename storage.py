import json
import os
from threading import Lock
import ipaddress

FILE = "traffic.json"
lock = Lock()

# ensure the file exists and contains a valid JSON object
if not os.path.exists(FILE) or os.path.getsize(FILE) == 0:
    with open(FILE, 'w') as f:
        json.dump({}, f)

def load_data():
    with lock:
        with open(FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                # empty or corrupted file — return empty mapping
                return {}
        

def save_data(data):
    with lock:
        with open(FILE, 'w') as f:
            json.dump(data, f, indent=2)

def add_traffic(ip,domain, time):
    data = load_data()
    if ip not in data:
        data[ip] = []
    data[ip].append({"domain": domain, "time": time})
    save_data(data)

def get_traffic_by_ip(ip):
    data = load_data()

    # Exact match first
    if ip in data:
        return data[ip]

    # Try to match IPv4-mapped or NAT64 variants
    def _normalize(ip_str: str) -> str:
        # IPv4-mapped ::ffff:192.0.2.1
        try:
            addr = ipaddress.ip_address(ip_str)
            if isinstance(addr, ipaddress.IPv4Address):
                return str(addr)
            if isinstance(addr, ipaddress.IPv6Address):
                if addr.ipv4_mapped:
                    return str(addr.ipv4_mapped)
        except Exception:
            pass

        # NAT64 well-known prefix 64:ff9b::/96 handling (best-effort)
        if ip_str.startswith("64:ff9b::"):
            try:
                parts = ip_str.split(":")
                tail = parts[-2:]
                hexstr = "".join(p for p in tail)
                if len(hexstr) >= 8:
                    hexstr = hexstr[-8:]
                    a = int(hexstr[0:2], 16)
                    b = int(hexstr[2:4], 16)
                    c = int(hexstr[4:6], 16)
                    d = int(hexstr[6:8], 16)
                    return f"{a}.{b}.{c}.{d}"
            except Exception:
                pass

        return ip_str

    target_norm = _normalize(ip)
    for key, entries in data.items():
        if _normalize(key) == target_norm:
            return entries

    return []

def get_domain_stats():
    data = load_data()
    stats = {}
    for ip in data:
        for entry in data[ip]:
            domain = entry["domain"]
            stats[domain] = stats.get(domain, 0) + 1

    return stats