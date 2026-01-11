import json
import os
from threading import Lock

FILE = "traffic.json"
lock = Lock()

if not os.path.exists(FILE):
    with open(FILE, 'w') as f:
        json.dump({}, f)

def load_data():
    with lock:
        with open(FILE, 'r') as f:
            return json.load(f)
        

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
    return data.get(ip, [])

def get_domain_stats():
    data = load_data()
    stats = {}
    for ip in data:
        for entry in data[ip]:
            domain = entry["domain"]
            stats[domain] = stats.get(domain, 0) + 1

    return stats