import json
import csv
from storage import load_data

def export_csv(filename="traffic.csv"):
    data = load_data()
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Domain", "Time"])
        for ip,entries in data.items():
            for e in entries:
                writer.writerow([ip, e["domain"], e["time"]])

def export_json(filename="traffic_export.json"):
    with open(filename, "w") as f:
        json.dump(load_data(), f, indent=2)