
import sys
import threading
from PyQt5.QtCore import pyqtSignal, QTimer

from PyQt5.QtWidgets import (
    QApplication, QWidget, QListWidget, QTextEdit,
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton
)

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from matplotlib.figure import Figure
import socket

from sniffer import start_sniffing, register_listener
from storage import get_traffic_by_ip, get_domain_stats
from exporter import export_csv, export_json


class GraphCanvas(FigureCanvasQTAgg):
    def __init__(self):
        self.figure = Figure(figsize=(5, 3))
        super().__init__(self.figure)

    def plot(self):
        self.figure.clear()
        ax = self.figure.add_subplot(111)

        stats = get_domain_stats()

        if stats:
            domains = list(stats.keys())
            counts = list(stats.values())

            ax.bar(domains, counts)
            ax.set_title("Domain Access Frequency")
            ax.set_ylabel("Requests")
            ax.set_xlabel("Domain")
            ax.set_xticklabels(domains, rotation=45, ha="right")

        self.draw()


from PyQt5.QtCore import pyqtSignal

class WifiMonitor(QWidget):
    ip_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Wi-Fi Traffic Monitor")
        self.setGeometry(200, 200, 1000, 500)

        self.ip_list = QListWidget()
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)

        self.graph = GraphCanvas()

        self.export_csv_btn = QPushButton("Export CSV")
        self.export_json_btn = QPushButton("Export JSON")

        left_layout = QVBoxLayout()
        left_layout.addWidget(QLabel("Active IPs"))
        left_layout.addWidget(self.ip_list)

        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Traffic Details"))
        right_layout.addWidget(self.log_view)
        right_layout.addWidget(self.graph)
        right_layout.addWidget(self.export_csv_btn)
        right_layout.addWidget(self.export_json_btn)

        main_layout = QHBoxLayout()
        main_layout.addLayout(left_layout, 2)
        main_layout.addLayout(right_layout, 5)

        self.setLayout(main_layout)

        # connections
        self.ip_list.itemClicked.connect(self.load_ip_traffic)
        self.export_csv_btn.clicked.connect(export_csv)
        self.export_json_btn.clicked.connect(export_json)

        # thread-safe buffering of incoming IP events
        self.pending_ips = set()
        self.update_timer = QTimer(self)
        self.update_timer.setInterval(1000)  # flush every 1s
        self.update_timer.timeout.connect(self.flush_pending_ips)

        # connect signal to buffer (runs in GUI thread)
        self.ip_signal.connect(self.buffer_ip)
        register_listener(self.emit_ip)

    def emit_ip(self, ip):
        try:
            self.ip_signal.emit(str(ip))
        except Exception:
            print("emit_ip: failed to emit", repr(ip))

    def buffer_ip(self, ip):
        try:
            self.pending_ips.add(str(ip))
            if not self.update_timer.isActive():
                self.update_timer.start()
        except Exception as e:
            print("buffer_ip error:", e)

    def flush_pending_ips(self):
        try:
            if not self.pending_ips:
                return

            existing_ips = {self.ip_list.item(i).text() for i in range(self.ip_list.count())}
            for ip in list(self.pending_ips):
                if ip not in existing_ips:
                    self.ip_list.addItem(ip)
            print("flush_pending_ips - current ip_list:", [self.ip_list.item(i).text() for i in range(self.ip_list.count())])

            # clear pending and update graph once
            self.pending_ips.clear()
        except Exception as e:
            print("flush_pending_ips error:", e)

        self.graph.plot()

    # 🔥 MISSING FUNCTION (now added)
    def load_ip_traffic(self, item):
        ip = item.text()
        print("load_ip_traffic for:", ip)
        self.log_view.clear()

        records = get_traffic_by_ip(ip)
        print("records found:", len(records))
        for entry in records:
            dst = entry.get("domain", "")
            self.log_view.append(f"[{entry['time']}] {dst}")




def run_sniffer():
    start_sniffing()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WifiMonitor()

    # Start sniffing after GUI and listeners are registered to avoid race
    sniff_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniff_thread.start()

    window.show()
    sys.exit(app.exec_())

