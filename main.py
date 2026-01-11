
import sys
import threading

from PyQt5.QtWidgets import (
    QApplication, QWidget, QListWidget, QTextEdit,
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton
)

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from matplotlib.figure import Figure

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


class WifiMonitor(QWidget):
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

        self.ip_list.itemClicked.connect(self.load_ip_traffic)
        self.export_csv_btn.clicked.connect(export_csv)
        self.export_json_btn.clicked.connect(export_json)

        register_listener(self.update_ip_list)

    def update_ip_list(self, ip):
        existing_ips = [
            self.ip_list.item(i).text()
            for i in range(self.ip_list.count())
        ]

        if ip not in existing_ips:
            self.ip_list.addItem(ip)

        self.graph.plot()

    def load_ip_traffic(self, item):
        ip = item.text()
        self.log_view.clear()

        records = get_traffic_by_ip(ip)
        for entry in records:
            self.log_view.append(
                f"[{entry['time']}] {entry['domain']}"
            )


def run_sniffer():
    start_sniffing()


if __name__ == "__main__":
    sniff_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniff_thread.start()

    app = QApplication(sys.argv)
    window = WifiMonitor()
    window.show()
    sys.exit(app.exec_())

