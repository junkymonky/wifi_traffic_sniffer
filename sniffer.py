from scapy.all import sniff, raw, TCP
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from datetime import datetime
from storage import add_traffic
from scapy.config import conf
import os
import socket
from scapy.layers.http import HTTPRequest


def _extract_sni_from_payload(payload: bytes) -> str | None:
    """Attempt to parse TLS ClientHello from raw payload and return SNI string.

    Returns the first server_name entry or None on failure.
    This parser is defensive and performs bounds checks to avoid exceptions.
    """
    try:
        if len(payload) < 5:
            return None

        # TLS record header: ContentType(1)=0x16, Version(2), Length(2)
        if payload[0] != 0x16:
            return None

        # handshake starts after 5-byte record header
        ptr = 5
        if ptr + 4 > len(payload):
            return None

        # Handshake header: HandshakeType(1)=0x01 (ClientHello), Length(3)
        if payload[ptr] != 0x01:
            return None

        # advance past handshake header
        ptr += 4

        # skip client_version (2) + random (32)
        if ptr + 34 > len(payload):
            return None
        ptr += 34

        # Session ID
        if ptr + 1 > len(payload):
            return None
        session_id_len = payload[ptr]
        ptr += 1 + session_id_len

        # Cipher suites
        if ptr + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[ptr:ptr+2], "big")
        ptr += 2 + cs_len

        # Compression methods
        if ptr + 1 > len(payload):
            return None
        comp_len = payload[ptr]
        ptr += 1 + comp_len

        # Extensions length
        if ptr + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[ptr:ptr+2], "big")
        ptr += 2
        end_ext = ptr + ext_len

        while ptr + 4 <= end_ext and ptr + 4 <= len(payload):
            ext_type = int.from_bytes(payload[ptr:ptr+2], "big")
            elen = int.from_bytes(payload[ptr+2:ptr+4], "big")
            ptr += 4
            if ptr + elen > len(payload):
                return None

            if ext_type == 0x0000:
                # server_name extension
                data = payload[ptr:ptr+elen]
                if len(data) < 2:
                    return None
                list_len = int.from_bytes(data[0:2], "big")
                pos = 2
                while pos + 3 <= len(data):
                    name_type = data[pos]
                    name_len = int.from_bytes(data[pos+1:pos+3], "big")
                    pos += 3
                    if pos + name_len > len(data):
                        break
                    name = data[pos:pos+name_len].decode(errors="ignore")
                    return name
            ptr += elen

    except Exception:
        return None

    return None


_reverse_cache: dict[str, str | None] = {}


def _reverse_lookup_cached(ip: str) -> str | None:
    if ip in _reverse_cache:
        return _reverse_cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
        # ignore results that are literal IPs
        if any(c.isalpha() for c in name):
            _reverse_cache[ip] = name
            # keep cache bounded
            if len(_reverse_cache) > 1000:
                _reverse_cache.pop(next(iter(_reverse_cache)))
            return name
    except Exception:
        pass
    _reverse_cache[ip] = None
    return None


def _normalize_ip(ip: str) -> str:
    """Convert IPv6-mapped or NAT64 addresses to IPv4 dotted form when possible."""
    # IPv4-mapped ::ffff:192.0.2.1
    if ip.startswith("::ffff:"):
        try:
            return ip.split(":")[-1]
        except Exception:
            return ip

    # NAT64 well-known prefix 64:ff9b::/96
    if ip.startswith("64:ff9b::") and len(ip.split(":")) >= 3:
        # last 32 bits encoded in hex groups
        try:
            # extract last 32-bit hex (two 16-bit groups)
            parts = ip.split(":")
            tail = parts[-2:] if len(parts) >= 2 else parts[-1:]
            # build a 32-bit hex string from tail groups
            hexstr = "".join(p for p in tail)
            # ensure even length
            if len(hexstr) >= 8:
                hexstr = hexstr[-8:]
                a = int(hexstr[0:2], 16)
                b = int(hexstr[2:4], 16)
                c = int(hexstr[4:6], 16)
                d = int(hexstr[6:8], 16)
                return f"{a}.{b}.{c}.{d}"
        except Exception:
            return ip

    return ip

# Allow promiscuous mode by default and support an optional IFACE env var
conf.sniff_promisc = True

listeners = []

def register_listener(callback):
    listeners.append(callback)

def notify(ip):
    for cb in listeners:
        cb(ip)

def process_packet(packet):

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

    elif packet.haslayer(IPv6):
        src = packet[IPv6].src
        dst = packet[IPv6].dst

    else:
        return

    time = datetime.now().strftime("%H:%M:%S")

    # normalize source and destination IPs (handle NAT64 / ::ffff:)
    norm_src = _normalize_ip(src)
    norm_dst = _normalize_ip(dst)

    # Determine a human-friendly domain/name for the destination
    domain = None

    try:
        # 1) HTTP Host
        if packet.haslayer(HTTPRequest):
            host = packet[HTTPRequest].Host
            if isinstance(host, bytes):
                domain = host.decode(errors="ignore")
            else:
                domain = str(host)

        # 2) TLS SNI
        if domain is None and packet.haslayer(TCP):
            payload = raw(packet[TCP].payload)
            if payload:
                sni = _extract_sni_from_payload(bytes(payload))
                if sni:
                    domain = sni

        # 3) reverse DNS (cached) — accept only if it contains alphabetic chars
        if domain is None:
            rd = _reverse_lookup_cached(norm_dst)
            if rd:
                domain = rd

    except Exception:
        domain = None

    # final fallback: store normalized destination IP if we don't have a hostname
    domain_to_store = domain if domain else norm_dst

    add_traffic(norm_src, domain_to_store, time)
    notify(norm_src)

def start_sniffing():
    iface = os.getenv("IFACE", None)
    sniff(
        iface=iface,          # <-- use IFACE env var if set
        filter="ip or ip6",
        prn=process_packet,
        store=False
    )
