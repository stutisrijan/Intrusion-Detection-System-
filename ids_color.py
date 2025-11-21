# ids_color.py
from scapy.all import sniff, IP, TCP, DNS
from scapy.layers.http import HTTPRequest
import logging
import json
import time
from collections import defaultdict
from colorama import init as colorama_init, Fore, Style

# ---------------- CONFIG ----------------
INTERFACE = "Wi-Fi"           # keep as you had it
LOG_FILE = "ids_logs.log"     # plain text log (human)
EVENT_FILE = "ids_events.jsonl"  # JSON lines of events (dashboard reads)
STATS_FILE = "ids_stats.json"    # aggregated counters (dashboard reads)

# thresholds
THRESHOLD_DOS = 100
TIME_WINDOW = 10  # seconds

# ----------------------------------------
colorama_init(autoreset=True)

# logging to file
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# also show console messages in color
console_logger = logging.getLogger()
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_logger.addHandler(console_handler)

# internal counters & trackers
ip_packet_counter = defaultdict(int)
port_scan_tracker = defaultdict(set)
last_reset_time = time.time()

# Stats to expose to dashboard
stats = {
    "total_packets": 0,
    "dos_count": 0,
    "portscan_count": 0,
    "dns_count": 0,
    "http_suspicious_count": 0,
    "unique_attackers": set()  # stored as list when written
}

# helper to persist event and stats
def append_event(event: dict):
    """Append event dict to JSONL file and update stats file."""
    # timestamp
    event['timestamp'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    # append to jsonl
    with open(EVENT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

    # update stats structure and write stats snapshot
    stats_snapshot = {
        "total_packets": stats["total_packets"],
        "dos_count": stats["dos_count"],
        "portscan_count": stats["portscan_count"],
        "dns_count": stats["dns_count"],
        "http_suspicious_count": stats["http_suspicious_count"],
        "unique_attackers": list(stats.get("unique_attackers", []))
    }
    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(stats_snapshot, f, indent=2)

# pretty console printing with colors
def console_info(msg):
    print(Fore.GREEN + msg + Style.RESET_ALL)
    logging.info(msg)

def console_warn(msg):
    print(Fore.YELLOW + msg + Style.RESET_ALL)
    logging.warning(msg)

def console_alert(msg):
    print(Fore.RED + msg + Style.RESET_ALL)
    logging.warning(msg)

# detection functions
def detect_port_scan(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        port_scan_tracker[src_ip].add(dst_port)

        if len(port_scan_tracker[src_ip]) > 10:
            stats["portscan_count"] += 1
            stats["unique_attackers"].add(src_ip)
            msg = f"[PORT SCAN DETECTED] Source: {src_ip} Ports: {sorted(port_scan_tracker[src_ip])}"
            console_warn(msg)
            append_event({"type": "portscan", "source": src_ip, "ports": list(port_scan_tracker[src_ip])})
            # clear to avoid continuous repeats
            port_scan_tracker[src_ip].clear()

def detect_dos(packet):
    global last_reset_time
    current_time = time.time()

    if current_time - last_reset_time > TIME_WINDOW:
        ip_packet_counter.clear()
        last_reset_time = current_time

    if IP in packet:
        src_ip = packet[IP].src
        ip_packet_counter[src_ip] += 1
        if ip_packet_counter[src_ip] > THRESHOLD_DOS:
            stats["dos_count"] += 1
            stats["unique_attackers"].add(src_ip)
            msg = f"[DoS ATTACK DETECTED] Source: {src_ip} Count: {ip_packet_counter[src_ip]}"
            console_alert(msg)
            append_event({"type": "dos", "source": src_ip, "count": ip_packet_counter[src_ip]})
            # optional: reset counter for that IP so not repeated every packet
            ip_packet_counter[src_ip] = 0

def detect_suspicious_http(packet):
    if packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
        host = http_layer.Host.decode() if http_layer.Host else "Unknown"
        path = http_layer.Path.decode() if http_layer.Path else "Unknown"
        url = f"http://{host}{path}"
        stats["http_suspicious_count"] += 0  # leave unchanged unless suspicious
        console_info(f"[HTTP TRAFFIC] Request to {url}")
        if "suspicious" in url:
            stats["http_suspicious_count"] += 1
            stats["unique_attackers"].add(packet[IP].src if IP in packet else "unknown")
            console_warn(f"[SUSPICIOUS HTTP DETECTED] URL: {url}")
            append_event({"type": "http_suspicious", "url": url, "source": packet[IP].src if IP in packet else "unknown"})

def detect_dns_activity(packet):
    if packet.haslayer(DNS) and packet[DNS].qd:
        domain = packet[DNS].qd.qname.decode()
        stats["dns_count"] += 1
        stats["unique_attackers"].add(packet[IP].src if IP in packet else "unknown")
        console_info(f"[DNS QUERY] Domain: {domain}")
        append_event({"type": "dns_query", "domain": domain, "source": packet[IP].src if IP in packet else "unknown"})
        if "malicious" in domain:
            console_warn(f"[MALICIOUS DNS QUERY DETECTED] Domain: {domain}")
            append_event({"type": "dns_malicious", "domain": domain, "source": packet[IP].src if IP in packet else "unknown"})

def packet_callback(packet):
    try:
        stats["total_packets"] += 1
        # basic prints for normal traffic count every 50 packets to avoid flooding console
        if stats["total_packets"] % 50 == 0:
            console_info(f"Total packets seen: {stats['total_packets']}")

        if IP in packet:
            detect_port_scan(packet)
            detect_dos(packet)

        if packet.haslayer(HTTPRequest):
            detect_suspicious_http(packet)

        if packet.haslayer(DNS):
            detect_dns_activity(packet)

    except Exception as e:
        console_warn(f"[ERROR] Packet processing error: {e}")
        logging.error(f"Packet processing error: {e}")

def main():
    console_info("[*] Starting IDS (color mode) ...")
    # write initial empty stats file so dashboard can read immediately
    append_event({"type": "startup", "message": "IDS started"})
    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        console_info("\n[*] Stopping IDS. Exiting...")
    except Exception as e:
        console_alert(f"[ERROR] Failed to start packet capture: {e}")
        logging.error(f"Failed to start packet capture: {e}")

if __name__ == "__main__":
    main()
