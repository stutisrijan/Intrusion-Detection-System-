from scapy.all import sniff, IP, TCP, UDP, DNS
from scapy.layers.http import HTTPRequest
import logging
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict
import time

# CONFIGURATION 
INTERFACE = 'Wi-Fi'  
LOG_FILE = 'ids_logs.log'
ALERT_EMAIL = 'reciever mail id'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'sender mail id'
SMTP_PASSWORD = 'sender mail password'


ip_packet_counter = defaultdict(int)  
THRESHOLD_DOS = 100  
TIME_WINDOW = 10  
last_reset_time = time.time()


# SETUP LOGGING 
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# ALERT FUNCTION 
def send_alert(subject, message):
    """Send an alert via email."""
    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = SMTP_USERNAME
        msg['To'] = ALERT_EMAIL

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_USERNAME, ALERT_EMAIL, msg.as_string())
        logging.info(f"[ALERT SENT] {subject}")
    except Exception as e:
        logging.error(f"[ERROR] Failed to send alert: {e}")


# DETECTION LOGIC 
port_scan_tracker = defaultdict(set)    

def detect_port_scan(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        port_scan_tracker[src_ip].add(dst_port)

        if len(port_scan_tracker[src_ip]) > 10:  
            logging.warning(f"[PORT SCAN DETECTED] Source: {src_ip}")
            send_alert(
                "Port Scan Detected",
                f"Port scan detected from {src_ip}. Targeted ports: {port_scan_tracker[src_ip]}"
            )
            port_scan_tracker[src_ip].clear()


def detect_dos(packet):
    """Detect potential DoS attacks based on traffic volume."""
    global last_reset_time
    current_time = time.time()

    if current_time - last_reset_time > TIME_WINDOW:
        ip_packet_counter.clear()
        last_reset_time = current_time

    if IP in packet:
        src_ip = packet[IP].src
        ip_packet_counter[src_ip] += 1

        if ip_packet_counter[src_ip] > THRESHOLD_DOS:
            logging.warning(f"[DoS ATTACK DETECTED] Source: {src_ip}")
            send_alert(
                "Potential DoS Attack Detected",
                f"High traffic volume detected from {src_ip}. Possible DoS attack."
            )


def detect_suspicious_http(packet):
    """Detect suspicious HTTP requests."""
    if packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
        host = http_layer.Host.decode() if http_layer.Host else "Unknown"
        path = http_layer.Path.decode() if http_layer.Path else "Unknown"
        url = f"http://{host}{path}"

        logging.info(f"[HTTP TRAFFIC] Request to {url}")
        if "suspicious" in url:  
            logging.warning(f"[SUSPICIOUS HTTP DETECTED] URL: {url}")
            send_alert(
                "Suspicious HTTP Traffic Detected",
                f"Suspicious HTTP request detected: {url}"
            )


# PACKET HANDLER
def packet_callback(packet):
    """Analyze each captured packet."""
    try:
        if IP in packet:
            detect_port_scan(packet)
            detect_dos(packet)

        if packet.haslayer(HTTPRequest):
            detect_suspicious_http(packet)

        if DNS in packet:
            detect_dns_activity(packet)

    except Exception as e:
        logging.error(f"[ERROR] Packet processing error: {e}")


def detect_dns_activity(packet):
    """Monitor DNS queries."""
    if packet.haslayer(DNS) and packet[DNS].qd:
        domain = packet[DNS].qd.qname.decode()
        logging.info(f"[DNS QUERY] Domain: {domain}")
        if "malicious" in domain:  
            logging.warning(f"[MALICIOUS DNS QUERY DETECTED] Domain: {domain}")
            send_alert(
                "Malicious DNS Query Detected",
                f"Detected DNS query to a malicious domain: {domain}"
            )


#MAIN FUNCTION 
def main():
    print("[*] Starting IDS...")
    try:
        sniff(iface=INTERFACE, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS. Exiting...")
    except Exception as e:
        logging.error(f"[ERROR] Failed to start packet capture: {e}")


if __name__ == "__main__":
    main()
