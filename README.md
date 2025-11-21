🛡️ Intrusion Detection System (IDS) Using Python & Scapy

A lightweight, real-time Intrusion Detection System built using Python.
It monitors live network traffic, detects malicious patterns, and displays alerts via:

Colored terminal output

JSON logs

Interactive Flask dashboard

This IDS is designed to be simple, fast, and perfect for academic projects or small network monitoring.

🚀 Features
🔍 Detection Capabilities

Port Scan Detection
Tracks unique ports accessed by an IP.

DoS / High Traffic Detection
Identifies sudden packet bursts from a single source.

Suspicious HTTP Request Detection
Flags URLs containing suspicious keywords.

Malicious DNS Query Detection
Alerts when domains include malicious patterns.

📁 Project Structure
IDS/
│── ids.py                 # Main IDS engine
│── ids_color.py           # Color-coded terminal alerts
│── dashboard.py           # Flask dashboard (charts + counters)
│── events.json            # Logged attack events
│── stats.json             # Traffic/alert statistics
│── templates/
│     └── dashboard.html   # Frontend UI
│── static/
      └── chart.js

⚙️ Installation
1️⃣ Install dependencies
pip install scapy flask colorama

2️⃣ Run Command Prompt as Administrator

Packet sniffing requires admin/root permissions.

▶️ How to Run the Project
1. Start the IDS Engine
cd C:\Users\Hp\Desktop\ids
python ids.py


This begins live packet sniffing & attack detection.

2. Start Color-Coded Alerts
cd C:\Users\Hp\Desktop\ids
python ids_color.py


Terminal colors:

🟢 Normal

🟡 Suspicious

🔴 Attack Detected

3. Launch the Dashboard
cd C:\Users\Hp\Desktop\ids
python dashboard.py


Open browser:
👉 http://127.0.0.1:5000/

Dashboard shows:

Total packets

DoS attempts

Port scans

HTTP alerts

DNS queries

Pie chart of attacks

Live event feed

🧪 How to Test the IDS

Use these tests to demonstrate your system.

1️⃣ Port Scan Test

Run from another system or Kali if available:

nmap <your-ip>


Expected:

Port scan alert in terminal

Event added to dashboard

2️⃣ DoS-like Traffic Test

Use continuous ping:

ping -t <ip>


This quickly increases packets → triggers DoS detection.

3️⃣ Suspicious HTTP URL Test

In browser, open:

http://localhost/suspicious


Triggers suspicious HTTP alert.

4️⃣ Malicious DNS Query Test

Visit a fake domain:

malicious.test


Triggers DNS malicious query detection.

🧠 How It Works

Scapy sniffs live packets from Wi-Fi or Ethernet.

Each packet is analyzed for:

High frequency

Multiple port hits

Suspicious URLs

Suspicious domain names

Alerts are generated and saved in JSON.

Dashboard updates automatically and displays:

Counters

Event list

Graphs

IDS runs continuously in a loop.

📊 Output Examples
✔️ Terminal Alerts

Color-coded alerts showing detection events.

✔️ Dashboard

Graph of attack categories

Real-time events section

Total counts of DNS, HTTP, Port Scan, DoS

🔚 Conclusion

This project demonstrates how Python can be used to build a simple but effective Intrusion Detection System. It is lightweight, beginner-friendly, and ideal for cybersecurity demonstrations, classroom learning, and small network environments.

🔮 Future Improvements

Machine learning anomaly detection

GeoIP attacker location

Telegram/WhatsApp alerting

Database instead of JSON

Multi-device centralized IDS
