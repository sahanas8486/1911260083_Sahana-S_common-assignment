# Network Security and Firewall Monitoring System

A web-based educational firewall monitoring system built with **Flask** and **SQLite**.  
It simulates network traffic, applies configurable packet-filtering rules, logs every decision, and raises alerts when a possible Denial-of-Service (DoS) pattern is detected.

This project matches the design described in the accompanying project report (SIMATS Engineering, 2026).

---

## Features

- **Traffic Simulation** – Generates realistic packets (≈80 % legitimate, ≈20 % potentially malicious) with source/destination IP, port and protocol.
- **Configurable Firewall Rules** – Create, view and delete rules based on source IP, destination IP, port and protocol. Supports wildcards (`*`, `192.168.1.*`).
- **Rule Evaluation Engine** – Ordered rule matching with **implicit default-deny** policy.
- **Security Logging** – Every packet is recorded with timestamp, details and final action (ALLOW / BLOCK).
- **DoS Detection** – If one source IP produces 5+ blocked packets in the recent window, a High-severity alert is raised and related logs are marked suspicious.
- **Real-time Dashboard** – Live statistics, packet log table and security alerts panel.
- **Clean Web UI** – Dark-themed responsive interface.

---

## Project Structure

```
Network_Security_Firewall_Monitoring_System/
├── app.py                 # Main Flask application (backend + logic)
├── requirements.txt       # Python dependencies
├── README.md              # This file
├── firewall.db            # SQLite database (created automatically on first run)
├── templates/
│   ├── base.html          # Common layout
│   ├── dashboard.html     # Traffic dashboard
│   ├── rules.html         # Rule management page
│   └── alerts.html        # Full alerts list
└── static/
    ├── css/
    │   └── style.css      # Stylesheet
    └── js/
        └── main.js        # Small client-side helpers
```

---

## Requirements

- Python 3.8 or higher
- Flask 2.x or higher

---

## Installation & Running

```bash
# 1. Clone the repository (or download the folder)
git clone <your-repo-url>
cd Network_Security_Firewall_Monitoring_System

# 2. (Optional but recommended) Create a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

Open your browser and go to:

```
http://127.0.0.1:5000
```

The SQLite database and default firewall rules are created automatically on the first run.

---

## Default Firewall Rules

| Name                        | Source        | Destination   | Port | Protocol | Action |
|-----------------------------|---------------|---------------|------|----------|--------|
| Allow Web Traffic (HTTP)    | *             | *             | 80   | TCP      | ALLOW  |
| Allow Web Traffic (HTTPS)   | *             | *             | 443  | TCP      | ALLOW  |
| Allow Internal DNS          | 192.168.1.*   | 192.168.1.*   | 53   | UDP      | ALLOW  |
| Block SSH from outside      | *             | 192.168.1.10  | 22   | TCP      | BLOCK  |
| Block known malicious IP    | 203.0.113.50  | *             | Any  | *        | BLOCK  |
| Allow Internal Traffic      | 192.168.1.*   | 192.168.1.*   | Any  | *        | ALLOW  |

Unmatched traffic is blocked by the **implicit deny** policy.

---

## How to Demonstrate

1. Open the **Dashboard**.
2. Click **Simulate Traffic (20 packets)** a few times.
3. Observe packets being marked ALLOW or BLOCK in the log table.
4. After several simulations, source IPs such as `203.0.113.50` will accumulate blocked packets and trigger a **DoS Alert**.
5. Go to **Firewall Rules** to add or delete rules and see how the behaviour changes.
6. Use **Clear Logs & Alerts** to reset the demonstration.

---

## DoS Detection Logic

- Looks at the most recent 100 log entries.
- Counts blocked packets per source IP.
- If any IP reaches **5 or more** blocked packets → raises a High-severity “DoS Alert”.
- Related log entries are marked as suspicious.
- Duplicate alerts for the same IP are suppressed for 1 minute.

The threshold can be changed in `app.py` (`DOS_THRESHOLD`).

---

## Technologies Used

| Technology   | Role                          |
|--------------|-------------------------------|
| Python 3.8+  | Core language                 |
| Flask        | Web framework & routing       |
| Jinja2       | HTML templating               |
| SQLite       | Embedded database             |
| HTML5/CSS3   | Frontend structure & styling  |
| JavaScript   | Minor client-side interactions|

---

## Scope & Limitations (Educational)

- Uses **simulated** traffic only (no real packet capture).
- Stateless packet filtering (no connection tracking).
- No deep packet inspection or machine-learning detection.
- Single-user, no authentication.

These limitations are intentional so the core concepts of packet filtering, access control and basic intrusion detection remain easy to understand.

---

## Future Enhancements (from Report)

- Real packet capture (Scapy / pcap)
- Stateful inspection
- Deep packet inspection
- Machine-learning anomaly detection
- User authentication & roles
- Charts and advanced visualisation
- Rule reordering (drag-and-drop)
- Alert notifications (email / webhook)
- Docker packaging

---

## License

This project is provided for educational purposes.
