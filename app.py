"""
Network Security and Firewall Monitoring System
Flask + SQLite implementation matching the project report.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
from datetime import datetime, timedelta
import random
import os

app = Flask(__name__)
app.secret_key = "network_security_firewall_monitoring_2026"

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall.db")

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            src_ip TEXT DEFAULT '*',
            dst_ip TEXT DEFAULT '*',
            port INTEGER DEFAULT 0,
            protocol TEXT DEFAULT '*',
            action TEXT NOT NULL CHECK(action IN ('ALLOW', 'BLOCK'))
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            traffic_type TEXT NOT NULL,
            action TEXT NOT NULL,
            is_suspicious INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL
        )
    """)

    # Insert default rules only if table is empty
    cur.execute("SELECT COUNT(*) FROM firewall_rules")
    if cur.fetchone()[0] == 0:
        default_rules = [
            ("Allow Web Traffic (HTTP)", "*", "*", 80, "TCP", "ALLOW"),
            ("Allow Web Traffic (HTTPS)", "*", "*", 443, "TCP", "ALLOW"),
            ("Allow Internal DNS", "192.168.1.*", "192.168.1.*", 53, "UDP", "ALLOW"),
            ("Block SSH from outside", "*", "192.168.1.10", 22, "TCP", "BLOCK"),
            ("Block known malicious IP", "203.0.113.50", "*", 0, "*", "BLOCK"),
            ("Allow Internal Traffic", "192.168.1.*", "192.168.1.*", 0, "*", "ALLOW"),
        ]
        cur.executemany(
            "INSERT INTO firewall_rules (name, src_ip, dst_ip, port, protocol, action) VALUES (?, ?, ?, ?, ?, ?)",
            default_rules,
        )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Firewall rule-matching algorithm (as described in the report)
# ---------------------------------------------------------------------------

def check_firewall(src, dst, port, proto):
    """
    Evaluate packet against ordered list of rules.
    First matching rule wins. Implicit deny if nothing matches.
    """
    conn = get_db()
    rules = conn.execute(
        "SELECT * FROM firewall_rules ORDER BY id"
    ).fetchall()
    conn.close()

    for rule in rules:
        # Protocol check
        if rule["protocol"] != "*" and rule["protocol"].upper() != proto.upper():
            continue
        # Port check (0 means any)
        if rule["port"] != 0 and rule["port"] != port:
            continue
        # Source IP check (supports simple wildcard *)
        if not match_ip(rule["src_ip"], src):
            continue
        # Destination IP check
        if not match_ip(rule["dst_ip"], dst):
            continue
        return rule["action"]

    return "BLOCK"  # Implicit deny


def match_ip(pattern, ip):
    """Simple wildcard matching: exact match or * or prefix.* style."""
    if pattern == "*":
        return True
    if pattern == ip:
        return True
    # Support patterns like 192.168.1.*
    if pattern.endswith(".*"):
        prefix = pattern[:-1]  # e.g. "192.168.1."
        return ip.startswith(prefix)
    return False


# ---------------------------------------------------------------------------
# Traffic simulation engine
# ---------------------------------------------------------------------------

INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 60)]
EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "203.0.113.50", "49.37.2.8",
    "114.114.114.114", "185.199.108.153", "104.16.132.229",
    "151.101.1.69", "13.107.42.14", "172.217.16.142"
]
MALICIOUS_SOURCES = ["203.0.113.50", "49.37.2.8", "114.114.114.114"]
COMMON_PORTS = {
    "HTTP": 80, "HTTPS": 443, "SSH": 22, "DNS": 53,
    "FTP": 21, "RDP": 3389, "HTTP-ALT": 8080, "MYSQL": 3306
}


def generate_traffic(count=20):
    """Generate a mix of legitimate (~80%) and potentially malicious (~20%) packets."""
    packets = []
    for _ in range(count):
        if random.random() < 0.80:
            # Legitimate traffic
            traffic_type = random.choice(["Internal", "Outbound"])
            if traffic_type == "Internal":
                src = random.choice(INTERNAL_IPS)
                dst = random.choice(INTERNAL_IPS)
                while dst == src:
                    dst = random.choice(INTERNAL_IPS)
                port = random.choice([53, 80, 443, 22])
                protocol = "UDP" if port == 53 else "TCP"
            else:
                src = random.choice(INTERNAL_IPS)
                dst = random.choice(["8.8.8.8", "1.1.1.1", "172.217.16.142", "151.101.1.69"])
                port = random.choice([80, 443, 53])
                protocol = "UDP" if port == 53 else "TCP"
        else:
            # Potentially malicious inbound traffic
            traffic_type = "Inbound"
            src = random.choice(MALICIOUS_SOURCES)
            dst = "192.168.1.10"  # main server
            port = random.choice([22, 21, 3389, 8080, 3306])
            protocol = "TCP"

        packets.append({
            "src_ip": src,
            "dst_ip": dst,
            "port": port,
            "protocol": protocol,
            "traffic_type": traffic_type,
        })
    return packets


# ---------------------------------------------------------------------------
# DoS detection
# ---------------------------------------------------------------------------

DOS_THRESHOLD = 5
RECENT_WINDOW = 100


def detect_dos():
    """
    Look at the most recent RECENT_WINDOW log entries.
    If any source IP has >= DOS_THRESHOLD blocked packets, raise an alert
    and mark those logs as suspicious. Suppress duplicate alerts within 1 minute.
    """
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM traffic_logs ORDER BY id DESC LIMIT ?",
        (RECENT_WINDOW,)
    ).fetchall()

    blocked_count = {}
    for log in logs:
        if log["action"] == "BLOCK":
            blocked_count[log["src_ip"]] = blocked_count.get(log["src_ip"], 0) + 1

    now = datetime.now()
    one_minute_ago = (now - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")

    for src_ip, count in blocked_count.items():
        if count >= DOS_THRESHOLD:
            # Check for recent duplicate alert
            existing = conn.execute(
                """SELECT id FROM security_alerts
                   WHERE description LIKE ? AND timestamp > ?
                   LIMIT 1""",
                (f"%{src_ip}%", one_minute_ago)
            ).fetchone()

            if existing:
                continue

            # Create alert
            timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
            description = (
                f"Possible DoS attack detected from source IP {src_ip}. "
                f"{count} blocked packets observed in recent window."
            )
            conn.execute(
                """INSERT INTO security_alerts (timestamp, alert_type, description, severity)
                   VALUES (?, ?, ?, ?)""",
                (timestamp, "DoS Alert", description, "High")
            )

            # Mark related logs as suspicious
            conn.execute(
                """UPDATE traffic_logs SET is_suspicious = 1
                   WHERE src_ip = ? AND action = 'BLOCK' AND is_suspicious = 0""",
                (src_ip,)
            )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    conn = get_db()

    total = conn.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
    allowed = conn.execute("SELECT COUNT(*) FROM traffic_logs WHERE action = 'ALLOW'").fetchone()[0]
    blocked = conn.execute("SELECT COUNT(*) FROM traffic_logs WHERE action = 'BLOCK'").fetchone()[0]
    alerts_count = conn.execute("SELECT COUNT(*) FROM security_alerts").fetchone()[0]

    recent_logs = conn.execute(
        "SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 50"
    ).fetchall()

    recent_alerts = conn.execute(
        "SELECT * FROM security_alerts ORDER BY id DESC LIMIT 10"
    ).fetchall()

    conn.close()

    stats = {
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "alerts": alerts_count,
    }
    return render_template(
        "dashboard.html",
        stats=stats,
        logs=recent_logs,
        alerts=recent_alerts,
    )


@app.route("/simulate", methods=["POST"])
def simulate():
    packets = generate_traffic(20)
    conn = get_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for pkt in packets:
        action = check_firewall(
            pkt["src_ip"], pkt["dst_ip"], pkt["port"], pkt["protocol"]
        )
        conn.execute(
            """INSERT INTO traffic_logs
               (timestamp, src_ip, dst_ip, port, protocol, traffic_type, action, is_suspicious)
               VALUES (?, ?, ?, ?, ?, ?, ?, 0)""",
            (
                now,
                pkt["src_ip"],
                pkt["dst_ip"],
                pkt["port"],
                pkt["protocol"],
                pkt["traffic_type"],
                action,
            ),
        )

    conn.commit()
    conn.close()

    # Run DoS detection after logging
    detect_dos()

    flash(f"Simulated {len(packets)} packets successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/rules")
def rules():
    conn = get_db()
    rules_list = conn.execute(
        "SELECT * FROM firewall_rules ORDER BY id"
    ).fetchall()
    conn.close()
    return render_template("rules.html", rules=rules_list)


@app.route("/rules/add", methods=["POST"])
def add_rule():
    name = request.form.get("name", "").strip()
    src_ip = request.form.get("src_ip", "*").strip() or "*"
    dst_ip = request.form.get("dst_ip", "*").strip() or "*"
    port = request.form.get("port", "0").strip() or "0"
    protocol = request.form.get("protocol", "*").strip() or "*"
    action = request.form.get("action", "BLOCK").strip().upper()

    if not name:
        flash("Rule name is required.", "danger")
        return redirect(url_for("rules"))

    try:
        port = int(port)
    except ValueError:
        port = 0

    if action not in ("ALLOW", "BLOCK"):
        action = "BLOCK"

    conn = get_db()
    conn.execute(
        """INSERT INTO firewall_rules (name, src_ip, dst_ip, port, protocol, action)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (name, src_ip, dst_ip, port, protocol, action),
    )
    conn.commit()
    conn.close()

    flash(f"Rule '{name}' added successfully.", "success")
    return redirect(url_for("rules"))


@app.route("/rules/delete/<int:rule_id>", methods=["POST"])
def delete_rule(rule_id):
    conn = get_db()
    conn.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    flash("Rule deleted.", "success")
    return redirect(url_for("rules"))


@app.route("/alerts")
def alerts():
    conn = get_db()
    all_alerts = conn.execute(
        "SELECT * FROM security_alerts ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return render_template("alerts.html", alerts=all_alerts)


@app.route("/clear_logs", methods=["POST"])
def clear_logs():
    conn = get_db()
    conn.execute("DELETE FROM traffic_logs")
    conn.execute("DELETE FROM security_alerts")
    conn.commit()
    conn.close()
    flash("All traffic logs and alerts have been cleared.", "success")
    return redirect(url_for("dashboard"))


@app.route("/api/stats")
def api_stats():
    """Simple JSON endpoint for live stats (optional use)."""
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
    allowed = conn.execute("SELECT COUNT(*) FROM traffic_logs WHERE action = 'ALLOW'").fetchone()[0]
    blocked = conn.execute("SELECT COUNT(*) FROM traffic_logs WHERE action = 'BLOCK'").fetchone()[0]
    alerts_count = conn.execute("SELECT COUNT(*) FROM security_alerts").fetchone()[0]
    conn.close()
    return jsonify({
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "alerts": alerts_count,
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("  Network Security and Firewall Monitoring System")
    print("  Running at http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
