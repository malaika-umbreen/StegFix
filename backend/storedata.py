# ============================================================
# new_endpoints.py
# Add these endpoints to your existing FastAPI main.py
# Uses new tables: detection_logs + alerts
# NO changes to flows, users, login_logs tables
# ============================================================

import mysql.connector
from fastapi import FastAPI

app = FastAPI()

# ---- DB Connection ----
db = mysql.connector.connect(
    host="localhost",
    user="root",          # your MySQL username
    password="12345",          # your MySQL password
    database="result"
)
cursor = db.cursor(dictionary=True)


# ============================================================
# ENDPOINT 1: /logs
# Used by: Logs.tsx
# Returns: all detection logs with technique, risk, confidence, status
# ============================================================

@app.get("/logs")
def get_logs():
    cursor.execute("""
        SELECT 
            id,
            timestamp,
            source,
            dest,
            protocol,
            technique,
            risk,
            confidence,
            status
        FROM detection_logs
        ORDER BY timestamp DESC
    """)
    return cursor.fetchall()


# ============================================================
# ENDPOINT 2: /dashboard
# Used by: Dashboard.tsx
# Returns: stats, protocols, techniques, recent detections, alerts
# ============================================================

@app.get("/dashboard")
def get_dashboard():

    # --- Stats: total, covert, normal ---
    cursor.execute("""
        SELECT
            COUNT(*)                                      AS total,
            SUM(status = 'covert')                        AS covert,
            SUM(status = 'normal')                        AS normal
        FROM detection_logs
    """)
    stats_row = cursor.fetchone()
    stats = {
        "total":  int(stats_row["total"]  or 0),
        "covert": int(stats_row["covert"] or 0),
        "normal": int(stats_row["normal"] or 0),
    }

    # --- Protocol counts (for bar chart) ---
    cursor.execute("""
        SELECT protocol, COUNT(*) AS count
        FROM detection_logs
        GROUP BY protocol
    """)
    protocol_rows = cursor.fetchall()
    protocols = {row["protocol"]: row["count"] for row in protocol_rows}

    # --- Technique counts (for doughnut chart) ---
    cursor.execute("""
        SELECT technique, COUNT(*) AS count
        FROM detection_logs
        WHERE status != 'normal'
        GROUP BY technique
    """)
    technique_rows = cursor.fetchall()
    techniques = {row["technique"]: row["count"] for row in technique_rows}

    # --- Recent detections (for dashboard table) ---
    cursor.execute("""
        SELECT 
            id,
            timestamp,
            source,
            dest,
            protocol,
            technique,
            risk,
            status
        FROM detection_logs
        ORDER BY timestamp DESC
        LIMIT 10
    """)
    recent = cursor.fetchall()

    # --- Alerts (for live alerts section) ---
    cursor.execute("""
        SELECT id, message, time, severity
        FROM alerts
        ORDER BY time DESC
        LIMIT 10
    """)
    alerts = cursor.fetchall()

    return {
        "stats":     stats,
        "protocols": protocols,
        "techniques": techniques,
        "recent":    recent,
        "alerts":    alerts,
    }