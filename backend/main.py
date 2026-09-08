from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import get_flows, get_flows_by_protocol
from packet_capture import start_capture, stop_capture
from database import get_flows
import json
app = FastAPI()

# -----------------------------
# Allow React Frontend Requests
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # later change to ["http://localhost:5173"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Start Packet Capture
# -----------------------------
@app.post("/start_capture")
def start():
    start_capture()
    return {"status": "capture started"}

# -----------------------------
# Stop Packet Capture
# -----------------------------
@app.post("/stop_capture")
def stop():
    stop_capture()
    return {"status": "capture stopped"}

# -----------------------------
# Get Captured Flows
# -----------------------------
@app.get("/flows")
def flows():
    return get_flows()


# -----------------------------
# Convert Labels → Frontend Format
# -----------------------------
# -----------------------------
# Convert Labels → Frontend Format  (FIXED)
# -----------------------------
def map_labels(flow):

    status = "covert" if flow["binary_label"] == 1 else "normal"

    technique_map = {
        0: "None",
        1: "Header Manipulation",
        2: "Time Obfuscation",
        3: "Flow Blending"
    }
    technique = technique_map.get(flow["technique_label"], "Unknown")

    raw = flow.get("anomaly_score")
    anomaly = float(raw) if raw is not None else None

    # ─── CONFIDENCE ───────────────────────────────────────────
    if flow["binary_label"] == 1:
        # Covert: if we have a real anomaly score, use it;
        # otherwise fall back to a fixed high confidence (85%)
        if anomaly is not None:
            confidence = int(100 * (0.7 * anomaly + 0.3))
        else:
            confidence = 85   # model said covert → high confidence
    else:
        # Normal: if we have a real anomaly score, use it;
        # otherwise fall back to a fixed moderate confidence (75%)
        if anomaly is not None:
            confidence = int(100 * (0.7 * (1.0 - anomaly) + 0.3))
        else:
            confidence = 75   # model said normal → moderate confidence

    confidence = max(0, min(100, confidence))

    # ─── RISK ─────────────────────────────────────────────────
    # Risk must reflect the binary_label first, anomaly_score second
    if flow["binary_label"] == 1:
        # Covert traffic is always at least medium risk
        if anomaly is not None and anomaly >= 0.7:
            risk = "high"
        else:
            risk = "high"   # covert = high risk regardless
    else:
        # Normal traffic: use anomaly score if available
        if anomaly is not None:
            if anomaly >= 0.7:
                risk = "medium"   # normal label but anomaly looks suspicious
            elif anomaly >= 0.4:
                risk = "low"
            else:
                risk = "low"
        else:
            risk = "low"

    return status, technique, risk, confidence


# -----------------------------
# Logs API
# -----------------------------
@app.get("/logs")
def get_logs():
    flows = get_flows()

    logs = []

    for flow in flows:
        status, technique, risk, confidence = map_labels(flow)

        logs.append({
            "id": flow["id"],
            "timestamp": str(flow["timestamp"]),
            "source": flow["src_ip"],
            "dest": flow["dst_ip"],
            "protocol": flow["protocol"],
            "technique": technique,
            "status": status,
            "risk": risk,
            "confidence": confidence
        })

    return logs

# -----------------------------
# Dashboard Data API
# -----------------------------
@app.get("/dashboard")
def dashboard_data():
    flows = get_flows()

    total_flows = len(flows)
    covert = sum(1 for f in flows if f["binary_label"] == 1)
    normal = total_flows - covert

    protocol_count = {}
    technique_count = {}
    alerts = []
    recent = []

    # ✅ MOVE OUTSIDE LOOP (IMPORTANT)
    protocol_map = {
        6: "TCP",
        17: "UDP",
        1: "ICMP",
        53: "DNS"
    }

    technique_map = {
        0: "None",
        1: "Header Manipulation",
        2: "Time Obfuscation",
        3: "Flow Blending"
    }

    for f in flows:

        # ✅ Convert protocol number → name
        proto_name = protocol_map.get(f["protocol"], str(f["protocol"]))

        # -----------------------------
        # Protocol stats (FIXED)
        # -----------------------------
        protocol_count[proto_name] = protocol_count.get(proto_name, 0) + 1

        # -----------------------------
        # Technique stats
        # -----------------------------
        tech = technique_map.get(f["technique_label"], "Unknown")
        technique_count[tech] = technique_count.get(tech, 0) + 1

        # -----------------------------
        # Recent detections (FIXED)
        # -----------------------------
        recent.append({
            "id": f["id"],
            "timestamp": str(f["timestamp"]),
            "source": f["src_ip"],
            "dest": f["dst_ip"],
            "protocol": proto_name,  # ✅ FIXED
            "technique": tech,
            "risk": "High" if f["binary_label"] == 1 else "Low",
            "status": "Covert" if f["binary_label"] == 1 else "Normal"
        })

        # -----------------------------
        # Alerts
        # -----------------------------
        if f["binary_label"] == 1:
            alerts.append({
                "id": f["id"],
                "message": f"Covert channel detected from {f['src_ip']}",
                "time": "just now",
                "severity": "high"
            })

    return {
        "stats": {
            "total": total_flows,
            "covert": covert,
            "normal": normal
        },
        "protocols": protocol_count,   # ✅ now returns TCP/UDP/ICMP/DNS
        "techniques": technique_count,
        "recent": recent[:5],
        "alerts": alerts[:5]
    }



# -----------------------------
# Protocol Analysis API
# -----------------------------
@app.get("/protocol-analysis")
def protocol_analysis():
    flows = get_flows()

    protocol_map = {
        6: "TCP",
        17: "UDP",
        1: "ICMP",
        53: "DNS"
    }

    # Initialize
    protocol_stats = {
        "TCP": {"total": 0, "covert": 0},
        "UDP": {"total": 0, "covert": 0},
        "ICMP": {"total": 0, "covert": 0},
        "DNS": {"total": 0, "covert": 0},
    }

    # Time buckets
    time_buckets = {}

    # ✅ LOOP START
    for f in flows:

        # ✅ Normalize protocol
        proto_raw = f["protocol"]

        if isinstance(proto_raw, int):
            proto = protocol_map.get(proto_raw, "OTHER")
        else:
            proto = str(proto_raw).strip().upper()

        print("Detected Protocol:", proto)  # debug

        if proto not in protocol_stats:
            continue

        # Count total
        protocol_stats[proto]["total"] += 1

        # Count covert
        if f["binary_label"] == 1:
            protocol_stats[proto]["covert"] += 1

        # Time grouping
        hour = f["timestamp"].strftime("%H:%M")

        if hour not in time_buckets:
            time_buckets[hour] = {
                "TCP": 0,
                "UDP": 0,
                "ICMP": 0,
                "DNS": 0
            }

        time_buckets[hour][proto] += 1

    # ✅ RETURN OUTSIDE LOOP
    return {
        "protocol_stats": protocol_stats,
        "timeline": time_buckets
    }


# -----------------------------
# Flow Details API (FIXED)
# -----------------------------
@app.get("/flow-details")
def flow_details(protocol: str):

    flows = get_flows()

    normal_values = {}
    covert_values = {}

    normal_count = 0
    covert_count = 0

    for f in flows:
        proto = str(f["protocol"]).upper()

        # ✅ Filter by selected protocol
        if proto != protocol.upper():
            continue

        # ✅ Load feature JSON safely
        try:
            features = json.loads(f["features"])
        except:
            continue

        binary = f["binary_label"]

        # -----------------------------
        # NORMAL TRAFFIC
        # -----------------------------
        if binary == 0:
            normal_count += 1
            for k, v in features.items():
                try:
                    normal_values[k] = normal_values.get(k, 0) + float(v)
                except:
                    continue

        # -----------------------------
        # COVERT TRAFFIC (ALL TYPES MERGED)
        # -----------------------------
        else:
            covert_count += 1
            for k, v in features.items():
                try:
                    covert_values[k] = covert_values.get(k, 0) + float(v)
                except:
                    continue

    # -----------------------------
    # AVERAGE FUNCTION
    # -----------------------------
    def avg(data, count):
        return {k: (v / count) if count > 0 else 0 for k, v in data.items()}

    # -----------------------------
    # FINAL RESPONSE (MATCHES FRONTEND)
    # -----------------------------
    return {
        "normal": avg(normal_values, normal_count),
        "covert": avg(covert_values, covert_count)
    }




# -----------------------------
# Technique Analysis API (NEW)
# -----------------------------
@app.get("/technique-analysis")
def technique_analysis(protocol: str):

    flows = get_flows()
    flows = get_flows_by_protocol(protocol)
    normal_values = {}
    header_values = {}
    flow_values = {}
    time_values = {}

    normal_count = 0
    header_count = 0
    flow_count = 0
    time_count = 0

    for f in flows:
        proto = str(f["protocol"]).upper()

        # ✅ Filter by protocol
        if proto != protocol.upper():
            continue

        # ✅ Load features
        try:
            features = json.loads(f["features"])
        except:
            continue

        binary = f["binary_label"]
        technique = f["technique_label"]

        # -----------------------------
        # NORMAL TRAFFIC
        # -----------------------------
        if binary == 0:
            normal_count += 1
            for k, v in features.items():
                try:
                    normal_values[k] = normal_values.get(k, 0) + float(v)
                except:
                    continue

        # -----------------------------
        # COVERT TRAFFIC BY TECHNIQUE
        # -----------------------------
        else:
            if technique == 1:   # Header Manipulation
                header_count += 1
                for k, v in features.items():
                    try:
                        header_values[k] = header_values.get(k, 0) + float(v)
                    except:
                        continue

            elif technique == 3: # Flow Blending
                flow_count += 1
                for k, v in features.items():
                    try:
                        flow_values[k] = flow_values.get(k, 0) + float(v)
                    except:
                        continue

            elif technique == 2: # Time Obfuscation
                time_count += 1
                for k, v in features.items():
                    try:
                        time_values[k] = time_values.get(k, 0) + float(v)
                    except:
                        continue

    # -----------------------------
    # AVERAGE FUNCTION
    # -----------------------------
    def avg(data, count):
        return {k: (v / count) if count > 0 else 0 for k, v in data.items()}

    # -----------------------------
    # RESPONSE (MATCHES FRONTEND)
    # -----------------------------
    return {
    "normal": avg(normal_values, normal_count),
    "header": avg(header_values, header_count),
    "flow": avg(flow_values, flow_count),
    "time": avg(time_values, time_count),

    # ✅ ADD THIS
    "counts": {
        "normal": normal_count,
        "header": header_count,
        "flow": flow_count,
        "time": time_count
    }
}