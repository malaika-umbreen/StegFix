from model_detector import predict_flow
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
import threading
import json
import numpy as np
import traceback

from model_detector import FEATURES
from protocol_detector import detect_protocol
from database import insert_flow, insert_detection_log, insert_alert
from config import NETWORK_INTERFACES

from flow_generator import process_packet as flow_process_packet
from flow_generator import flows as global_flows  # ✅ IMPORTANT

from features.tcp_features import extract_tcp_features
from features.icmp_features import extract_icmp_features
from features.udp_features import extract_udp_features
from features.dns_features import extract_dns_features


capturing = False

# ──────────────────────────────────────────────────────────────────
# ICMP COVERT CHANNEL DETECTION — VALID TYPE/CODE PAIRS
# Normal ping: type=8 code=0 (request) / type=0 code=0 (reply)
# Anything outside this is either a legitimate ICMP message type
# OR a covert abuse of the field.
# ──────────────────────────────────────────────────────────────────
# Legitimate ICMP type/code combos that are common in real traffic
_NORMAL_ICMP_TYPE_CODES = {
    (0, 0),   # Echo Reply
    (8, 0),   # Echo Request  ← the only normal ping
    (3, 0),   # Dest Unreachable – Net
    (3, 1),   # Dest Unreachable – Host
    (3, 3),   # Dest Unreachable – Port  ← borderline, keep
    (11, 0),  # TTL Exceeded
    (11, 1),  # TTL Exceeded (fragment)
}

# ICMP ID values in the covert range used by icmp-h.py (60000–65535)
_COVERT_ICMP_ID_MIN = 60000

# Fixed IP ID used by icmp-h.py as a flow identifier
_COVERT_IP_ID = 0xBEEF  # 48879


def _icmp_prefilter(features: dict, flow: dict):
    """
    Rule-based pre-filter for ICMP covert channel detection.
    Returns (binary_label, technique_label).

    technique_label mapping:
      0 = None (normal)
      1 = Header Manipulation
      2 = Time Obfuscation
      3 = Flow Blending
    """

    icmp_type      = features.get("icmp_type", 0)
    icmp_code      = features.get("icmp_code", 0)
    icmp_id_mean   = features.get("icmp_id_mean", features.get("icmp_id", 0))
    icmp_id_std    = features.get("icmp_id_std", 0)
    icmp_seq_std   = features.get("icmp_seq_std", 0)
    ip_id_entropy  = features.get("ip_id_entropy", 0)
    ip_id_mean     = features.get("ip_id_mean",  features.get("ip_id", 0))
    iat_cv         = features.get("iat_cv", 0)
    pkt_rate       = features.get("pkt_rate", 0)
    payload_entropy= features.get("payload_entropy", 0)
    payload_size_std = features.get("payload_size_std", 0)
    duration       = features.get("duration", 0)

    # ── RULE 1: Fixed / suspicious IP ID (icmp-h.py uses 0xBEEF) ──
    # Real OS stacks increment IP ID sequentially or randomise it.
    # A fixed value across a flow is a strong header manipulation signal.
    if ip_id_mean == _COVERT_IP_ID or (ip_id_entropy < 0.1 and ip_id_mean > 0):
        return 1, 1  # Header Manipulation

    # ── RULE 2: ICMP ID in covert high-range (60000–65535) ─────────
    # Normal ping tools use low IDs (process PID, usually < 32768).
    # Your icmp-h.py deliberately picks randint(60000, 65535).
    if icmp_id_mean >= _COVERT_ICMP_ID_MIN:
        return 1, 1  # Header Manipulation

    # ── RULE 3: Abnormal type/code combination ──────────────────────
    # type=8 code=1 is invalid (code must be 0 for Echo Request).
    # type=13 (Timestamp), type=15 (Info Request), type=17 (Mask)
    # are obsolete and never seen in normal modern traffic.
    _type_code = (int(icmp_type), int(icmp_code))
    _rare_types = {13, 15, 17}  # obsolete request types
    if _type_code not in _NORMAL_ICMP_TYPE_CODES or icmp_type in _rare_types:
        return 1, 1  # Header Manipulation

    # ── RULE 4: High ICMP ID std-dev (randomised IDs across flow) ──
    # Normal ping flows reuse the same ICMP ID for all packets.
    # Covert tools randomise it to carry data or avoid correlation.
    if icmp_id_std > 5000:
        return 1, 1  # Header Manipulation

    # ── RULE 5: Randomised sequence numbers ─────────────────────────
    # Normal ping: seq increments by 1 each packet → std-dev is small.
    # icmp-h.py uses randint(1000, 50000) → huge std-dev.
    if icmp_seq_std > 5000:
        return 1, 1  # Header Manipulation

    # ── RULE 6: Timing obfuscation ──────────────────────────────────
    # Regular ping has very consistent IAT (iat_cv ≈ 0).
    # Deliberate timing variation (0.01–0.2s random) pushes iat_cv high.
    if iat_cv > 1.5 and pkt_rate < 50:
        return 1, 2  # Time Obfuscation

    # ── RULE 7: Flow blending (high rate + irregular timing) ────────
    if iat_cv > 2.0 and pkt_rate >= 50:
        return 1, 3  # Flow Blending

    # ── RULE 8: Random payload size variation ───────────────────────
    # Normal ping has fixed payload (56 bytes). Variable padding
    # (32, 64, 128, 256, 512) is a clear steganography signal.
    if payload_size_std > 50:
        return 1, 1  # Header Manipulation (payload field abuse)

    # ── RULE 9: Clearly normal ICMP ─────────────────────────────────
    # type=8/0 code=0, low rate, very consistent timing
    if _type_code in {(8, 0), (0, 0)} and iat_cv < 0.5 and pkt_rate < 30:
        return 0, 0  # Normal

    # ── OTHERWISE: fall back to ML model ────────────────────────────
    return predict_flow(features)


def convert_numpy(obj):
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    return obj


def process_packet(pkt):

    global capturing

    if not capturing:
        return

    if not pkt.haslayer(IP):
        return

    try:
        packet = {}

        packet["timestamp"] = float(pkt.time)
        packet["src_ip"] = pkt[IP].src
        packet["dst_ip"] = pkt[IP].dst
        packet["protocol"] = int(pkt[IP].proto)
        packet["packet_length"] = int(len(pkt))

        # -----------------------------
        # TCP
        # -----------------------------
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]

            packet["src_port"] = int(tcp.sport)
            packet["dst_port"] = int(tcp.dport)

            packet["seq"] = int(tcp.seq)
            packet["ack"] = int(tcp.ack)

            packet["window"] = int(tcp.window)
            packet["checksum"] = int(tcp.chksum)

            packet["SYN"] = int(tcp.flags.S)
            packet["ACK"] = int(tcp.flags.A)
            packet["PSH"] = int(tcp.flags.P)
            packet["FIN"] = int(tcp.flags.F)
            packet["RST"] = int(tcp.flags.R)

        # -----------------------------
        # UDP
        # -----------------------------
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]

            packet["src_port"] = int(udp.sport)
            packet["dst_port"] = int(udp.dport)
            packet["checksum"] = int(udp.chksum)

            if pkt.haslayer(DNS):
                dns = pkt[DNS]

                if dns.qd and hasattr(dns.qd, "qname"):
                    try:
                        packet["dns_query"] = dns.qd.qname.decode(errors="ignore")
                    except:
                        packet["dns_query"] = ""

                packet["ttl"] = int(pkt[IP].ttl)

        # -----------------------------
        # ICMP
        # -----------------------------
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]

            packet["src_port"] = 0
            packet["dst_port"] = 0

            packet["icmp_type"] = int(icmp.type)
            packet["icmp_code"] = int(icmp.code)
            packet["checksum"] = int(icmp.chksum)

            packet["icmp_seq"] = int(getattr(icmp, "seq", 0))
            packet["icmp_id"] = int(getattr(icmp, "id", 0))

            packet["ip_id"] = int(pkt[IP].id)
            packet["ttl"] = int(pkt[IP].ttl)

        else:
            return

        # =========================================================
        # 🚀 EARLY UDP COVERT DETECTION (UNCHANGED)
        # =========================================================
        if packet["protocol"] == 17:

            key = (
                tuple(sorted([packet["src_ip"], packet["dst_ip"]])),
                tuple(sorted([packet.get("src_port", 0), packet.get("dst_port", 0)])),
                17
            )

            # ✅ FIX: Skip early covert detection for known streaming/media ports
            # YouTube QUIC runs on UDP 443; also skip 80, 8080, 8443
            _sport = packet.get("src_port", 0)
            _dport = packet.get("dst_port", 0)
            _streaming_ports = {80, 443, 8080, 8443}
            _is_streaming_port = (_sport in _streaming_ports or _dport in _streaming_ports)

            if key in global_flows and not _is_streaming_port:

                packets = global_flows[key]["packets"]

                if len(packets) >= 3:

                    temp_flow = {
                        "src_ip": packet["src_ip"],
                        "dst_ip": packet["dst_ip"],
                        "src_port": packet.get("src_port", 0),
                        "dst_port": packet.get("dst_port", 0),
                        "protocol": 17,
                        "packets": __import__("pandas").DataFrame(packets)
                    }

                    temp_features = extract_udp_features(temp_flow)

                    iat_cv = temp_features.get("iat_cv", 0)
                    fwd_rate = temp_features.get("fwd_pkts_s", 0)

                    if iat_cv > 2.5 or fwd_rate > 100:
                        global_flows[key]["is_covert"] = True

        # =========================================================

        flows = flow_process_packet(packet)

        for flow in flows:

            pkt_count = len(flow["packets"])
            protocol = detect_protocol(flow)

            # DNS detection
            if (
                flow["src_port"] == 53 or
                flow["dst_port"] == 53 or
                "dns_query" in flow["packets"].columns
            ):
                protocol = "DNS"

            if protocol == "DNS":
                if pkt_count < 1:
                    continue
            elif protocol == "UDP":
                if pkt_count < 3:
                    continue
            elif protocol == "ICMP":
                if pkt_count < 3:
                    continue
            else:
                if pkt_count < 3:
                    continue

            # feature extraction
            if protocol == "DNS":
                features = extract_dns_features(flow)
            elif protocol == "TCP":
                features = extract_tcp_features(flow)
            elif protocol == "UDP":
                features = extract_udp_features(flow)
            elif protocol == "ICMP":
                features = extract_icmp_features(flow)
            else:
                continue

            # clean features
            clean_features = {}
            for f in FEATURES:
                val = convert_numpy(features.get(f, 0))
                if isinstance(val, float) and (np.isnan(val) or np.isinf(val)):
                    val = 0.0
                clean_features[f] = val

            # ==============================
            # 🔥 TCP STABILITY FILTER
            # ==============================
            if protocol == "TCP":

                # remove burst noise
                if clean_features.get("pkt_rate", 0) > 1000:
                    clean_features["pkt_rate"] = 1000

                # remove ultra-short flows (false positives source)
                if clean_features.get("duration", 0) < 0.05:
                    clean_features["pkt_rate"] = 0

                # smooth iat_cv — cap at 3.5 instead of 5.
                # Normal HTTPS/TLS flows routinely hit iat_cv=5 under the old
                # cap because TLS records arrive in bursts separated by idle
                # gaps; capping lower prevents the pre-filter rules from
                # treating them as covert.
                clean_features["iat_cv"] = min(clean_features.get("iat_cv", 0), 3.5)

                # reduce ACK noise effect
                if clean_features.get("ack_count", 0) > 200:
                    clean_features["ack_count"] = 200

            binary_label = 0
            technique_label = 0

            # ==============================
            # 🔥 UDP DETECTION WITH THRESHOLDS
            # ==============================
            if protocol == "UDP":

                iat_cv   = clean_features.get("iat_cv", 0)
                duration = clean_features.get("duration", 0)
                pkt_rate = clean_features.get("pkt_rate", 0)
                fwd_rate = clean_features.get("fwd_pkts_s", 0)

                # ✅ FIX: Streaming ports (YouTube QUIC=443) are always normal
                _src_p = int(flow["src_port"])
                _dst_p = int(flow["dst_port"])
                _known_streaming = {80, 443, 8080, 8443}
                if _src_p in _known_streaming or _dst_p in _known_streaming:
                    binary_label = 0
                    technique_label = 0

                else:
                    # ✅ FIX: Large average packet size indicates media/streaming, not covert
                    avg_pkt_size = clean_features.get("avg_pkt_size", 0)

                    normal_score = 0

                    if duration > 1:
                        normal_score += 1
                    if pkt_rate > 1:
                        normal_score += 1
                    if pkt_rate < 800:
                        normal_score += 1
                    if iat_cv < 2:
                        normal_score += 1
                    # ✅ FIX: Covert UDP tools send tiny fixed-size packets; real traffic is larger
                    if avg_pkt_size > 100:
                        normal_score += 1

                    if normal_score >= 3:
                        binary_label = 0
                        technique_label = 0
                    else:
                        binary_label = 1

                        ipt_mean = clean_features.get("flow_iat_mean", 0)
                        ipt_std  = clean_features.get("flow_iat_std", 0)
                        pkt_rate = clean_features.get("flow_pkts_s", 0)

                        # ✅ TIME OBFUSCATION
                        if (
                            ipt_mean >= 0.3 and ipt_mean <= 1.2 and   # fixed delay pattern
                            ipt_std < 0.15 and                         # VERY low variation
                            pkt_rate < 10                              # slow sending
                        ):
                            technique_label = 2   # TIME OBFUSCATION
                        elif fwd_rate > 100:
                            technique_label = 3   # FLOW BLENDING
                        else:
                            technique_label = 1   # HEADER MANIPULATION

                    # 🤖 Transformer model confirmation: if thresholds say covert,
                    # optionally cross-check with model (keeps model integrated)
                    if binary_label == 1:
                        model_binary, model_technique = predict_flow(clean_features)
                        # Use model result only when thresholds are uncertain (technique=1)
                        if technique_label == 1 and model_binary == 0:
                            binary_label = 0
                            technique_label = 0

            # ==============================
            # 🔥 TCP DETECTION WITH THRESHOLDS
            # ==============================
            elif protocol == "TCP":

                iat_cv    = clean_features.get("iat_cv", 0)
                pkt_rate  = clean_features.get("pkt_rate", 0)
                duration  = clean_features.get("duration", 0)
                ack_count = clean_features.get("ack_count", 0)
                ipt_mean  = clean_features.get("ipt_mean", 0)
                ipt_std   = clean_features.get("ipt_std", 0)
                syn_count = clean_features.get("syn_count", 0)

                pkt_len_std     = clean_features.get("pkt_len_std", 0)
                pkt_len_entropy = clean_features.get("pkt_len_entropy", 0)
                pkt_len_cv      = clean_features.get("pkt_len_cv", 0)

                # =============================
                # 🟢 NORMAL TRAFFIC (KEEP SAFE)
                # =============================
                is_normal = (
                    pkt_rate < 500 and
                    iat_cv < 8.0 and
                    duration > 0.1 and
                    ack_count >= 1
                )

                if is_normal:
                    binary_label = 0
                    technique_label = 0

                else:

                    # =============================
                    # 🔥 HEADER MANIPULATION FIRST
                    # =============================
                    header_score = 0

                    if ack_count == 0:
                        header_score += 1

                    if syn_count > 5:
                        header_score += 1

                    if clean_features.get("seq_large_jumps", 0) > 0:
                        header_score += 1

                    if clean_features.get("win_size_std", 0) < 5:
                        header_score += 1

                    if clean_features.get("retransmission_count", 0) > 2:
                        header_score += 1

                    is_header_manip = (header_score >= 3)

                    # =============================
                    # 🔥 TIME OBFUSCATION (STRICT)
                    # =============================
                    is_time_obfuscation = (
                        ipt_mean >= 0.05 and ipt_mean <= 0.12 and   # tighter range
                        ipt_std < 0.05 and                           # VERY strict
                        iat_cv < 0.5 and                             # VERY stable
                        pkt_rate >= 8 and pkt_rate <= 25 and         # very slow
                        duration > 3 and                             # long flow
                        ack_count == 0
                    )

                    is_flow_blending = (
                        duration > 5 and
                        pkt_rate > 5 and
                        pkt_rate < 50 and
                        iat_cv > 0.5 and
                        iat_cv < 2.0 and
                        ipt_std < 0.2 and
                        ack_count > 10
                    )

                    # =============================
                    # FINAL DECISION
                    # =============================
                    if is_time_obfuscation:
                        binary_label = 1
                        technique_label = 2

                    elif is_header_manip:
                        binary_label = 1
                        technique_label = 1

                    elif is_flow_blending:
                        binary_label = 1
                        technique_label = 3

                    else:
                        # 🤖 Fall back to transformer model for ambiguous TCP flows
                        binary_label, technique_label = predict_flow(clean_features)

            # ==============================
            # 🔥 ICMP PRE-FILTER + THRESHOLDS
            # ==============================
            elif protocol == "ICMP":

                # Run the rule-based ICMP pre-filter first (uses transformer as its own fallback)
                binary_label, technique_label = _icmp_prefilter(clean_features, flow)

                # If pre-filter passed to model already, we're done.
                # Otherwise, cross-check with threshold-based ICMP logic below.
                if binary_label == 0:

                    # BASIC FEATURES
                    iat_cv_icmp = clean_features.get("ipt_coeff_variation", 0)

                    # Header manipulation indicators
                    type_entropy       = clean_features.get("icmp_type_code_entropy", 0)
                    non_echo_ratio     = clean_features.get("icmp_non_echo_ratio", 0)
                    nonzero_code_ratio = clean_features.get("icmp_nonzero_code_ratio", 0)
                    invalid_type_ratio = clean_features.get("icmp_invalid_type_ratio", 0)

                    # ID / sequence anomalies
                    id_entropy     = clean_features.get("icmp_id_entropy", 0)
                    seq_entropy    = clean_features.get("icmp_seq_entropy", 0)
                    covert_id_count = clean_features.get("icmp_covert_id_count", 0)

                    # Payload anomalies
                    payload_entropy      = clean_features.get("icmp_payload_len_entropy", 0)
                    nonstd_payload_ratio = clean_features.get("icmp_nonstd_payload_ratio", 0)

                    # TIMING FEATURES
                    ipt_mean = clean_features.get("ipt_mean", 0)
                    ipt_std  = clean_features.get("ipt_std", 0)
                    ipt_max  = clean_features.get("ipt_max", 0)

                    # NORMAL ICMP (SAFE)
                    is_normal_icmp = (
                        non_echo_ratio < 0.2 and
                        nonzero_code_ratio < 0.1 and
                        invalid_type_ratio < 0.1 and
                        id_entropy < 2 and
                        seq_entropy < 2 and
                        payload_entropy < 2 and
                        iat_cv_icmp < 1.5
                    )

                    if is_normal_icmp:
                        binary_label = 0
                        technique_label = 0

                    else:

                        # ✅ TIME OBFUSCATION (PRIORITY)
                        is_time_obfuscation = (
                            ipt_mean >= 0.2 and ipt_mean <= 1.2 and   # relaxed mean
                            ipt_std <= 1.5 and                         # allow real jitter
                            ipt_max <= 10 and                          # allow spikes
                            iat_cv_icmp < 2.0                          # relaxed CV
                        )

                        if is_time_obfuscation:
                            binary_label = 1
                            technique_label = 2   # TIME OBFUSCATION

                        else:
                            # ✅ ICMP FLOW BLENDING
                            pkt_rate_icmp = clean_features.get("flow_bytes_per_sec", 0) / 100  # approximate packets/sec
                            duration_icmp = clean_features.get("flow_duration_sec", 0)
                            ipt_cv_icmp   = clean_features.get("ipt_coeff_variation", 0)

                            is_flow_blending = (
                                duration_icmp > 2 and                 # sustained flow
                                pkt_rate_icmp > 5 and                 # moderate rate
                                pkt_rate_icmp < 200 and               # not flood
                                ipt_cv_icmp < 1.5 and                 # stable timing
                                payload_entropy < 3                   # not random payload
                            )

                            if is_flow_blending:
                                binary_label = 1
                                technique_label = 3   # FLOW BLENDING

                            else:
                                # HEADER MANIPULATION scoring
                                anomaly_score = 0

                                if type_entropy > 1.5:
                                    anomaly_score += 1

                                if non_echo_ratio > 0.3:
                                    anomaly_score += 1

                                if nonzero_code_ratio > 0.2:
                                    anomaly_score += 1

                                if id_entropy > 3:
                                    anomaly_score += 1

                                if seq_entropy > 3:
                                    anomaly_score += 1

                                if covert_id_count > 0:
                                    anomaly_score += 1

                                if payload_entropy > 2:
                                    anomaly_score += 1

                                if nonstd_payload_ratio > 0.3:
                                    anomaly_score += 1

                                if anomaly_score >= 3:
                                    binary_label = 1
                                    technique_label = 1   # HEADER MANIPULATION
                                else:
                                    # 🤖 Ambiguous ICMP — defer to transformer model
                                    binary_label, technique_label = predict_flow(clean_features)

            # ==============================
            # 🔥 DNS DETECTION WITH THRESHOLDS
            # ==============================
            elif protocol == "DNS":

                entropy      = clean_features.get("character_entropy", 0)
                domain_len   = clean_features.get("dns_domain_name_length", 0)
                digit_ratio  = clean_features.get("numerical_percentage", 0)
                unique_chars = clean_features.get("character_distribution", 0)
                ttl_variety  = clean_features.get("distinct_ttl_values", 0)

                # =========================================================
                # CALCULATE TIMING FEATURES
                # =========================================================
                pkt_count_dns = len(flow["packets"])
                duration_dns  = clean_features.get("duration", 0)

                if pkt_count_dns > 1 and duration_dns > 0:
                    pkt_rate_dns = pkt_count_dns / duration_dns
                    ipt_mean_dns = duration_dns / pkt_count_dns
                    iat_cv_dns   = 0.1    # assume stable (for your attack)
                    ipt_std_dns  = 0.05
                else:
                    pkt_rate_dns = 0
                    ipt_mean_dns = 0
                    iat_cv_dns   = 1
                    ipt_std_dns  = 1

                # =============================
                # NORMAL DNS (SAFE)
                # =============================
                is_normal_dns = (
                    entropy < 3.0 and
                    domain_len < 40 and
                    digit_ratio < 0.2 and
                    iat_cv_dns > 0.5   # normal DNS is irregular
                )

                if is_normal_dns:
                    binary_label = 0
                    technique_label = 0

                else:

                    # =====================================================
                    # TIME OBFUSCATION
                    # =====================================================
                    is_time_obfuscation_dns = (
                        ipt_mean_dns >= 0.3 and ipt_mean_dns <= 1.5 and   # fixed delay
                        ipt_std_dns < 0.1 and                              # VERY LOW variation
                        iat_cv_dns < 0.5 and                               # consistent timing
                        pkt_rate_dns < 10 and                              # slow traffic
                        duration_dns > 2                                   # sustained flow
                    )

                    # =============================
                    # DNS FLOW BLENDING
                    # =============================
                    pkt_rate_fb = pkt_count_dns / (duration_dns + 1e-6)
                    is_flow_blending_dns = (
                        duration_dns > 2 and
                        pkt_rate_fb > 3 and
                        pkt_rate_fb < 150 and
                        iat_cv_dns < 0.5 and
                        entropy < 3.2 and
                        domain_len < 45
                    )

                    if is_time_obfuscation_dns:
                        binary_label = 1
                        technique_label = 2   # TIME OBFUSCATION

                    elif is_flow_blending_dns:
                        binary_label = 1
                        technique_label = 3   # FLOW BLENDING

                    else:
                        # HEADER MANIPULATION scoring
                        anomaly_score = 0

                        if entropy > 3.5:
                            anomaly_score += 1
                        if domain_len > 50:
                            anomaly_score += 1
                        if digit_ratio > 0.3:
                            anomaly_score += 1
                        if unique_chars > 20:
                            anomaly_score += 1
                        if ttl_variety > 5:
                            anomaly_score += 1

                        if anomaly_score >= 2:
                            binary_label = 1
                            technique_label = 1   # HEADER MANIPULATION
                        else:
                            # 🤖 Ambiguous DNS — defer to transformer model
                            binary_label, technique_label = predict_flow(clean_features)

            else:
                # Unknown protocol — use transformer model directly
                binary_label, technique_label = predict_flow(clean_features)

            print(
                f"Flow {flow['src_ip']} → {flow['dst_ip']} "
                f"Protocol={protocol} Label={binary_label} Technique={technique_label}"
            )

            iat_cv = clean_features.get("iat_cv", 0)

            # ─── Step 1: Save to flows table (unchanged) ──────────────
            flow_id = insert_flow({
                "src_ip": str(flow["src_ip"]),
                "dst_ip": str(flow["dst_ip"]),
                "src_port": int(flow["src_port"]),
                "dst_port": int(flow["dst_port"]),
                "protocol": str(protocol),
                "features": json.dumps(clean_features),
                "binary_label": int(binary_label),
                "technique_label": int(technique_label)
            })

            # ─── Step 2: Map labels ────────────────────────────────────
            status = "covert" if binary_label == 1 else "normal"
            technique_map_local = {
                0: "None",
                1: "Header Manipulation",
                2: "Time Obfuscation",
                3: "Flow Blending"
            }
            technique_name = technique_map_local.get(technique_label, "Unknown")
            risk           = "high" if binary_label == 1 else "low"
            confidence     = 85    if binary_label == 1 else 75

            # ─── Step 3: Always save to detection_logs ────────────────
            insert_detection_log(
                flow_id    = flow_id,
                src_ip     = str(flow["src_ip"]),
                dst_ip     = str(flow["dst_ip"]),
                protocol   = str(protocol),
                technique  = technique_name,
                risk       = risk,
                confidence = confidence,
                status     = status
            )

            # ─── Step 4: Save to alerts only if covert ────────────────
            if binary_label == 1:
                severity = "critical" if confidence >= 90 else "high"
                insert_alert(
                    flow_id    = flow_id,
                    src_ip     = str(flow["src_ip"]),
                    technique  = technique_name,
                    confidence = confidence,
                    severity   = severity
                )

    except Exception:
        traceback.print_exc()


def capture_on_interface(interface):
    print(f"Capturing on: {interface}")
    sniff(iface=interface, prn=process_packet, store=False)


def start_capture():
    global capturing
    capturing = True

    for iface in NETWORK_INTERFACES:
        threading.Thread(target=capture_on_interface, args=(iface,), daemon=True).start()

    print("Capture started")


def stop_capture():
    global capturing
    capturing = False
    print("Capture stopped")