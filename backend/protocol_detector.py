def detect_protocol(flow):

    proto = int(flow["protocol"])
    src_port = int(flow["src_port"])
    dst_port = int(flow["dst_port"])

    # -----------------------------
    # ICMP (no ports)
    # -----------------------------
    if proto == 1:
        return "ICMP"

    # -----------------------------
    # TCP
    # -----------------------------
    elif proto == 6:
        return "TCP"

    # -----------------------------
    # UDP / DNS
    # -----------------------------
    elif proto == 17:

        # DNS detection (VERY IMPORTANT)
        if src_port == 53 or dst_port == 53:
            return "DNS"

        return "UDP"

    # -----------------------------
    # Other protocols
    # -----------------------------
    return "OTHER"