# -----------------------------
# Database configuration
# -----------------------------

DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = "12345"
DB_NAME = "stego_detection"


# -----------------------------
# Packet capture configuration
# -----------------------------

NETWORK_INTERFACES = [
    r"\Device\NPF_{356C7764-025B-40DA-9D48-D133D7549256}",  # WiFi
    r"\Device\NPF_{A51EB10E-7852-4663-9387-63A14897CBEA}"   # VMware
]


# -----------------------------
# Flow generation settings
# -----------------------------

FLOW_TIMEOUT = 15
#MIN_PACKETS_PER_FLOW = 20


# -----------------------------
# AI Model configuration
# -----------------------------

MODEL_PATH = "model/steganography_transformer_model.pth"
FEATURE_LIST_PATH = "model/feature_list.json"


# -----------------------------
# API configuration
# -----------------------------

API_HOST = "127.0.0.1"
API_PORT = 8000