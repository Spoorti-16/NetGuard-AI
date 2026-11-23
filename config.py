import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "ids.db")
CAPTURE_DIR = os.path.join(BASE_DIR, "captures")
MODEL_DIR = os.path.join(BASE_DIR, "models")
NSL_DIR = os.path.join(MODEL_DIR, "nsl")
LAB_API = "http://127.0.0.1:9000"      # lab_controller.py control API
SERVER_IP = "10.0.0.3"                 # protected server inside Mininet

DEFAULT_SETTINGS = {
    "iface": "s1-eth3",                # switch port facing the server
    "window": "5",                     # seconds per analysis window
    "auto_block": "1",                 # 1 = block attackers automatically (active defense enabled)
    "block_conf": "0.7",               # min confidence for auto-block
    "block_ttl_min": "10",             # auto-expire blocks (0 = never)
    "whitelist": "10.0.0.2,10.0.0.3,10.0.0.4,127.0.0.1",
    "payload_preview": "0",             # 1 = store a short payload preview (participants must consent)
    "normal_max": "50000",             # stop adding to normal_connections.csv / traffic_dataset.csv after this many rows
    "sched_algo": "fcfs",               # fcfs | round_robin | priority - how the admin's inbound-request queue is served
    "auto_train": "0",                  # 1 = retrain automatically once enough new rows have accumulated
    "retrain_every": "40",              # new rows needed (normal or flows) before an automatic retrain
    "last_train_rows_normal": "0",      # bookkeeping for auto_train (do not edit)
    "last_train_rows_flows": "0",       # bookkeeping for auto_train (do not edit)
}


def secret_key():
    p = os.path.join(BASE_DIR, "instance", "secret.key")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    if not os.path.exists(p):
        with open(p, "w") as fh:
            fh.write(secrets.token_hex(32))
    return open(p).read().strip()
