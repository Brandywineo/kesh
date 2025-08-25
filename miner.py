import requests
import time
import hashlib
import os
import threading
import statistics
import sys
import json
import itertools
from datetime import datetime

"""
KESH Miner (XMRig-style feedback)
- Connects to a Kesh full node (acting as a pool) via /get_job and /submit_block
- Prints: new job received, accepted/rejected shares, threaded & rolling hashrate
- Supports local solo mining (node_url) and pool_mode (pool_url)
- Uses BLAKE2b-256 with leading-zero difficulty target
- Compatible fallback to /mine_block if /submit_block is not available
"""

# -----------------------------
# Configuration / CLI handling
# -----------------------------
DEFAULT_CONFIG = {
    "node_url": "http://127.0.0.1:5000",
    "wallet_address": "kes25defaultMiningAddress",
    "threads": max(1, os.cpu_count() or 1),
    "poll_interval": 2.0,         # seconds between job polls
    "request_timeout": 10.0,      # HTTP timeout
    "pool_mode": False,
    "pool_url": "http://127.0.0.1:8000",
    "difficulty_window": 30       # samples used for rolling average
}

CONFIG = DEFAULT_CONFIG.copy()

# Try config file if present
try:
    from miner_config import CONFIG as FILE_CONFIG
    CONFIG.update(FILE_CONFIG)
except Exception:
    pass

# Simple CLI: miner.py <wallet_address> <node_url> [--threads N] [--pool <url>]
args = sys.argv[1:]
if len(args) >= 2:
    CONFIG["wallet_address"] = args[0]
    CONFIG["node_url"] = args[1]
    if "--threads" in args:
        try:
            idx = args.index("--threads")
            CONFIG["threads"] = int(args[idx + 1])
        except Exception:
            pass
    if "--pool" in args:
        try:
            idx = args.index("--pool")
            CONFIG["pool_mode"] = True
            CONFIG["pool_url"] = args[idx + 1]
        except Exception:
            pass

# -----------------------------
# Pretty UI helpers
# -----------------------------
BANNER = """
███████╗███████╗███████╗██╗  ██╗
██╔════╝██╔════╝██╔════╝██║ ██╔╝
███████╗█████╗  █████╗  █████╔╝ 
╚════██║██╔══╝  ██╔══╝  ██╔═██╗ 
███████║███████╗██║     ██║  ██╗
╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝
     KESH Miner CLI 🚀
========================================
"""

PRINT_LOCK = threading.Lock()
STATUS_LOCK = threading.Lock()

# Rolling hashrate stats
THREAD_HASH_COUNTS = {}
EMA_HASHRATE = 0.0
EMA_ALPHA = 0.2  # smoothing

CURRENT_JOB = None
JOB_LOCK = threading.Lock()
NEW_JOB_EVENT = threading.Event()
STOP_EVENT = threading.Event()

# -----------------------------
# Utility functions
# -----------------------------

def log(msg: str):
    with PRINT_LOCK:
        print(msg, flush=True)

def fmt_hps(hps: float) -> str:
    units = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s"]
    i = 0
    value = float(hps)
    while value >= 1000.0 and i < len(units) - 1:
        value /= 1000.0
        i += 1
    return f"{value:.2f} {units[i]}"

# Build candidate string deterministically.
# The node should use the same header assembly; we attempt to be compatible with two styles:
# 1) explicit 'header' string + nonce
# 2) components: index|previous_hash|timestamp|data|nonce (data must be a JSON string)

def build_candidate(job: dict, nonce: int) -> bytes:
    if isinstance(job.get("header"), str):
        return f"{job['header']}{nonce}".encode()
    # fallback: compose header
    index = job.get("index")
    prev = job.get("previous_hash")
    ts = job.get("timestamp")
    data = job.get("data")
    if isinstance(data, (dict, list)):
        data = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return f"{index}|{prev}|{ts}|{data}|{nonce}".encode()

# Hash function: BLAKE2b-256

def blake2b256(x: bytes) -> str:
    return hashlib.blake2b(x, digest_size=32).hexdigest()

# -----------------------------
# Job management (poll /get_job)
# -----------------------------

def fetch_job(session: requests.Session) -> dict | None:
    url = CONFIG["pool_url"] if CONFIG["pool_mode"] else CONFIG["node_url"]
    endpoint = f"{url}/get_job"
    try:
        # Some nodes may require the miner address to personalize the job
        r = session.get(endpoint, params={"address": CONFIG["wallet_address"]}, timeout=CONFIG["request_timeout"])
        if r.status_code != 200:
            log(f"⚠️  get_job HTTP {r.status_code}: {r.text}")
            return None
        try:
            job = r.json()
        except Exception:
            log(f"⚠️  get_job returned non-JSON: {r.text[:200]}")
            return None
        # Normalize fields we expect to exist for printing
        if "difficulty" not in job:
            job["difficulty"] = job.get("target", 3)
        return job
    except Exception as e:
        log(f"❌ get_job error: {e}")
        return None


def job_poller():
    global CURRENT_JOB
    with requests.Session() as s:
        backoff = CONFIG["poll_interval"]
        connected = False
        while not STOP_EVENT.is_set():
            job = fetch_job(s)
            if job is None:
                if connected:
                    log("⚠️  Lost connection to pool/node. Reconnecting…")
                    connected = False
                time.sleep(min(backoff * 2, 10))
                continue

            if not connected:
                if CONFIG["pool_mode"]:
                    log(f"🔌 Connected to pool: {CONFIG['pool_url']}")
                else:
                    log(f"🔗 Connected to node: {CONFIG['node_url']}")
                connected = True

            # Detect new job (by index+prev or job_id if provided)
            with JOB_LOCK:
                prev = CURRENT_JOB
                CURRENT_JOB = job
            is_new = (
                prev is None or
                (prev.get("index"), prev.get("previous_hash"), prev.get("job_id"))
                != (job.get("index"), job.get("previous_hash"), job.get("job_id"))
            )
            if is_new:
                diff = job.get("difficulty", "?")
                height = job.get("index", "?")
                prefix = "0" * int(diff) if isinstance(diff, int) else "?"
                log(f"🆕 New job received (height {height}, diff {diff}, target {prefix}…)")
                # signal workers to switch
                NEW_JOB_EVENT.set()
                # let workers notice, then clear the flag
                time.sleep(0.1)
                NEW_JOB_EVENT.clear()

            time.sleep(CONFIG["poll_interval"])

# -----------------------------
# Mining workers
# -----------------------------

def submit_block(session: requests.Session, job: dict, nonce: int, h: str) -> bool:
    url = CONFIG["pool_url"] if CONFIG["pool_mode"] else CONFIG["node_url"]

    payload = {
        "miner_address": CONFIG["wallet_address"],
        "index": job.get("index"),
        "previous_hash": job.get("previous_hash"),
        "timestamp": job.get("timestamp"),
        "data": job.get("data"),  # JSON string or dict; node should parse
        "difficulty": job.get("difficulty"),
        "nonce": nonce,
        "hash": h,
    }

    # First try modern /submit_block
    try:
        r = session.post(f"{url}/submit_block", json=payload, timeout=CONFIG["request_timeout"])
        if r.status_code == 200:
            log("✅ Block accepted")
            return True
        else:
            try:
                err = r.json()
                log(f"❌ Rejected: {err}")
            except Exception:
                log(f"❌ Rejected: HTTP {r.status_code} {r.text}")
    except Exception as e:
        log(f"❌ submit_block error: {e}")

    # Fallback: legacy /mine_block
    try:
        r = session.post(f"{url}/mine_block", json=payload, timeout=CONFIG["request_timeout"])
        if r.status_code == 200:
            log("✅ Block accepted (legacy endpoint)")
            return True
        else:
            try:
                err = r.json()
                log(f"❌ Rejected (legacy): {err}")
            except Exception:
                log(f"❌ Rejected (legacy): HTTP {r.status_code} {r.text}")
    except Exception as e:
        log(f"❌ mine_block error: {e}")

    return False


def worker_thread(tid: int):
    local_counter = 0
    last_update = time.time()
    with requests.Session() as s:
        while not STOP_EVENT.is_set():
            # Grab latest job snapshot
            with JOB_LOCK:
                job = CURRENT_JOB
            if not job:
                time.sleep(0.1)
                continue

            try:
                diff = int(job.get("difficulty", 3))
            except Exception:
                diff = 3
            prefix = "0" * diff

            nonce = 0
            while not STOP_EVENT.is_set():
                # If a new job arrives, break and fetch it next loop
                if NEW_JOB_EVENT.is_set():
                    break

                candidate = build_candidate(job, nonce)
                h = blake2b256(candidate)
                nonce += 1
                local_counter += 1

                # once per second, update per-thread count
                now = time.time()
                if now - last_update >= 1.0:
                    with STATUS_LOCK:
                        THREAD_HASH_COUNTS[tid] = local_counter
                    local_counter = 0
                    last_update = now

                if h.startswith(prefix):
                    accepted = submit_block(s, job, nonce - 1, h)
                    # whether accepted or not, request a fresh job
                    NEW_JOB_EVENT.set()
                    break

# -----------------------------
# Stats printer (rolling average like XMRig)
# -----------------------------

def stats_printer():
    EMA = 0.0
    EMA_ALPHA_LOCAL = 0.2
    per_thread_hist = {i: [] for i in range(CONFIG["threads"])}
    window = CONFIG["difficulty_window"]
    last_print = time.time()

    while not STOP_EVENT.is_set():
        time.sleep(1.0)
        with STATUS_LOCK:
            per = {i: THREAD_HASH_COUNTS.get(i, 0) for i in range(CONFIG["threads"])}
            for i in range(CONFIG["threads"]):
                THREAD_HASH_COUNTS[i] = 0

        # Update rolling stats
        for i in range(CONFIG["threads"]):
            hist = per_thread_hist.setdefault(i, [])
            hist.append(per[i])
            if len(hist) > window:
                hist.pop(0)
        total_inst = sum(per.values())
        EMA = EMA_ALPHA_LOCAL * total_inst + (1 - EMA_ALPHA_LOCAL) * EMA

        if time.time() - last_print >= 2.0:
            parts = [f"T{i}:{fmt_hps(statistics.mean(per_thread_hist[i]) if per_thread_hist[i] else 0)}" for i in range(CONFIG["threads"])]
            log(f"⚡ Hashrate: {fmt_hps(EMA)} | " + " ".join(parts))
            last_print = time.time()

# -----------------------------
# Main
# -----------------------------

def main():
    log(BANNER)
    addr = CONFIG["wallet_address"]
    node = CONFIG["pool_url"] if CONFIG["pool_mode"] else CONFIG["node_url"]
    if CONFIG["pool_mode"]:
        log(f"🔌 Pool mode → {node}")
    else:
        log(f"🔗 Node → {node}")
    log(f"💼 Mining to → {addr}")

    # Start background threads
    poller = threading.Thread(target=job_poller, daemon=True)
    poller.start()

    stats = threading.Thread(target=stats_printer, daemon=True)
    stats.start()

    workers = []
    for tid in range(CONFIG["threads"]):
        t = threading.Thread(target=worker_thread, args=(tid,), daemon=True)
        t.start()
        workers.append(t)

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("Stopping miner…")
        STOP_EVENT.set()
        NEW_JOB_EVENT.set()
        for t in workers:
            t.join(timeout=1.0)

if __name__ == "__main__":
    main()
