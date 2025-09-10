#!/usr/bin/env python3
"""
KESH Full Node (patched)

Features:
- Persistent store using sqlite3 (blocks, txs, utxos, mempool, meta)
- UTXO accounting
- Coinbase & halving logic
- Fee enforcement (MIN_FEE)
- Signature verification (ECDSA-SECP256k1) for inputs (skipped for coinbase)
- /get_job, /submit_block, /new_transaction, /get_balance, /get_transactions, /pending_transactions, /blocks, /height, /difficulty
- Standardized API error responses
- Optional debug logging to console
"""

import hashlib
import json
import time
import threading
import os
import sqlite3
import base64
from typing import List, Dict, Any, Tuple

import requests
from flask import Flask, request, jsonify
import ecdsa
import traceback
import sys

# ------------------------
# Configuration Constants
# ------------------------
DB_FILE = "blockchain.db"
PEERS_FILE = "peers.txt"
SEEDS = ["52.53.191.12:5000"]

TARGET_BLOCK_TIME = 120  # seconds per block (2 minutes)
INITIAL_DIFFICULTY = 3
MAX_DIFFICULTY = 32
MIN_DIFFICULTY = 1
HALVING_INTERVAL = 210_000
INITIAL_REWARD = 500.0
TAIL_EMISSION = 50.0
MAX_SUPPLY = 60_000_000_000.0
SYNC_INTERVAL = 300  # seconds

MIN_FEE = 0.000000005
DECIMALS = 8  # 8 decimal places

DEBUG = True  # set False to reduce console noise

app = Flask(__name__)


# ------------------------
# Helpers & Crypto
# ------------------------
def log_debug(*args, **kwargs):
    if DEBUG:
        print("[DEBUG]", *args, **kwargs)


def log_error(*args, **kwargs):
    print("[ERROR]", *args, **kwargs, file=sys.stderr)


def blake2b_hex(s: str) -> str:
    return hashlib.blake2b(s.encode(), digest_size=32).hexdigest()


def canonical(obj: Any) -> str:
    """Canonical JSON representation (sorted keys, compact separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _tx_message(tx: Dict[str, Any]) -> str:
    """Create normalized transaction message for signing/verification."""
    msg = {
        "version": tx.get("version", 1),
        "vin": [{"txid": i["txid"], "vout": int(i["vout"])} for i in tx.get("vin", [])],
        "vout": [{"address": o["address"], "amount": round(float(o["amount"]), DECIMALS)} for o in tx.get("vout", [])],
        "fee": round(float(tx.get("fee", 0)), DECIMALS),
        "nonce": int(tx.get("nonce", 0)),
        "timestamp": int(tx.get("timestamp", 0)),
    }
    return canonical(msg)


def pubkey_to_address(pubkey_bytes: bytes) -> str:
    """Derive a Kesh address from a raw public key (bytes)."""
    h = hashlib.blake2b(pubkey_bytes, digest_size=32).hexdigest()
    return "kes25" + h[:28]


def verify_input_sig(vin_entry: Dict[str, Any], msg: str) -> bool:
    """
    Verify ECDSA signature for a vin entry.
    vin_entry should include 'pubkey' (base64) and 'signature' (base64).
    """
    try:
        sig_b64 = vin_entry.get("signature", "")
        pub_b64 = vin_entry.get("pubkey", "")
        if not sig_b64 or not pub_b64:
            return False
        pub = base64.b64decode(pub_b64)
        sig = base64.b64decode(sig_b64)
        vk = ecdsa.VerifyingKey.from_string(pub, curve=ecdsa.SECP256k1)
        vk.verify(sig, msg.encode())
        addr = vin_entry.get("address")
        if addr and addr != pubkey_to_address(pub):
            return False
        return True
    except Exception:
        log_debug("Signature verification exception:", traceback.format_exc())
        return False


# ------------------------
# Storage (sqlite)
# ------------------------
class Store:
    def __init__(self, path: str):
        # sqlite3 connection used by multiple threads (check_same_thread=False)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cur = self.conn.cursor()
        self._init()

    def _init(self):
        # Create required tables
        self.cur.execute(
            """CREATE TABLE IF NOT EXISTS blocks (
                   height INTEGER PRIMARY KEY,
                   timestamp REAL,
                   previous_hash TEXT,
                   merkle TEXT,
                   nonce INTEGER,
                   difficulty INTEGER,
                   hash TEXT
               )"""
        )
        self.cur.execute(
            """CREATE TABLE IF NOT EXISTS txs (
                   txid TEXT PRIMARY KEY,
                   height INTEGER,
                   data TEXT
               )"""
        )
        self.cur.execute(
            """CREATE TABLE IF NOT EXISTS utxos (
                   txid TEXT,
                   vout_idx INTEGER,
                   address TEXT,
                   amount REAL,
                   spent INTEGER DEFAULT 0,
                   spent_by TEXT,
                   PRIMARY KEY (txid, vout_idx)
               )"""
        )
        self.cur.execute(
            """CREATE TABLE IF NOT EXISTS mempool (
                   txid TEXT PRIMARY KEY,
                   data TEXT
               )"""
        )
        self.cur.execute(
            """CREATE TABLE IF NOT EXISTS meta (
                   key TEXT PRIMARY KEY,
                   value TEXT
               )"""
        )
        self.conn.commit()

        # initialize genesis if needed
        if self.get_tip() is None:
            self._create_genesis()

        if self.get_meta("difficulty") is None:
            self.set_meta("difficulty", str(INITIAL_DIFFICULTY))

    def _create_genesis(self):
        ts = time.time()
        genesis_hash = blake2b_hex(canonical({"height": 0, "timestamp": ts, "previous_hash": "0"}))
        self.cur.execute(
            "INSERT INTO blocks(height, timestamp, previous_hash, merkle, nonce, difficulty, hash) VALUES(?,?,?,?,?,?,?)",
            (0, ts, "0", "", 0, INITIAL_DIFFICULTY, genesis_hash),
        )
        self.conn.commit()

    # meta helpers
    def get_meta(self, k: str):
        self.cur.execute("SELECT value FROM meta WHERE key=?", (k,))
        row = self.cur.fetchone()
        return row[0] if row else None

    def set_meta(self, k: str, v: str):
        self.cur.execute("REPLACE INTO meta(key,value) VALUES(?,?)", (k, v))
        self.conn.commit()

    # tip/block helpers
    def get_tip(self):
        self.cur.execute("SELECT height, hash, difficulty, timestamp FROM blocks ORDER BY height DESC LIMIT 1")
        return self.cur.fetchone()

    def get_block(self, height: int):
        self.cur.execute("SELECT * FROM blocks WHERE height=?", (height,))
        return self.cur.fetchone()

    def add_block(self, height: int, ts: float, prev_hash: str, merkle: str, nonce: int, difficulty: int, hash_hex: str):
        self.cur.execute(
            "INSERT INTO blocks(height, timestamp, previous_hash, merkle, nonce, difficulty, hash) VALUES(?,?,?,?,?,?,?)",
            (height, ts, prev_hash, merkle, nonce, difficulty, hash_hex),
        )
        self.conn.commit()

    # tx helpers
    def put_tx(self, txid: str, height: int, data: Dict[str, Any]):
        self.cur.execute("REPLACE INTO txs(txid, height, data) VALUES(?,?,?)", (txid, height, canonical(data)))
        self.conn.commit()

    # utxo helpers
    def add_utxo(self, txid: str, idx: int, address: str, amount: float):
        amt = round(float(amount), DECIMALS)
        self.cur.execute(
            "REPLACE INTO utxos(txid, vout_idx, address, amount, spent, spent_by) VALUES(?,?,?,?,0,NULL)",
            (txid, idx, address, amt),
        )

    def spend_utxo(self, txid: str, idx: int, spender_txid: str):
        self.cur.execute(
            "UPDATE utxos SET spent=1, spent_by=? WHERE txid=? AND vout_idx=? AND spent=0",
            (spender_txid, txid, idx),
        )

    def get_utxos(self, address: str):
        self.cur.execute("SELECT txid, vout_idx, amount FROM utxos WHERE address=? AND spent=0", (address,))
        return self.cur.fetchall()

    def balance(self, address: str) -> float:
        self.cur.execute("SELECT SUM(amount) FROM utxos WHERE address=? AND spent=0", (address,))
        row = self.cur.fetchone()
        return round(float(row[0]), DECIMALS) if row and row[0] is not None else 0.0

    # mempool helpers
    def mempool_put(self, txid: str, tx: Dict[str, Any]):
        self.cur.execute("REPLACE INTO mempool(txid, data) VALUES(?,?)", (txid, canonical(tx)))
        self.conn.commit()

    def mempool_all(self) -> List[Dict[str, Any]]:
        self.cur.execute("SELECT data FROM mempool")
        return [json.loads(r[0]) for r in self.cur.fetchall()]

    def mempool_delete(self, txid: str):
        self.cur.execute("DELETE FROM mempool WHERE txid=?", (txid,))
        self.conn.commit()


# ------------------------
# Node logic
# ------------------------
class Node:
    def __init__(self):
        self.store = Store(DB_FILE)
        self.peers = set()
        self._load_peers()
        # start a periodic sync loop in background (lightweight placeholder)
        threading.Thread(target=self._sync_loop, daemon=True).start()

    def current_height(self) -> int:
        tip = self.store.get_tip()
        return int(tip[0]) if tip else 0

    def current_hash(self) -> str:
        tip = self.store.get_tip()
        return str(tip[1]) if tip else "0"

    def current_difficulty(self) -> int:
        d = self.store.get_meta("difficulty")
        return int(d) if d else INITIAL_DIFFICULTY

    def block_reward(self, height: int, total_issued: float) -> float:
        halvings = height // HALVING_INTERVAL
        # floating halving handling
        reward = INITIAL_REWARD / (2 ** halvings)
        if reward < TAIL_EMISSION:
            reward = TAIL_EMISSION
        if total_issued >= MAX_SUPPLY:
            reward = TAIL_EMISSION
        return round(float(reward), DECIMALS)

    def _adjust_difficulty(self):
        # Adjust difficulty based on last N blocks (simple algorithm)
        self.store.cur.execute("SELECT timestamp, difficulty FROM blocks ORDER BY height DESC LIMIT 30")
        rows = self.store.cur.fetchall()
        if len(rows) < 2:
            return
        times = [r[0] for r in rows][::-1]
        diffs = [int(r[1]) for r in rows][::-1]
        intervals = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
        avg = sum(intervals) / len(intervals)
        cur = int(diffs[-1])
        if avg < TARGET_BLOCK_TIME * 0.8 and cur < MAX_DIFFICULTY:
            cur += 1
        elif avg > TARGET_BLOCK_TIME * 1.2 and cur > MIN_DIFFICULTY:
            cur -= 1
        self.store.set_meta("difficulty", str(cur))

    def compute_txid(self, tx: Dict[str, Any]) -> str:
        return blake2b_hex(canonical(tx))

    def _calc_total_in(self, tx: Dict[str, Any]) -> float:
        total_in = 0.0
        for i in tx.get("vin", []):
            self.store.cur.execute(
                "SELECT amount FROM utxos WHERE txid=? AND vout_idx=? AND spent=0",
                (i["txid"], int(i["vout"]))
            )
            r = self.store.cur.fetchone()
            if not r:
                return -1.0
            total_in += float(r[0])
        return round(total_in, DECIMALS)

    def _calc_total_out(self, tx: Dict[str, Any]) -> float:
        return round(sum(float(o["amount"]) for o in tx.get("vout", [])), DECIMALS)

    def calc_tx_fee(self, tx: Dict[str, Any]) -> float:
        if len(tx.get("vin", [])) == 0:
            # coinbase has no fee
            return 0.0
        total_in = self._calc_total_in(tx)
        total_out = self._calc_total_out(tx)
        if total_in < 0:
            return -1.0
        fee = round(total_in - total_out, DECIMALS)
        return fee

    def validate_tx(self, tx: Dict[str, Any]) -> bool:
        """
        Validate a transaction (inputs exist & not spent, signatures correct, fee >= MIN_FEE).
        Coinbase (vin empty) is allowed by this function to be considered valid (special-case elsewhere).
        """
        # coinbase (no inputs) treated as valid here; coinbase rules enforced in block submission
        if len(tx.get("vin", [])) == 0:
            return True

        msg = _tx_message(tx)
        for i in tx.get("vin", []):
            if not verify_input_sig(i, msg):
                log_debug("Invalid signature for input", i)
                return False

            self.store.cur.execute(
                "SELECT address, amount, spent FROM utxos WHERE txid=? AND vout_idx=?",
                (i["txid"], int(i["vout"]))
            )
            r = self.store.cur.fetchone()
            if not r or r["spent"] == 1:
                log_debug("Referenced UTXO missing or spent:", i)
                return False
            if i.get("address") and i.get("address") != r["address"]:
                log_debug("Input address mismatch:", i, r)
                return False

        total_in = self._calc_total_in(tx)
        if total_in < 0:
            return False
        total_out = self._calc_total_out(tx)
        fee_calc = round(total_in - total_out, DECIMALS)
        if fee_calc < MIN_FEE:
            log_debug("Fee too low:", fee_calc)
            return False

        return True

    def merkle_like(self, txs: List[Dict[str, Any]]) -> str:
        joined = "".join(self.compute_txid(t) for t in txs)
        return blake2b_hex(joined)

    def pow_valid(self, header: Dict[str, Any], nonce: int, difficulty: int) -> Tuple[str, bool]:
        header_str = canonical({**header, "nonce": int(nonce), "difficulty": int(difficulty)})
        h = blake2b_hex(header_str)
        return h, h.startswith("0" * int(difficulty))

    def assemble_block_template(self, miner_address: str) -> Dict[str, Any]:
        """Create a block template (header + txs) for miners."""
        height = self.current_height() + 1
        prev_hash = self.current_hash()
        difficulty = self.current_difficulty()
        mem = self.store.mempool_all()
        total_issued = self.total_issued()
        reward_only = self.block_reward(height, total_issued)
        total_fees = 0.0
        valid_mem = []
        for t in mem:
            if not self.validate_tx(t):
                continue
            fee = self.calc_tx_fee(t)
            if fee < MIN_FEE:
                continue
            total_fees += fee
            valid_mem.append(t)
        total_fees = round(total_fees, DECIMALS)

        coinbase = {
            "version": 1,
            "vin": [],  # coinbase has no inputs
            "vout": [{"address": miner_address, "amount": round(reward_only + total_fees, DECIMALS)}],
            "fee": 0.0,
            "nonce": 0,
            "timestamp": int(time.time()),
            "coinbase": True,
        }
        txs = [coinbase] + valid_mem
        merkle = self.merkle_like(txs)
        header = {
            "height": height,
            "timestamp": time.time(),
            "previous_hash": prev_hash,
            "merkle": merkle,
        }
        return {"header": header, "difficulty": difficulty, "txs": txs}

    def apply_block(self, header: Dict[str, Any], nonce: int, difficulty: int, txs: List[Dict[str, Any]], block_hash: str):
        """Apply a validated block to the store (write blocks, txs, update UTXOs)."""
        height = int(header["height"])
        ts = float(header["timestamp"])
        merkle = str(header["merkle"])
        prev_hash = str(header["previous_hash"])

        # write block
        self.store.add_block(height, ts, prev_hash, merkle, int(nonce), int(difficulty), block_hash)

        # write txs and update utxos
        for tx in txs:
            txid = self.compute_txid(tx)
            # store tx with height
            self.store.put_tx(txid, height, tx)
            # spend inputs
            for i in tx.get("vin", []):
                self.store.spend_utxo(i["txid"], int(i["vout"]), txid)
            # add outputs
            for idx, o in enumerate(tx.get("vout", [])):
                self.store.add_utxo(txid, idx, o["address"], float(o["amount"]))
            # ensure it's removed from mempool if present
            self.store.mempool_delete(txid)

        # commit and adjust difficulty
        self.store.conn.commit()
        self._adjust_difficulty()

    def total_issued(self) -> float:
        """Return total Kesh issued by summing all utxos (approximation)."""
        self.store.cur.execute("SELECT SUM(amount) FROM utxos")
        row = self.store.cur.fetchone()
        return round(float(row[0]), DECIMALS) if row and row[0] is not None else 0.0

    def _load_peers(self):
        if os.path.exists(PEERS_FILE):
            with open(PEERS_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self.peers.add(line)
        if not self.peers:
            self.peers.update(SEEDS)

    def _sync_loop(self):
        # minimal periodic maintenance loop; placeholder for future peer sync
        while True:
            time.sleep(SYNC_INTERVAL)


# Create node instance
node = Node()

# ------------------------
# API: web endpoints
# ------------------------
def api_error(message: str, code: int = 400, accepted_field: bool = False):
    """
    Standardized API error helper.
    If accepted_field True, returns {'accepted': False, 'error': message}.
    Else returns {'error': message}.
    """
    if accepted_field:
        return jsonify({"accepted": False, "error": message}), code
    return jsonify({"error": message}), code


@app.route("/", methods=["GET"])
def root():
    html = """
    <pre>
███████╗███████╗███████╗██╗  ██╗
██╔════╝██╔════╝██╔════╝██║ ██╔╝
███████╗█████╗  █████╗  █████╔╝ 
╚════██║██╔══╝  ██╔══╝  ██╔═██╗ 
███████║███████╗██║     ██║  ██╗
╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝

 KESH Full Node is running.

✅ For the People, By the People
💪 Support freedom by running this node
💡 You are powering a transparent and just financial system
    </pre>
    <h1 style='color: #4CAF50;'>🚀 Welcome to the Kesh Node</h1>
    <p>✅ Your full node is running successfully.</p>
    <p>🌐 To interact with the blockchain, use available API endpoints.</p>
    <ul>
      <li>GET /get_balance/&lt;address&gt;</li>
      <li>GET /get_transactions/&lt;address&gt;</li>
      <li>POST /new_transaction</li>
      <li>GET /pending_transactions</li>
      <li>GET /get_job?address=&lt;miner_addr&gt;</li>
      <li>POST /submit_block</li>
      <li>GET /blocks</li>
      <li>GET /height</li>
      <li>GET /difficulty</li>
    </ul>
    <hr>
    <p style='font-size: small;'>Kesh: For the people. By the people.</p>
    """
    return html, 200, {"Content-Type": "text/html"}


@app.route("/get_balance/<address>", methods=["GET"])
def get_balance(address):
    try:
        bal = node.store.balance(address)
        return jsonify({"address": address, "balance": bal})
    except Exception:
        log_error("get_balance error:", traceback.format_exc())
        return api_error("internal error", 500)


@app.route("/get_transactions/<address>", methods=["GET"])
def get_transactions(address):
    try:
        node.store.cur.execute("SELECT txid, height, data FROM txs ORDER BY height ASC")
        rows = node.store.cur.fetchall()
        hits = []
        for row in rows:
            txid = row["txid"]
            height = row["height"]
            tx = json.loads(row["data"])
            # incoming outputs
            for o in tx.get("vout", []):
                if o.get("address") == address:
                    hits.append({"txid": txid, "height": height, "direction": "in", "amount": o.get("amount")})
            # outgoing inputs
            for i in tx.get("vin", []):
                if i.get("address") == address:
                    node.store.cur.execute(
                        "SELECT amount FROM utxos WHERE txid=? AND vout_idx=?",
                        (i["txid"], int(i["vout"]))
                    )
                    r = node.store.cur.fetchone()
                    amt = float(r[0]) if r else 0.0
                    hits.append({"txid": txid, "height": height, "direction": "out", "amount": amt})
        return jsonify({"address": address, "txs": hits})
    except Exception:
        log_error("get_transactions error:", traceback.format_exc())
        return api_error("internal error", 500)


@app.route("/pending_transactions", methods=["GET"])
def pending_transactions():
    try:
        mem = node.store.mempool_all()
        return jsonify(mem)
    except Exception:
        log_error("pending_transactions error:", traceback.format_exc())
        return api_error("internal error", 500)


@app.route("/new_transaction", methods=["POST"])
def new_transaction():
    """
    Accepts a user-signed transaction and places it into mempool.
    Expects JSON tx object with vin, vout, fee, nonce, timestamp, etc.
    """
    try:
        tx = request.get_json(force=True)
    except Exception:
        return api_error("invalid json", 400)

    if not isinstance(tx, dict):
        return api_error("tx must be object", 400)
    if "vout" not in tx or not isinstance(tx.get("vout"), list):
        return api_error("missing outputs", 400)
    if len(tx.get("vin", [])) == 0:
        return api_error("coinbase not allowed here", 400)

    try:
        if not node.validate_tx(tx):
            return api_error("invalid transaction", 400)
        fee_calc = node.calc_tx_fee(tx)
        if fee_calc < MIN_FEE:
            return api_error("fee below minimum", 400)
        txid = node.compute_txid(tx)

        # check double-spend / duplicates
        node.store.cur.execute("SELECT 1 FROM txs WHERE txid=?", (txid,))
        if node.store.cur.fetchone():
            return api_error("already mined", 400)
        node.store.cur.execute("SELECT 1 FROM mempool WHERE txid=?", (txid,))
        if node.store.cur.fetchone():
            return api_error("exists in mempool", 400)

        node.store.mempool_put(txid, tx)
        return jsonify({"ok": True, "txid": txid})
    except Exception:
        log_error("new_transaction error:", traceback.format_exc())
        return api_error("internal error", 500)


def _difficulty_to_target_hex(d: int) -> str:
    d = max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, int(d)))
    return "0" * d + "f" * (64 - d)


@app.route("/get_job", methods=["GET"])
def get_job():
    """
    Return a mining job (header, txs, difficulty, target, height, previous_hash, job_id).
    Miners must supply ?address=kes25...
    """
    miner_address = request.args.get("address")
    if not miner_address or not isinstance(miner_address, str) or not miner_address.startswith("kes25"):
        return api_error("missing or invalid miner address", 400)

    try:
        tpl = node.assemble_block_template(miner_address)
        diff = node.current_difficulty()
        tpl_out = {
            "header": tpl["header"],
            "txs": tpl["txs"],
            "difficulty": diff,
            "target": _difficulty_to_target_hex(diff),
            "height": tpl["header"]["height"],
            "previous_hash": tpl["header"]["previous_hash"],
        }
        job_id = blake2b_hex(canonical({"h": tpl_out["header"], "txs": tpl_out["txs"]}))
        tpl_out["job_id"] = job_id
        return jsonify(tpl_out)
    except Exception:
        log_error("get_job error:", traceback.format_exc())
        return api_error("internal error", 500)


def _extract_submit_payload(data: Dict[str, Any]) -> Tuple[Dict[str, Any], int, int, List[Dict[str, Any]]]:
    """
    Accept different payload shapes:
    - {"header":..., "txs": [...], "nonce": ..., "difficulty": ...}
    - {"block": {"header":..., "txs": [...], "nonce": ..., "difficulty": ...}, "miner_address": "..."}
    Return header, nonce, difficulty, txs
    """
    if not isinstance(data, dict):
        return {}, 0, node.current_difficulty(), []

    if "header" in data and "txs" in data and "nonce" in data:
        header = data["header"]
        nonce = int(data["nonce"])
        difficulty = int(data.get("difficulty", node.current_difficulty()))
        txs = data["txs"]
        return header, nonce, difficulty, txs

    if "block" in data and isinstance(data["block"], dict):
        b = data["block"]
        header = b.get("header", {})
        txs = b.get("txs", [])
        nonce = int(b.get("nonce", data.get("nonce", 0)))
        difficulty = int(b.get("difficulty", data.get("difficulty", node.current_difficulty())))
        return header, nonce, difficulty, txs

    # legacy flat format support: detect flat fields
    if all(k in data for k in ("index", "previous_hash", "timestamp", "data", "nonce")):
        header = {
            "height": data.get("index"),
            "timestamp": data.get("timestamp"),
            "previous_hash": data.get("previous_hash"),
            "merkle": data.get("merkle", ""),
        }
        nonce = int(data.get("nonce", 0))
        difficulty = int(data.get("difficulty", node.current_difficulty()))
        txs = data.get("txs", [])
        return header, nonce, difficulty, txs

    return {}, 0, node.current_difficulty(), []


@app.route("/submit_block", methods=["POST"])
def submit_block():
    """
    Validate and accept a submitted block.
    Standardized error responses: returns {"accepted": False, "error": "..."} on rejection.
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return api_error("invalid json", 400, accepted_field=True)

    header, nonce, difficulty, txs = _extract_submit_payload(data)

    # minimal shape checks
    if not isinstance(header, dict) or not isinstance(txs, list):
        return api_error("malformed payload", 400, accepted_field=True)

    try:
        # expected previous & height
        tip = node.store.get_tip()
        exp_prev = tip["hash"] if tip else "0"
        exp_height = (int(tip["height"]) if tip else 0) + 1

        if header.get("previous_hash") != exp_prev:
            return api_error("stale previous hash", 400, accepted_field=True)
        if int(header.get("height", -1)) != exp_height:
            return api_error("bad height", 400, accepted_field=True)

        # coinbase must be present and first
        if len(txs) == 0:
            return api_error("empty block txs", 400, accepted_field=True)
        # coinbase: no vin allowed
        if len(txs[0].get("vin", [])) != 0:
            return api_error("first tx must be coinbase (no inputs)", 400, accepted_field=True)

        # validate all other transactions
        total_fees = 0.0
        for t in txs[1:]:
            if not node.validate_tx(t):
                return api_error("invalid tx in block", 400, accepted_field=True)
            fee = node.calc_tx_fee(t)
            if fee < MIN_FEE:
                return api_error("tx fee below minimum", 400, accepted_field=True)
            total_fees += fee
        total_fees = round(total_fees, DECIMALS)

        # verify coinbase amount equals block subsidy + fees
        total_issued = node.total_issued()
        expected_reward = node.block_reward(exp_height, total_issued)
        coinbase_out = round(sum(float(o["amount"]) for o in txs[0].get("vout", [])), DECIMALS)
        if coinbase_out != round(expected_reward + total_fees, DECIMALS):
            return api_error("bad coinbase value", 400, accepted_field=True)

        # verify merkle
        calc_merkle = node.merkle_like(txs)
        if header.get("merkle") != calc_merkle:
            return api_error("bad merkle", 400, accepted_field=True)

        # verify PoW
        block_hash, ok = node.pow_valid(header, int(nonce), difficulty)
        if not ok:
            return api_error("invalid pow", 400, accepted_field=True)

        # apply block to DB
        node.apply_block(header, int(nonce), difficulty, txs, block_hash)
        log_debug(f"Block accepted height={exp_height} hash={block_hash}")
        return jsonify({"accepted": True, "height": exp_height, "hash": block_hash})
    except Exception:
        log_error("submit_block internal error:", traceback.format_exc())
        return api_error("internal error", 500, accepted_field=True)


# legacy endpoints mapping to submit_block for compatibility
@app.route("/mine", methods=["POST"])
def mine_legacy():
    return submit_block()


@app.route("/mine_block", methods=["POST"])
def mine_block_legacy():
    return submit_block()


@app.route("/blocks", methods=["GET"])
def blocks():
    try:
        limit = int(request.args.get("limit", 50))
        node.store.cur.execute(
            "SELECT height, timestamp, previous_hash, merkle, nonce, difficulty, hash FROM blocks ORDER BY height DESC LIMIT ?",
            (limit,)
        )
        rows = node.store.cur.fetchall()
        res = [
            {
                "height": r["height"],
                "timestamp": r["timestamp"],
                "previous_hash": r["previous_hash"],
                "merkle": r["merkle"],
                "nonce": r["nonce"],
                "difficulty": r["difficulty"],
                "hash": r["hash"],
            }
            for r in rows
        ]
        return jsonify(res)
    except Exception:
        log_error("blocks error:", traceback.format_exc())
        return api_error("internal error", 500)


@app.route("/height", methods=["GET"])
def height():
    try:
        tip = node.store.get_tip()
        return jsonify({"height": int(tip["height"]) if tip else 0})
    except Exception:
        log_error("height error:", traceback.format_exc())
        return api_error("internal error", 500)


@app.route("/difficulty", methods=["GET"])
def difficulty():
    try:
        return jsonify({"difficulty": node.current_difficulty()})
    except Exception:
        log_error("difficulty error:", traceback.format_exc())
        return api_error("internal error", 500)


# ------------------------
# If executed directly, run Flask
# ------------------------
if __name__ == "__main__":
    print(
        """
███████╗███████╗███████╗██╗  ██╗
██╔════╝██╔════╝██╔════╝██║ ██╔╝
███████╗█████╗  █████╗  █████╔╝
╚════██║██╔══╝  ██╔══╝  ██╔═██╗
███████║███████╗██║     ██║  ██╗
╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝
  KESH Full Node starting...
        """
    )
    host = os.environ.get("KESH_BIND", "0.0.0.0")
    port = int(os.environ.get("KESH_PORT", "5000"))
    try:
        app.run(host=host, port=port, threaded=True)
    except Exception:
        log_error("Flask failed to start:", traceback.format_exc())
