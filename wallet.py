import os
import json
import base64
import hashlib
import secrets
import requests
import time
import ecdsa

WALLET_DIR = "wallets"
NODE_ADDRESS = "http://127.0.0.1:5000"

if not os.path.exists(WALLET_DIR):
    os.makedirs(WALLET_DIR)

def save_wallet(wallet_data):
    filename = os.path.join(WALLET_DIR, f"{wallet_data['address']}.json")
    with open(filename, "w") as f:
        json.dump(wallet_data, f)

def pubkey_to_address(pubkey_bytes: bytes) -> str:
    h = hashlib.blake2b(pubkey_bytes, digest_size=32).hexdigest()
    return "kes25" + h[:28]

def generate_wallet():
    private_key = secrets.token_hex(32)
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key_bytes = vk.to_string()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    address = pubkey_to_address(public_key_bytes)

    wallet_data = {
        "address": address,
        "private_key": private_key,
        "public_key": public_key_b64,
        "nonce": 0
    }

    save_wallet(wallet_data)

    print(f"\n✅ Wallet generated and saved to {os.path.join(WALLET_DIR, f'{address}.json')}")
    print(f"📮 Address: {address}")
    print(f"🔑 Private Key: {private_key}")
    return wallet_data

def load_wallet():
    files = [f for f in os.listdir(WALLET_DIR) if f.endswith(".json")]
    if not files:
        print("⚠️ No wallets found. Generate or import one first.")
        return None

    print("\n📂 Available wallets:")
    for i, f in enumerate(files):
        print(f"{i + 1}. {f}")
    choice = int(input("Choose wallet: ")) - 1

    with open(os.path.join(WALLET_DIR, files[choice]), "r") as f:
        wallet_data = json.load(f)

    print(f"\n✅ Wallet loaded: {wallet_data['address']}")
    return wallet_data

def get_balance(address):
    try:
        response = requests.get(f"{NODE_ADDRESS}/get_balance/{address}")
        if response.status_code == 200:
            return response.json().get("balance", 0.0)
    except Exception as e:
        print(f"❌ Error fetching balance: {e}")
    return 0

def sign_transaction(tx, private_key):
    msg = json.dumps({
        "vin": tx["vin"],
        "vout": tx["vout"],
        "fee": tx["fee"],
        "nonce": tx["nonce"],
        "timestamp": tx["timestamp"]
    }, sort_keys=True)
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    signature = base64.b64encode(sk.sign(msg.encode())).decode()
    return signature

def generate_transaction(wallet):
    to = input("📮 To (recipient address): ")
    amount = float(input("💰 Amount in KES: "))
    fee = float(input("💸 Fee (minimum 0.000000005): ") or 0.000000005)
    nonce = wallet.get("nonce", int(time.time()))
    timestamp = int(time.time())

    # For now, assume the wallet spends all UTXOs (simple version)
    try:
        utxos = requests.get(f"{NODE_ADDRESS}/get_transactions/{wallet['address']}").json()
    except Exception as e:
        print(f"❌ Error fetching UTXOs: {e}")
        return

    # Build vin and vout (simplified: take first available UTXO)
    vin = []
    total_in = 0.0
    for tx in utxos.get("txs", []):
        if tx["direction"] == "in":
            vin.append({"txid": tx["txid"], "vout": 0, "address": wallet["address"], "pubkey": wallet["public_key"]})
            total_in += tx["amount"]
            if total_in >= amount + fee:
                break

    if total_in < amount + fee:
        print("❌ Not enough balance for this transaction.")
        return

    vout = [{"address": to, "amount": round(amount, 8)}]
    change = round(total_in - amount - fee, 8)
    if change > 0:
        vout.append({"address": wallet["address"], "amount": change})

    tx_data = {
        "version": 1,
        "vin": vin,
        "vout": vout,
        "fee": fee,
        "nonce": nonce,
        "timestamp": timestamp
    }

    signature = sign_transaction(tx_data, wallet["private_key"])
    for i in vin:
        i["signature"] = signature

    try:
        res = requests.post(f"{NODE_ADDRESS}/new_transaction", json=tx_data)
        if res.status_code == 200:
            print("✅ Transaction submitted.")
            wallet["nonce"] += 1
            save_wallet(wallet)
        else:
            print(f"❌ Failed to send transaction: {res.text}")
    except Exception as e:
        print(f"❌ Network error: {e}")

def main():
    print("🔐 Welcome to Kesh Wallet")
    print("==========================")
    print("1. Generate new wallet")
    print("2. Load wallet")
    print("3. Check balance")
    print("4. Send KES")
    print("5. Quit")

    wallet = None
    while True:
        choice = input("\nChoose an option (1–5): ")
        if choice == "1":
            wallet = generate_wallet()
        elif choice == "2":
            wallet = load_wallet()
        elif choice == "3":
            if wallet:
                balance = get_balance(wallet["address"])
                print(f"\n💼 Balance: {balance:.8f} KES")
            else:
                print("⚠️ Load a wallet first.")
        elif choice == "4":
            if wallet:
                generate_transaction(wallet)
            else:
                print("⚠️ Load a wallet first.")
        elif choice == "5":
            print("👋 Exiting wallet.")
            break
        else:
            print("❌ Invalid option.")

if __name__ == "__main__":
    main()
