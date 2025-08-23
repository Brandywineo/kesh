# miner_config.py

CONFIG = {
    # Your mining wallet address (KES format)
    "wallet_address": "kes25cce3a41c9375dac7d4a556543452",

    # URL of the node this miner will submit to and fetch work from
    "node_url": "http://127.0.0.1:5000",

    # Pool mining URL (optional, used if passed as CLI argument)
    "pool_url": None,

    # Time to wait before attempting another mining request (in seconds)
    "mining_interval": 0.0,

    # List of peer nodes in your network (optional)
    "peers": [
        # Example:
        # "http://192.168.1.99:5000",
        # "http://10.0.0.12:5000",
    ]
}
