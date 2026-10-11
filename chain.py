import json, os
from web3 import Web3

w3 = Web3(Web3.HTTPProvider(os.getenv("RPC_URL", "http://127.0.0.1:8545")))
ART = os.getenv("ARTIFACT", "blockchain/artifacts/contracts/MediLedger.sol/MediLedger.json")
contract = w3.eth.contract(
    address=Web3.to_checksum_address(os.environ["CONTRACT_ADDRESS"]),
    abi=json.load(open(ART))["abi"],
)
ACCOUNT = w3.eth.accounts[0]

def _send(fn):
    tx = fn.transact({"from": ACCOUNT})
    w3.eth.wait_for_transaction_receipt(tx)
    return w3.to_hex(tx)

def store(mid, device_id, hash_hex, counter):
    return _send(contract.functions.store(mid, device_id, bytes.fromhex(hash_hex), counter))

def get(mid):
    try:
        h, dev, ctr, ts = contract.functions.get(mid).call()
        return {"hash": h.hex(), "device": dev, "counter": ctr, "ts": ts}
    except Exception:
        return None

def register_device(device_id, key_hash: bytes):
    return _send(contract.functions.registerDevice(device_id, key_hash))

def device_key_hash(device_id) -> bytes:
    return contract.functions.deviceKeyHash(Web3.keccak(text=device_id)).call()