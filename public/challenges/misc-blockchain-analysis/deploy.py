#!/usr/bin/env python3
"""
Misc Challenge: Blockchain Analysis
Deploys the SecretVault contract to a local Ethereum node (Hardhat/Anvil/Ganache)
and demonstrates how to read "private" storage.

Usage:
  1. Start a local node: npx hardhat node  (or anvil, or ganache-cli)
  2. python3 deploy.py

Dependencies: pip install web3 py-solc-x
  OR: Use the pre-compiled ABI/bytecode below for a dependency-light version.

The key insight: Solidity "private" variables are NOT private on-chain.
Anyone can read any storage slot using eth_getStorageAt.
"""

import json
import os
import sys

FLAG = "zemi{bl0ckch41n_tr4c3d}"

# Pre-compiled contract ABI and bytecode (compiled with solc 0.8.20)
# This allows deployment without needing the Solidity compiler installed.
# If you want to compile from source, use: solc --abi --bin Contract.sol

# Minimal ABI for interaction
CONTRACT_ABI = [
    {
        "inputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "inputs": [],
        "name": "getOwner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "isVaultLocked",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
]


def read_storage_slot(w3, contract_address, slot):
    """Read a raw storage slot from the contract."""
    value = w3.eth.get_storage_at(contract_address, slot)
    return value


def decode_dynamic_string(w3, contract_address, slot):
    """
    Decode a Solidity dynamic-length string from contract storage.

    For strings <= 31 bytes: data is stored in the slot itself (right-aligned),
    with the last byte being length*2.

    For strings > 31 bytes: the slot stores length*2+1, and actual data
    is at keccak256(slot).
    """
    raw = read_storage_slot(w3, contract_address, slot)

    # Check if it's a short string (last byte is even and < 64)
    last_byte = raw[-1]

    if last_byte % 2 == 0:
        # Short string: data is in the slot, length = last_byte / 2
        length = last_byte // 2
        return raw[:length].decode("utf-8", errors="replace")
    else:
        # Long string: length = (value - 1) / 2
        slot_value = int.from_bytes(raw, "big")
        length = (slot_value - 1) // 2

        # Data starts at keccak256(slot_number)
        from web3 import Web3
        data_slot = int.from_bytes(
            Web3.keccak(slot.to_bytes(32, "big")), "big"
        )

        # Read enough 32-byte chunks
        result = b""
        chunks_needed = (length + 31) // 32
        for i in range(chunks_needed):
            chunk = read_storage_slot(w3, contract_address, data_slot + i)
            result += chunk

        return result[:length].decode("utf-8", errors="replace")


def main():
    try:
        from web3 import Web3
    except ImportError:
        print("[!] web3 library not installed.")
        print("    pip install web3")
        print()
        print("Without deploying, here's how the attack works:")
        print()
        print("1. Connect to the node where the contract is deployed")
        print("2. Read storage slot 0 of the contract:")
        print("   web3.eth.getStorageAt(contractAddress, 0)")
        print("3. Decode the bytes as a UTF-8 string")
        print(f"4. The flag is: {FLAG}")
        return

    # Connect to local node
    rpc_url = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    if not w3.is_connected():
        print(f"[!] Cannot connect to {rpc_url}")
        print("    Start a local node first:")
        print("    npx hardhat node")
        print("    # or: anvil")
        print("    # or: ganache-cli")
        sys.exit(1)

    print(f"[+] Connected to {rpc_url}")
    print(f"    Chain ID: {w3.eth.chain_id}")
    print(f"    Block: {w3.eth.block_number}")

    # Use first account to deploy
    deployer = w3.eth.accounts[0]
    print(f"    Deployer: {deployer}")

    # Check if we have bytecode to deploy
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bytecode_file = os.path.join(script_dir, "Contract.bin")

    if os.path.exists(bytecode_file):
        with open(bytecode_file) as f:
            bytecode = f.read().strip()
    else:
        print()
        print("[!] No compiled bytecode (Contract.bin) found.")
        print("    To compile: solc --bin Contract.sol -o . --overwrite")
        print("    Or install: pip install py-solc-x")
        print()
        print("Demonstrating storage reading concept instead:")
        print(f"  The 'private' string secretFlag = \"{FLAG}\"")
        print(f"  is stored in storage slot 0 of the contract.")
        print(f"  Read it with: w3.eth.get_storage_at(contract_addr, 0)")
        return

    # Deploy
    print()
    print("[*] Deploying SecretVault contract...")
    tx_hash = w3.eth.send_transaction({
        "from": deployer,
        "data": "0x" + bytecode,
        "gas": 1000000,
    })
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = receipt.contractAddress
    print(f"[+] Deployed at: {contract_address}")

    # Now demonstrate reading "private" storage
    print()
    print("[*] Reading 'private' storage slots...")
    print()

    # Slot 0: secretFlag (string)
    print("  Slot 0 (secretFlag):")
    raw_slot0 = read_storage_slot(w3, contract_address, 0)
    print(f"    Raw: {raw_slot0.hex()}")
    flag = decode_dynamic_string(w3, contract_address, 0)
    print(f"    Decoded: {flag}")

    # Slot 1: owner (address)
    print("  Slot 1 (owner):")
    raw_slot1 = read_storage_slot(w3, contract_address, 1)
    print(f"    Raw: {raw_slot1.hex()}")
    owner = "0x" + raw_slot1[-20:].hex()
    print(f"    Decoded: {owner}")

    # Slot 2: deployTimestamp (uint256)
    print("  Slot 2 (deployTimestamp):")
    raw_slot2 = read_storage_slot(w3, contract_address, 2)
    print(f"    Raw: {raw_slot2.hex()}")
    print(f"    Decoded: {int.from_bytes(raw_slot2, 'big')}")

    print()
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
