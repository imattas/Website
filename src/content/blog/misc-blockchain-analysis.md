---
title: "Misc - Blockchain Analysis"
description: "Extracting a hidden flag from a Solidity smart contract's private storage slot using a local Anvil node and cast."
author: "Zemi"
---

## Challenge Info

| Detail     | Value        |
|------------|--------------|
| Category   | Misc         |
| Difficulty | Hard         |
| Points     | 350          |
| Flag       | `zemi{bl0ckch41n_tr4c3d}` |

## Challenge Files

Download the challenge files to get started:

- [Contract.sol](/Website/challenges/misc-blockchain-analysis/Contract.sol)
- [deploy.py](/Website/challenges/misc-blockchain-analysis/deploy.py)
- [flag.txt](/Website/challenges/misc-blockchain-analysis/flag.txt)

## Reconnaissance

The challenge gives us a Solidity smart contract source and tells us it has been deployed on a local Anvil node. The flag is stored somewhere in the contract.

```bash
cat SecretVault.sol
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SecretVault {
    bool public isLocked = true;        // slot 0
    uint256 private secretNumber;        // slot 1
    address public owner;                // slot 2
    bytes32 private secretFlag;          // slot 3
    string private hiddenMessage;        // slot 4 (dynamic)

    mapping(address => bool) public authorized;  // slot 5

    constructor(bytes32 _flag, uint256 _secret) {
        owner = msg.sender;
        secretFlag = _flag;
        secretNumber = _secret;
        hiddenMessage = "The flag is in the secretFlag variable";
        authorized[msg.sender] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAuthorized() {
        require(authorized[msg.sender], "Not authorized");
        _;
    }

    function getFlag() public view onlyAuthorized returns (bytes32) {
        require(!isLocked, "Vault is locked");
        return secretFlag;
    }

    function unlock(uint256 _guess) public onlyOwner {
        require(_guess == secretNumber, "Wrong number");
        isLocked = false;
    }
}
```

The `secretFlag` is declared as `private` and the `getFlag()` function requires us to be the owner, authorized, and the vault must be unlocked. But `private` in Solidity does not mean hidden.

## Analysis

### Solidity storage layout

The EVM stores contract state in 32-byte storage slots, numbered sequentially:

| Slot | Variable | Type | Visibility |
|------|----------|------|------------|
| 0 | `isLocked` | bool | public |
| 1 | `secretNumber` | uint256 | private |
| 2 | `owner` | address | public |
| 3 | `secretFlag` | bytes32 | **private** |
| 4 | `hiddenMessage` | string | private (dynamic) |
| 5 | `authorized` | mapping | public |

**Key insight**: `private` only means other contracts cannot read the variable through the Solidity interface. Anyone can read any storage slot directly from the blockchain node. There is no on-chain privacy.

### Setting up the local environment

```bash
# Start a local Anvil node (Foundry's local Ethereum node)
anvil &
```

```
                             _   _
                            (_) | |
      __ _   _ __   __   __ _  | |
     / _` | | '_ \  \ \ / /| | | |
    | (_| | | | | |  \ V / | | | |
     \__,_| |_| |_|   \_/  |_| |_|

    0.2.0 (abc1234 2026-01-10T00:00:00.000Z)

Listening on 127.0.0.1:8545

Available Accounts
==================
(0) 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 (10000 ETH)
...

Private Keys
==================
(0) 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
...
```

### Deploy the contract

```bash
# Compile and deploy with forge
forge create --rpc-url http://localhost:8545 \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    src/SecretVault.sol:SecretVault \
    --constructor-args \
    0x7a656d697b626c30636b636834316e5f74723463336400000000000000000000 \
    42
```

```
Deployer: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
Deployed to: 0x5FbDB2315678afecb367f032d93F642f64180aa3
Transaction hash: 0x...
```

The contract is deployed at `0x5FbDB2315678afecb367f032d93F642f64180aa3`.

## Step-by-Step Walkthrough

### Step 1: Read the public variables first

```bash
# Check isLocked (slot 0)
cast storage 0x5FbDB2315678afecb367f032d93F642f64180aa3 0 --rpc-url http://localhost:8545
```

```
0x0000000000000000000000000000000000000000000000000000000000000001
```

The vault is locked (`true` = 1).

```bash
# Check owner (slot 2)
cast storage 0x5FbDB2315678afecb367f032d93F642f64180aa3 2 --rpc-url http://localhost:8545
```

```
0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266
```

The deployer's address.

### Step 2: Read the "private" secretNumber (slot 1)

```bash
cast storage 0x5FbDB2315678afecb367f032d93F642f64180aa3 1 --rpc-url http://localhost:8545
```

```
0x000000000000000000000000000000000000000000000000000000000000002a
```

`0x2a` = 42 in decimal. The secret number is 42.

### Step 3: Read the "private" secretFlag (slot 3)

```bash
cast storage 0x5FbDB2315678afecb367f032d93F642f64180aa3 3 --rpc-url http://localhost:8545
```

```
0x7a656d697b626c30636b636834316e5f74723463336400000000000000000000
```

### Step 4: Decode the bytes32 value

The storage value is hex-encoded ASCII. Convert it:

```bash
cast --to-ascii 0x7a656d697b626c30636b636834316e5f74723463336400000000000000000000
```

```
zemi{bl0ckch41n_tr4c3d}
```

Alternatively, decode with Python:

```python
hex_value = "7a656d697b626c30636b636834316e5f74723463336400000000000000000000"
flag = bytes.fromhex(hex_value).rstrip(b'\x00').decode()
print(flag)
```

```
zemi{bl0ckch41n_tr4c3d}
```

### Step 5: Reading dynamic types (bonus)

The `hiddenMessage` is a `string` — stored differently because it is dynamic:

```bash
cast storage 0x5FbDB2315678afecb367f032d93F642f64180aa3 4 --rpc-url http://localhost:8545
```

```
0x546865206...0000000000000000000000000000000000000000000000004e
```

For short strings (< 32 bytes), Solidity stores the string data and its length * 2 in the same slot. The last byte `0x4e` = 78, and 78/2 = 39 characters:

```python
import binascii
hex_val = "546865206...4e"  # full hex
data = bytes.fromhex(hex_val[:-2])  # strip length byte
print(data.rstrip(b'\x00').decode())
```

```
The flag is in the secretFlag variable
```

### Alternative: Using web3.py

```python
#!/usr/bin/env python3
"""read_storage.py - Read all contract storage slots"""
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
contract = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

print("[*] Reading all storage slots...")
for slot in range(6):
    value = w3.eth.get_storage_at(contract, slot)
    print(f"  Slot {slot}: {value.hex()}")

# Decode the flag from slot 3
flag_hex = w3.eth.get_storage_at(contract, 3)
flag = flag_hex.rstrip(b'\x00').decode()
print(f"\n[+] Flag: {flag}")
```

```bash
python3 read_storage.py
```

```
[*] Reading all storage slots...
  Slot 0: 0x0000000000000000000000000000000000000000000000000000000000000001
  Slot 1: 0x000000000000000000000000000000000000000000000000000000000000002a
  Slot 2: 0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266
  Slot 3: 0x7a656d697b626c30636b636834316e5f74723463336400000000000000000000
  Slot 4: 0x546865...4e
  Slot 5: 0x0000000000000000000000000000000000000000000000000000000000000000

[+] Flag: zemi{bl0ckch41n_tr4c3d}
```

## Solidity Storage Layout Reference

| Type | Storage Rule |
|------|-------------|
| `uint256`, `bytes32` | One full slot |
| `bool`, `uint8`, `address` | Packed into a single slot if consecutive |
| `string`, `bytes` (short) | Data + length in same slot |
| `string`, `bytes` (long) | Length in slot N, data at `keccak256(N)` |
| `mapping(K => V)` | Value at `keccak256(key . slot_number)` |
| `T[]` (dynamic array) | Length in slot N, elements at `keccak256(N) + index` |

## Common Solidity Vulnerabilities in CTFs

| Vulnerability | Description |
|---------------|-------------|
| **Private != Hidden** | All storage is publicly readable |
| **Integer overflow** | Unchecked math in Solidity < 0.8.0 |
| **Reentrancy** | External calls before state updates |
| **tx.origin** | Using `tx.origin` instead of `msg.sender` for auth |
| **Weak randomness** | Using `block.timestamp` or `blockhash` for randomness |
| **Visibility defaults** | Functions default to `public` in older Solidity |

## Tools Used

- **Foundry (`cast`, `forge`, `anvil`)** — local Ethereum development toolkit
- `cast storage` — read raw storage slots from any contract
- `cast --to-ascii` — convert hex to ASCII
- **Anvil** — local Ethereum node for testing
- **web3.py** — Python library for Ethereum interaction
- **Solidity** — understanding the source code and storage layout

## Lessons Learned

- **`private` in Solidity only restricts contract-to-contract access** — anyone with node access can read any storage slot with `eth_getStorageAt`
- Never store secrets, passwords, or flags in contract storage, even in `private` variables
- Understanding Solidity's storage layout is essential — variables are assigned sequential slots, and knowing the slot number lets you read any variable
- `cast storage` is the fastest way to inspect contract state in CTFs
- For real-world smart contracts, sensitive data should be stored off-chain or encrypted before being stored on-chain
- Local tools like Anvil and Hardhat make it easy to deploy and interact with contracts without any testnet ETH
