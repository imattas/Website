// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Misc Challenge: Blockchain Analysis
 *
 * This contract stores the flag in a "private" state variable.
 * In Solidity, "private" only means other contracts can't read it directly.
 * Anyone can read all storage slots of a deployed contract using
 * eth_getStorageAt or similar RPC calls.
 *
 * Intended solution:
 *   1. Deploy the contract (or find its address)
 *   2. Read storage slot 0: web3.eth.getStorageAt(contractAddress, 0)
 *   3. Convert the hex bytes to ASCII to reveal the flag
 *
 * Since the flag is longer than 32 bytes, Solidity stores it as a
 * dynamic-length string. The slot itself contains (length * 2 + 1),
 * and the data is at keccak256(slot_number).
 */
contract SecretVault {
    // "Private" does NOT mean invisible on the blockchain!
    string private secretFlag;
    address private owner;
    uint256 private deployTimestamp;
    bool private isLocked;

    event VaultCreated(address indexed creator, uint256 timestamp);
    event VaultAccessed(address indexed accessor);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
        deployTimestamp = block.timestamp;
        isLocked = true;

        // The flag is stored in contract storage -- it's NOT actually secret!
        secretFlag = "zemi{bl0ckch41n_tr4c3d}";

        emit VaultCreated(msg.sender, block.timestamp);
    }

    /**
     * @notice This function requires the caller to be the owner.
     * But you don't need to call it -- just read the storage directly!
     */
    function getFlag() external onlyOwner returns (string memory) {
        require(isLocked == false, "Vault is locked");
        emit VaultAccessed(msg.sender);
        return secretFlag;
    }

    function unlock(bytes32 key) external onlyOwner {
        // Even this "unlock" mechanism is irrelevant --
        // the storage is always readable.
        require(key == keccak256(abi.encodePacked("open sesame")), "Wrong key");
        isLocked = false;
    }

    function getOwner() external view returns (address) {
        return owner;
    }

    function isVaultLocked() external view returns (bool) {
        return isLocked;
    }
}
