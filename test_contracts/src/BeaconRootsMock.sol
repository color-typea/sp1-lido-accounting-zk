// SPDX-FileCopyrightText: 2025 Lido <info@lido.fi>
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.27;


// NOT PART OF THE AUDIT SCOPE, ONLY USED FOR INTEGRATION TESTS
contract BeaconRootsMock {
    mapping(uint256 timestamp => bytes32 beacon_block_hash) public beacon_block_hashes;

    // Set the root for a given slot
    function setRoot(uint256 timestamp, bytes32 root) external {
        beacon_block_hashes[timestamp] = root;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        // Decode input as uint256
        uint256 timestamp = abi.decode(msg.data, (uint256));

        return abi.encode(beacon_block_hashes[timestamp]);
    }
}