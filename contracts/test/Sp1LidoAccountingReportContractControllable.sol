// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Sp1LidoAccountingReportContract, LidoValidatorState, Report, ReportMetadata} from "../src/Sp1LidoAccountingReportContract.sol";

contract Sp1LidoAccountingReportContractControllable is
    Sp1LidoAccountingReportContract
{
    mapping(uint256 => bytes32) private _beaconBlockHashes;

    constructor(
        address _verifier,
        bytes32 _vkey,
        bytes32 _lido_withdrawal_credentials,
        uint256 _genesis_timestamp,
        LidoValidatorState memory _initial_state
    ) Sp1LidoAccountingReportContract(_verifier, _vkey, _lido_withdrawal_credentials, _genesis_timestamp, _initial_state)  {
    }
    
    function setBeaconBlockHash(uint256 slot, bytes32 beaconBlockHash) public {
        _beaconBlockHashes[slot] = beaconBlockHash;
    }

    function _getBeaconBlockHash(
        uint256 slot
    ) internal view override returns (bytes32) {
        bytes32 result = _beaconBlockHashes[slot];
        require(result != 0, "Block hash is not set for target slot");
        return result;
    }

    function verify(
        uint256 slot,
        Report calldata report,
        ReportMetadata calldata metadata,
        bytes calldata proof,
        bytes calldata publicValues
    ) public view {
        _verify(slot, report, metadata, proof, publicValues);
    }
}
