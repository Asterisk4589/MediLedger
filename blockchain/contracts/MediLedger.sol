// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MediLedger {
    address public owner;
    struct Record { bytes32 dataHash; string deviceId; uint64 counter; uint64 storedAt; }
    mapping(uint256 => Record) private records;
    mapping(bytes32 => bytes32) public deviceKeyHash;

    event MeasurementStored(uint256 indexed id, string deviceId, bytes32 dataHash, uint64 counter);
    event DeviceRegistered(string deviceId, bytes32 keyHash);

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    constructor() { owner = msg.sender; }

    function registerDevice(string calldata deviceId, bytes32 keyHash) external onlyOwner {
        require(keyHash != bytes32(0), "empty key");
        require(deviceKeyHash[keccak256(bytes(deviceId))] == bytes32(0), "device exists");
        deviceKeyHash[keccak256(bytes(deviceId))] = keyHash;
        emit DeviceRegistered(deviceId, keyHash);
    }

    function store(uint256 id, string calldata deviceId, bytes32 dataHash, uint64 counter) external onlyOwner {
        require(records[id].storedAt == 0, "exists");
        records[id] = Record(dataHash, deviceId, counter, uint64(block.timestamp));
        emit MeasurementStored(id, deviceId, dataHash, counter);
    }

    function get(uint256 id) external view returns (bytes32, string memory, uint64, uint64) {
        Record storage r = records[id];
        require(r.storedAt != 0, "missing");
        return (r.dataHash, r.deviceId, r.counter, r.storedAt);
    }
}
