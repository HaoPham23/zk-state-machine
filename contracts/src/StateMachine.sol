// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { StateMachineVerifier } from "./StateMachineVerifier.sol";

contract StateMachine {
    StateMachineVerifier verifier;
    bytes internal phi;
    mapping(bytes32 => bytes32) public publicKeyToRandomness;

    constructor(address _verifier, bytes memory _phi) {
        verifier = StateMachineVerifier(_verifier);
        phi = _phi;
    }

    function getCurrentState() public view returns (bytes memory) {
        return phi;
    }

    function deposit(bytes calldata _publicValues, bytes calldata _proofBytes) public payable {
        (bytes memory old_phi, bytes memory next_phi, uint256 amount, bytes32 pkey, bytes32 v) = verifier.verifyStateMachineDepositProof(_publicValues, _proofBytes);
        require(keccak256(old_phi) == keccak256((phi)), "current state does not match");
        require(amount == msg.value, "amount must be greater than 0");
        phi = next_phi;
        publicKeyToRandomness[pkey] = v;
    }

    function send(bytes calldata _publicValues, bytes calldata _proofBytes) public {
        (bytes memory old_phi, bytes memory next_phi) = verifier.verifyStateMachineSendProof(_publicValues, _proofBytes);
        require(keccak256(old_phi) == keccak256((phi)), "current state does not match");
        phi = next_phi;
    }

    function withdraw(bytes calldata _publicValues, bytes calldata _proofBytes) public {
        (bytes memory old_phi, bytes memory next_phi, uint256 amount, address recipient) = verifier.verifyStateMachineWithdrawProof(_publicValues, _proofBytes);
        require(keccak256(old_phi) == keccak256((phi)), "current state does not match");
        require(amount <= address(this).balance, "insufficient balance");
        payable(recipient).transfer(amount);
        phi = next_phi;
    }

    function rotate(bytes calldata _publicValues, bytes calldata _proofBytes) public {
        (bytes memory old_phi, bytes memory next_phi, bytes32 pubkey, bytes32 new_t) = verifier.verifyStateMachineRotateProof(_publicValues, _proofBytes);
        require(keccak256(old_phi) == keccak256((phi)), "current state does not match");
        publicKeyToRandomness[pubkey] = new_t;
        phi = next_phi;
    }
}