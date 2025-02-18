// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

struct PublicValuesDeposit {
    bytes old_phi;
    bytes next_phi;
    uint256 amount;
    bytes32 pkey;
    bytes32 t;
}

struct PublicValuesSend {
    bytes old_phi;
    bytes next_phi;
}

struct PublicValuesWithdraw {
    bytes old_phi;
    bytes next_phi;
    uint256 amount;
    address recipient;
}

struct PublicValuesRotate {
    bytes old_phi;
    bytes next_phi;
    bytes32 new_t;
    bytes32 pkey;
}

contract StateMachineVerifier {
    /// @notice The address of the SP1 verifier contract.
    /// @dev This can either be a specific SP1Verifier for a specific version, or the
    ///      SP1VerifierGateway which can be used to verify proofs for any version of SP1.
    ///      For the list of supported verifiers on each chain, see:
    ///      https://github.com/succinctlabs/sp1-contracts/tree/main/contracts/deployments
    address public verifier;

    /// @notice The verification key for the fibonacci program.
    bytes32 public stateMachineProgramVKey;

    constructor(address _verifier, bytes32 _stateMachineProgramVKey) {
        verifier = _verifier;
        stateMachineProgramVKey = _stateMachineProgramVKey;
    }

    function verifyStateMachineDepositProof(bytes calldata _publicValues, bytes calldata _proofBytes)
        public
        view
        returns (bytes memory, bytes memory, uint256, bytes32, bytes32)
    {
        ISP1Verifier(verifier).verifyProof(stateMachineProgramVKey, _publicValues, _proofBytes);
        PublicValuesDeposit memory publicValues = abi.decode(_publicValues, (PublicValuesDeposit));
        return (publicValues.old_phi, publicValues.next_phi, publicValues.amount, publicValues.pkey, publicValues.t);
    }

    function verifyStateMachineSendProof(bytes calldata _publicValues, bytes calldata _proofBytes)
        public
        view
        returns (bytes memory, bytes memory)
    {
        ISP1Verifier(verifier).verifyProof(stateMachineProgramVKey, _publicValues, _proofBytes);
        PublicValuesSend memory publicValues = abi.decode(_publicValues, (PublicValuesSend));
        return (publicValues.old_phi, publicValues.next_phi);
    }

    function verifyStateMachineWithdrawProof(bytes calldata _publicValues, bytes calldata _proofBytes)
        public
        view
        returns (bytes memory, bytes memory, uint256, address)
    {
        ISP1Verifier(verifier).verifyProof(stateMachineProgramVKey, _publicValues, _proofBytes);
        PublicValuesWithdraw memory publicValues = abi.decode(_publicValues, (PublicValuesWithdraw));
        return (publicValues.old_phi, publicValues.next_phi, publicValues.amount, publicValues.recipient);
    }

    function verifyStateMachineRotateProof(bytes calldata _publicValues, bytes calldata _proofBytes)
        public
        view
        returns (bytes memory, bytes memory, bytes32, bytes32)
    {
        ISP1Verifier(verifier).verifyProof(stateMachineProgramVKey, _publicValues, _proofBytes);
        PublicValuesRotate memory publicValues = abi.decode(_publicValues, (PublicValuesRotate));
        return (publicValues.old_phi, publicValues.next_phi, publicValues.pkey, publicValues.new_t);
    }
}