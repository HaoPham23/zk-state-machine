// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {StateMachine} from "../src/StateMachine.sol";
import {StateMachineVerifier} from "../src/StateMachineVerifier.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";

struct SP1ProofDepositFixtureJson {
    bytes old_phi;
    bytes next_phi;
    uint64 amount;
    bytes32 pkey;
    bytes32 v;
    bytes32 vkey;
    bytes publicValues;
    bytes proof;
}

contract StateMachineGroth16Test is Test {
    using stdJson for string;

    address verifier;
    StateMachineVerifier public stateMachineVerifier;
    StateMachine public stateMachine;

    function loadFixture() public view returns (SP1ProofDepositFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/groth16-zk-state-machine-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        console.logBytes(jsonBytes);
        return abi.decode(jsonBytes, (SP1ProofDepositFixtureJson));
    }

    function setUp() public {
        SP1ProofDepositFixtureJson memory fixture = loadFixture();

        verifier = address(new SP1VerifierGateway(address(1)));
        stateMachineVerifier = new StateMachineVerifier(verifier, fixture.vkey);
        stateMachine = new StateMachine(address(stateMachineVerifier), fixture.old_phi);
    }

    function test() public {}

    // function test_ValidStateMachineVerifierProof() public {
    //     SP1ProofDepositFixtureJson memory fixture = loadFixture();

    //     vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

    //     (bytes memory old_phi, bytes memory next_phi, uint256 amount, bytes32 pkey, bytes32 v) = stateMachineVerifier.verifyStateMachineDepositProof(fixture.publicValues, fixture.proof);
    //     assert(keccak256(old_phi) == keccak256(fixture.old_phi));
    //     assert(keccak256(next_phi) == keccak256(fixture.next_phi));
    //     assert(amount == fixture.amount);
    //     assert(pkey == fixture.pkey);
    //     assert(v == fixture.v);
    // }

    // function testFail_InvalidStateMachineVerifierProof() public view {
    //     SP1ProofDepositFixtureJson memory fixture = loadFixture();

    //     // Create a fake proof.
    //     bytes memory fakeProof = new bytes(fixture.proof.length);

    //     stateMachineVerifier.verifyStateMachineDepositProof(fixture.publicValues, fakeProof);
    // }
}
