// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Script} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {StateMachine} from "../src/StateMachine.sol";
import {StateMachineVerifier} from "../src/StateMachineVerifier.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";
import {SP1Verifier as SP1VerifierGroth16} from "@sp1-contracts/v4.0.0-rc.3/SP1VerifierGroth16.sol";
import {SP1Verifier as SP1VerifierPlonk} from "@sp1-contracts/v4.0.0-rc.3/SP1VerifierPlonk.sol";
import {SP1ProofDepositFixtureJson} from "../test/StateMachine.t.sol";

contract StateMachineDeploy is Script {
    StateMachine stateMachine;
    StateMachineVerifier verifier;

    function run() public {
        address gateway = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;
        SP1ProofDepositFixtureJson memory fixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-a.json");
        vm.createSelectFork("sepolia");
        vm.startBroadcast();
        verifier = new StateMachineVerifier(gateway, fixture.vkey);
        stateMachine = new StateMachine(address(verifier), fixture.old_phi);
        vm.stopBroadcast();
    }

    function loadFixtureDeposit(string memory relativePath) public view returns (SP1ProofDepositFixtureJson memory) {
        bytes memory jsonBytes = loadFixture(relativePath);
        return abi.decode(jsonBytes, (SP1ProofDepositFixtureJson));
    }

    function loadFixture(string memory relativePath) public view returns (bytes memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, relativePath);
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = vm.parseJson(json);
        return jsonBytes;
    }

}