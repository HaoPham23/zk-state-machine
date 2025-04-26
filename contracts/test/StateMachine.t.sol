// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {StateMachine} from "../src/StateMachine.sol";
import {StateMachineVerifier} from "../src/StateMachineVerifier.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";
import {SP1Verifier as SP1VerifierGroth16} from "@sp1-contracts/v4.0.0-rc.3/SP1VerifierGroth16.sol";
import {SP1Verifier as SP1VerifierPlonk} from "@sp1-contracts/v4.0.0-rc.3/SP1VerifierPlonk.sol";

struct SP1ProofDepositFixtureJson {
    uint64 amount;
    bytes next_phi;
    bytes old_phi;
    bytes32 pkey;
    bytes proof;
    bytes public_values;
    bytes32 t;
    bytes32 vkey;
}

struct SP1ProofSendFixtureJson {
    bytes next_phi;
    bytes old_phi;
    bytes proof;
    bytes public_values;
    bytes32 vkey;
}

struct SP1ProofWithdrawFixtureJson {
    uint64 amount;
    bytes next_phi;
    bytes old_phi;
    bytes proof;
    bytes public_values;
    address recipient;
    bytes32 vkey;
}

struct SP1ProofRotateFixtureJson {
    bytes32 new_t;
    bytes next_phi;
    bytes old_phi;
    bytes32 pkey;
    bytes proof;
    bytes public_values;
    bytes32 vkey;
}

contract StateMachineGroth16Test is Test {
    using stdJson for string;

    address gateway;
    address owner;
    SP1VerifierGroth16 verifierGroth16;
    SP1VerifierPlonk verifierPlonk;
    StateMachineVerifier public stateMachineVerifier;
    StateMachine public stateMachine;

    function loadFixture(string memory relativePath) public view returns (bytes memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, relativePath);
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = vm.parseJson(json);
        return jsonBytes;
    }

    function loadFixtureDeposit(string memory relativePath) public view returns (SP1ProofDepositFixtureJson memory) {
        bytes memory jsonBytes = loadFixture(relativePath);
        return abi.decode(jsonBytes, (SP1ProofDepositFixtureJson));
    }

    function loadFixtureSend() public view returns (SP1ProofSendFixtureJson memory) {
        bytes memory jsonBytes = loadFixture("/src/fixtures/groth16-zk-state-machine-fixture-send.json");
        return abi.decode(jsonBytes, (SP1ProofSendFixtureJson));
    }

    function loadFixtureWithdraw() public view returns (SP1ProofWithdrawFixtureJson memory) {
        bytes memory jsonBytes = loadFixture("/src/fixtures/groth16-zk-state-machine-fixture-withdraw.json");
        return abi.decode(jsonBytes, (SP1ProofWithdrawFixtureJson));
    }

    function loadFixtureRotate() public view returns (SP1ProofRotateFixtureJson memory) {
        bytes memory jsonBytes = loadFixture("/src/fixtures/groth16-zk-state-machine-fixture-rotate.json");
        return abi.decode(jsonBytes, (SP1ProofRotateFixtureJson));
    }

    function setUp() public {
        SP1ProofDepositFixtureJson memory fixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-a.json");
        if (block.chainid == 31337) {
            verifierGroth16 = new SP1VerifierGroth16();
            verifierPlonk = new SP1VerifierPlonk();
            owner = makeAddr("owner");
            gateway = address(new SP1VerifierGateway(owner));
            vm.startPrank(owner);
            SP1VerifierGateway(gateway).addRoute(address(verifierGroth16));
            SP1VerifierGateway(gateway).addRoute(address(verifierPlonk));
            stateMachineVerifier = new StateMachineVerifier(gateway, fixture.vkey);
            stateMachine = new StateMachine(address(stateMachineVerifier), fixture.old_phi);
            vm.stopPrank();
        } else if (block.chainid == 11155111) {
            owner = 0xCafEf00d348Adbd57c37d1B77e0619C6244C6878;
            gateway = 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B;
            stateMachineVerifier = StateMachineVerifier(0x51BcB68D81C3d167deb2c913E5de5478B40A1a77);
            stateMachine = StateMachine(0x62F3cC26FB8e8B06aC13274f1728EdcBd1fac921);
        }        
    }

    function test_setup_gateway() public {
        if (block.chainid != 31337) {
            return;
        }
        assertEq(SP1VerifierGateway(gateway).owner(), owner);

        bytes4 selectorGroth16 = bytes4(verifierGroth16.VERIFIER_HASH());
        (address verifier, bool frozen) = SP1VerifierGateway(gateway).routes(selectorGroth16);
        assertEq(verifier, address(verifierGroth16));
        assertEq(frozen, false);

        bytes4 selectorPlonk = bytes4(verifierPlonk.VERIFIER_HASH());
        (verifier, frozen) = SP1VerifierGateway(gateway).routes(selectorPlonk);
        assertEq(verifier, address(verifierPlonk));
        assertEq(frozen, false);
    }

    function test_ValidStateMachineVerifierProof() public {
        SP1ProofDepositFixtureJson memory fixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-a.json");

        (bytes memory old_phi, bytes memory next_phi, uint256 amount, bytes32 pkey, bytes32 t) = stateMachineVerifier.verifyStateMachineDepositProof(fixture.public_values, fixture.proof);
        assert(keccak256(old_phi) == keccak256(fixture.old_phi));
        assert(keccak256(next_phi) == keccak256(fixture.next_phi));
        assert(amount == fixture.amount);
        assert(pkey == fixture.pkey);
        assert(t == fixture.t);
    }

    function test_InvalidStateMachineVerifierProof() public {
        SP1ProofDepositFixtureJson memory fixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-a.json");

        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);
        vm.expectRevert();
        stateMachineVerifier.verifyStateMachineDepositProof(fixture.public_values, fakeProof);
    }

    function test_deposit_valid_proof_valid_amount() public {
        SP1ProofDepositFixtureJson memory fixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-a.json");

        address user = makeAddr("user");
        uint256 amount = 100;
        vm.deal(user, amount);
        vm.prank(user);
        stateMachine.deposit{value: amount}(fixture.public_values, fixture.proof);
        assertEq(stateMachine.getCurrentState(), fixture.next_phi);
        assertEq(address(stateMachine).balance, amount);
    }

    function test_deposit_valid_proof_invalid_amount() public {
        SP1ProofDepositFixtureJson memory fixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-a.json");

        address user = makeAddr("user");
        uint256 amount = 100;
        vm.deal(user, amount + 1);
        vm.prank(user);
        vm.expectRevert();
        stateMachine.deposit{value: amount + 1}(fixture.public_values, fixture.proof);
    }

    function test_send_valid_proof() public {
        SP1ProofDepositFixtureJson memory depositAFixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-a.json");
        SP1ProofDepositFixtureJson memory depositBFixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-b.json");
        SP1ProofSendFixtureJson memory fixture = loadFixtureSend();

        address userA = makeAddr("userA");
        uint256 amountA = 100;
        vm.deal(userA, amountA);
        vm.prank(userA);
        stateMachine.deposit{value: amountA}(depositAFixture.public_values, depositAFixture.proof);

        address userB = makeAddr("userB");
        uint256 amountB = 200;
        vm.deal(userB, amountB);
        vm.prank(userB);
        stateMachine.deposit{value: amountB}(depositBFixture.public_values, depositBFixture.proof);

        address relayer = makeAddr("relayer");
        vm.prank(relayer);
        stateMachine.send(fixture.public_values, fixture.proof);
        assertEq(stateMachine.getCurrentState(), fixture.next_phi);
    }

    function test_withdraw_valid_proof() public {
        // Setup
        SP1ProofDepositFixtureJson memory depositAFixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-a.json");
        SP1ProofDepositFixtureJson memory depositBFixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-b.json");
        SP1ProofSendFixtureJson memory sendFixture = loadFixtureSend();
        SP1ProofWithdrawFixtureJson memory fixture = loadFixtureWithdraw();

        // User A deposit 100 coins
        address userA = makeAddr("userA");
        uint256 amountA = 100;
        vm.deal(userA, amountA);
        vm.prank(userA);
        stateMachine.deposit{value: amountA}(depositAFixture.public_values, depositAFixture.proof);

        // User B deposit 200 coins
        address userB = makeAddr("userB");
        uint256 amountB = 200;
        vm.deal(userB, amountB);
        vm.prank(userB);
        stateMachine.deposit{value: amountB}(depositBFixture.public_values, depositBFixture.proof);

        // User B secretly send 30 coins to User A, submit by relayer
        address relayer = makeAddr("relayer");
        vm.prank(relayer);
        stateMachine.send(sendFixture.public_values, sendFixture.proof);
        
        // User A secretly withdraw 10 coins to new address (recipient), submit by relayer
        vm.prank(relayer);
        stateMachine.withdraw(fixture.public_values, fixture.proof);
        assertEq(stateMachine.getCurrentState(), fixture.next_phi);

        address recipient = fixture.recipient;
        assertEq(recipient.balance, fixture.amount);
    }

    function test_rotate_valid_proof() public {
        // Setup
        SP1ProofDepositFixtureJson memory depositAFixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-a.json");
        SP1ProofDepositFixtureJson memory depositBFixture = loadFixtureDeposit("/src/fixtures/groth16-zk-state-machine-fixture-deposit-b.json");
        SP1ProofSendFixtureJson memory sendFixture = loadFixtureSend();
        SP1ProofWithdrawFixtureJson memory withdrawFixture = loadFixtureWithdraw();
        SP1ProofRotateFixtureJson memory fixture = loadFixtureRotate();

        // User A deposit 100 coins
        address userA = makeAddr("userA");
        uint256 amountA = 100;
        vm.deal(userA, amountA);
        vm.prank(userA);
        stateMachine.deposit{value: amountA}(depositAFixture.public_values, depositAFixture.proof);

        // User B deposit 200 coins
        address userB = makeAddr("userB");
        uint256 amountB = 200;
        vm.deal(userB, amountB);
        vm.prank(userB);
        stateMachine.deposit{value: amountB}(depositBFixture.public_values, depositBFixture.proof);

        // User B secretly send 30 coins to User A, submit by relayer
        address relayer = makeAddr("relayer");
        vm.prank(relayer);
        stateMachine.send(sendFixture.public_values, sendFixture.proof);
        
        // User A secretly withdraw 10 coins to new address (recipient), submit by relayer
        vm.prank(relayer);
        stateMachine.withdraw(withdrawFixture.public_values, withdrawFixture.proof);

        vm.prank(relayer);
        stateMachine.rotate(fixture.public_values, fixture.proof);
        assertEq(stateMachine.getCurrentState(), fixture.next_phi);
    }
}
