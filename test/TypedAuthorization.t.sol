// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {TypedAuthorization} from "../src/TypedAuthorization.sol";

contract CounterTest is Test {
    TypedAuthorization authorizationA;
    TypedAuthorization authorizationB;

    uint256 userPrivateKey;
    address user;
    address recipient;
    function setUp() public {
        userPrivateKey = vm.envUint("PRIVATE_KEY");
        user = vm.addr(userPrivateKey);
        // authorization = new TypedAuthorization();
        authorizationA = new TypedAuthorization();
        authorizationB = new TypedAuthorization();

        vm.deal(address(authorizationA), 10 ether);
        vm.deal(address(authorizationB), 10 ether);
    }

    function _authorization(
        uint256 amount,
        uint256 authNonce,
        uint256 deadline
    ) internal view returns (TypedAuthorization.Authorization memory) {
        return
            TypedAuthorization.Authorization({
                user: user,
                recipient: recipient,
                amount: amount,
                nonce: authNonce,
                deadline: deadline
            });
    }

    function _digest(
        TypedAuthorization contract_,
        TypedAuthorization.Authorization memory auth
    ) internal view returns (bytes32) {
        bytes32 typeHash = keccak256(
            "Authorization(address user,address recipient,uint256 amount,uint256 nonce,uint256 deadline)"
        );

        bytes32 structHash = keccak256(
            abi.encode(
                typeHash,
                auth.user,
                auth.recipient,
                auth.amount,
                auth.nonce,
                auth.deadline
            )
        );

        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    contract_.DOMAIN_SEPARATOR(),
                    structHash
                )
            );
    }

    function _sign(
        TypedAuthorization contract_,
        TypedAuthorization.Authorization memory auth
    ) internal returns (bytes memory) {
        bytes32 digest = _digest(contract_, auth);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);

        return abi.encodePacked(r, s, v);
    }

    function test_ValidSignature() public {
        TypedAuthorization.Authorization memory auth = _authorization(
            1 ether,
            0,
            block.timestamp + 1 days
        );

        bytes memory signature = _sign(authorizationA, auth);

        uint256 beforeBalance = recipient.balance;

        authorizationA.execute(auth, signature);

        assertEq(recipient.balance, beforeBalance + 1 ether);
        assertEq(authorizationA.nonce(user), 1);
    }

    function test_WrongSigner() public {
        TypedAuthorization.Authorization memory auth = _authorization(
            1 ether,
            0,
            block.timestamp + 1 days
        );

        bytes32 digest = _digest(authorizationA, auth);

        uint256 wrongPrivateKey = 99999;

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, digest);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("Invalid signer");

        authorizationA.execute(auth, signature);
    }

    function test_ModifiedRecepient() public {
        TypedAuthorization.Authorization memory auth = _authorization(
            1 ether,
            0,
            block.timestamp + 1 days
        );

        bytes memory signature = _sign(authorizationA, auth);

        vm.expectRevert("Invalid signer");

        authorizationA.execute(
            TypedAuthorization.Authorization({
                user: user,
                recipient: makeAddr("attacker"),
                amount: 1 ether,
                nonce: 0,
                deadline: block.timestamp + 1 days
            }),
            signature
        );
    }
    function test_ModifiedAmount() public {
        TypedAuthorization.Authorization memory auth = _authorization(
            1 ether,
            0,
            block.timestamp + 1 days
        );

        bytes memory signature = _sign(authorizationA, auth);

        vm.expectRevert("Invalid signer");

        authorizationA.execute(
            _authorization(2 ether, 0, block.timestamp + 1 days),
            signature
        );
    }
}
