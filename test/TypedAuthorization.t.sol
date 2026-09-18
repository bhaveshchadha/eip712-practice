// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {TypedAuthorization} from "../src/TypedAuthorization.sol";

contract CounterTest is Test {
    TypedAuthorization public authorization;

    function setUp() public {
        authorization = new TypedAuthorization();
    }
}
