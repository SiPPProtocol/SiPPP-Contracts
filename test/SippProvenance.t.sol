// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import "src/SippProvenance.sol";

contract CounterTest is Test {
    SippProvenance public sipp;

    address private admin = vm.addr(uint256(keccak256("ADMIN")));
    address private app = vm.addr(uint256(keccak256("APP")));

    function setUp() public {
        sipp = new SippProvenance(admin,app);
    }

    function test_Increment() public {
        counter.increment();
        assertEq(counter.number(), 1);
    }

    function testFuzz_SetNumber(uint256 x) public {
        counter.setNumber(x);
        assertEq(counter.number(), x);
    }
}
