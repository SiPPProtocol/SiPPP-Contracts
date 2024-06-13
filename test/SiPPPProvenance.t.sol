// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {SiPPPProvenance} from "src/SiPPPProvenance.sol";

contract SiPPPProvenanceTest is Test {
    SiPPPProvenance public sippp;

    address private admin = vm.addr(uint256(keccak256("ADMIN")));
    address private app = vm.addr(uint256(keccak256("APP")));

    function setUp() public {
        sippp = new SiPPPProvenance(admin, app);
    }
}
