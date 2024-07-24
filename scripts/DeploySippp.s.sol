// SPDX-License-Identifier: MIT

pragma solidity ^0.8.21;

import {SiPPP} from "../src/SiPPP.sol";

contract DeploySippp {
    function run() external {
        vm.startBroadcast();

        SiPPP sippp = new SiPPP();
        console.log("SiPPP deployed to:", sippp);

        vm.stopBroadcast();
    }
}