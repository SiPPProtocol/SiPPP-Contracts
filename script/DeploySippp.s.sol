// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {SiPPP} from "../src/SiPPP.sol";

contract DeploySippp is Script {
    address public admin = 0x2C80552A6f2FD1b32d7783E4c5086899da3933b8;
    address payable public treasury = payable(0x2C80552A6f2FD1b32d7783E4c5086899da3933b8);
    address public publicAddress = 0x2C80552A6f2FD1b32d7783E4c5086899da3933b8;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        SiPPP sippp = new SiPPP(admin, publicAddress, treasury);

        console.logAddress(address(sippp));

        vm.stopBroadcast();
    }
}

// forge script script/DeploySippp.s.sol:DeploySippp -vvvv --rpc-url $RPC_URL --broadcast --verify
