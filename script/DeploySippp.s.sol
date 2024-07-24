// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {SiPPP} from "../src/SiPPP.sol";

contract DeploySippp is Script {
    address public admin = 0x796A25e6f79043Add7F63735F80472129e77B009;
    address payable public treasury = payable(0x796A25e6f79043Add7F63735F80472129e77B009);
    address public publicAddress = 0x796A25e6f79043Add7F63735F80472129e77B009;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        SiPPP sippp = new SiPPP(admin, publicAddress, treasury);

        console.logAddress(address(sippp));

        vm.stopBroadcast();
    }
}

// forge script script/DeploySippp.s.sol:DeploySippp -vvvv --rpc-url $RPC_URL --broadcast --verify
