// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {SiPPPProvenance} from "../src/SiPPPProvenance.sol";

contract SiPPPProvenanceTest is Test {
    SiPPPProvenance public sippp;

    address private admin = vm.addr(uint256(keccak256("ADMIN")));
    address private app = vm.addr(uint256(keccak256("APP")));
    address private newApp = vm.addr(uint256(keccak256("NEW_APP")));
    address private badApp = vm.addr(uint256(keccak256("BAD_APP")));
    address private userWallet = vm.addr(uint256(keccak256("USER_WALLET")));

    uint256 farcasterId = 12345;
    address primaryAccount = vm.addr(uint256(keccak256("PRIMARY_ACCOUNT")));
    string name;
    string email;

    bytes encodedUserData;

    SiPPPProvenance.UserDevice device = SiPPPProvenance.UserDevice({
        deviceId: 1,
        user: userWallet,
        make: "Test Make",
        model: "Test Model",
        serialNumber: "1234567890"
    });

    bytes encodedUserDevice = abi.encode(device);

    function setUp() public {
        vm.prank(admin);
        sippp = new SiPPPProvenance(admin, app);
        vm.prank(admin);
        sippp.grantAppRole(app);

        name = "Test User";
        email = "test@example.com";

        encodedUserData = abi.encode(userWallet, farcasterId, primaryAccount, name, email);
    }

    function test_grantAppRole() public {
        vm.prank(admin);
        sippp.grantAppRole(newApp);

        bool hasRole = sippp.hasRole(sippp.APP_ROLE(), newApp);
        assertTrue(hasRole, "New app should have APP_ROLE");
    }

    function test_revokeAppRole() public {
        vm.prank(admin);
        sippp.revokeAppRole(badApp);

        bool hasRole = sippp.hasRole(sippp.APP_BANNED(), badApp);
        assertTrue(hasRole, "Bad app should have APP_BANNED");
    }

    function test_registerUser() public {
        vm.prank(app);
        sippp.registerUser(encodedUserData);

        SiPPPProvenance.UserAccount memory registeredUser = sippp.getUserAccount(userWallet);

        assertEq(registeredUser.farcasterId, farcasterId, "Farcaster ID should match");
        assertEq(registeredUser.primaryAccount, primaryAccount, "Primary account should match");
        assertEq(registeredUser.name, name, "Name should match");
        assertEq(registeredUser.email, email, "Email should match");
    }

    function test_registerDevice() public {
        vm.prank(app);
        sippp.registerUser(encodedUserData);

        vm.prank(app);
        sippp.registerDevice(userWallet, encodedUserDevice);

        SiPPPProvenance.UserDevice memory registeredDevice = sippp.getUserDevice(userWallet, device.deviceId);

        assertEq(registeredDevice.deviceId, device.deviceId, "Device ID should match");
        assertEq(registeredDevice.user, device.user, "User should match");
        assertEq(registeredDevice.make, device.make, "Make should match");
        assertEq(registeredDevice.model, device.model, "Model should match");
        assertEq(registeredDevice.serialNumber, device.serialNumber, "Serial number should match");
    }

    function test_revert_registerDevice_userNotRegistered() public {
        vm.prank(app);
        vm.expectRevert(SiPPPProvenance.UserNotRegistered.selector);
        sippp.registerDevice(userWallet, encodedUserDevice);
    }

    function test_registerPhoto() public {
        vm.prank(app);
        sippp.registerUser(encodedUserData);

        vm.prank(app);
        sippp.registerDevice(userWallet, encodedUserDevice);

        SiPPPProvenance.PhotoProvenance memory photo = SiPPPProvenance.PhotoProvenance({
            deviceId: 1,
            timestamp: block.timestamp,
            location: "Test Location",
            seedPhrase: "Test Seed Phrase",
            seedAlgorithm: "Test Algorithm",
            user: userWallet,
            photoHash: keccak256(abi.encodePacked("Test Photo")),
            algoConfirmed: false
        });

        bytes memory encodedPhoto = abi.encode(photo);

        vm.prank(app);
        sippp.registerPhoto(userWallet, photo.deviceId, encodedPhoto);

        (
            uint256 deviceId,
            uint256 timestamp,
            string memory location,
            string memory seedPhrase,
            string memory seedAlgorithm,
            address user,
            bytes32 photoHash,
            bool algoConfirmed
        ) = sippp.userPhotos(userWallet, photo.photoHash);

        assertEq(deviceId, photo.deviceId, "Device ID should match");
        assertEq(timestamp, photo.timestamp, "Timestamp should match");
        assertEq(location, photo.location, "Location should match");
        assertEq(seedPhrase, photo.seedPhrase, "Seed phrase should match");
        assertEq(seedAlgorithm, photo.seedAlgorithm, "Seed algorithm should match");
        assertEq(user, photo.user, "User should match");
        assertEq(photoHash, photo.photoHash, "Photo hash should match");
        assertEq(algoConfirmed, photo.algoConfirmed, "Algo confirmed should match");
    }

    function test_revert_registerPhoto_userNotRegistered() public {
        vm.prank(app);

        sippp.registerUser(encodedUserData);

        SiPPPProvenance.PhotoProvenance memory photo = SiPPPProvenance.PhotoProvenance({
            deviceId: 1,
            timestamp: block.timestamp,
            location: "Test Location",
            seedPhrase: "Test Seed Phrase",
            seedAlgorithm: "Test Algorithm",
            user: userWallet,
            photoHash: keccak256(abi.encodePacked("Test Photo")),
            algoConfirmed: false
        });

        bytes memory encodedPhoto = abi.encode(photo);

        vm.prank(app);
        vm.expectRevert(SiPPPProvenance.DeviceNotRegistered.selector);
        sippp.registerPhoto(userWallet, photo.deviceId, encodedPhoto);

        (
            uint256 deviceId,
            uint256 timestamp,
            string memory location,
            string memory seedPhrase,
            string memory seedAlgorithm,
            address user,
            bytes32 photoHash,
            bool algoConfirmed
        ) = sippp.userPhotos(userWallet, photo.photoHash);
    }
}
