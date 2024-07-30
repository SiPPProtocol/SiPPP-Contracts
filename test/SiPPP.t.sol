// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {SiPPP} from "../src/SiPPP.sol";
import {RecoverMessage} from "../src/RecoverMessage.sol";

contract SiPPPTest is Test {
    SiPPP public sippp;

    address private admin = vm.addr(uint256(keccak256("ADMIN")));
    address private app = vm.addr(uint256(keccak256("APP")));
    address private newApp = vm.addr(uint256(keccak256("NEW_APP")));
    address private badApp = vm.addr(uint256(keccak256("BAD_APP")));
    address private userWallet = vm.addr(uint256(keccak256("USER_WALLET")));
    address private treasury = vm.addr(uint256(keccak256("TREASURY")));

    uint256 farcasterId = 12345;
    address primaryAccount = vm.addr(uint256(keccak256("PRIMARY_ACCOUNT")));
    string name;
    string email;

    bytes encodedUserData;

    // SiPPP.UserDevice device = SiPPP.UserDevice({
    //     deviceId: 1,
    //     user: userWallet,
    //     make: "Test Make",
    //     model: "Test Model",
    //     serialNumber: "1234567890"
    // });

    // bytes encodedUserDevice = abi.encode(device);

    function setUp() public {
        vm.startPrank(admin);
        sippp = new SiPPP(admin, app, payable(treasury));
        sippp.updatePubAddy(app);

        name = "Test User";
        email = "test@example.com";

        encodedUserData = abi.encode(userWallet, farcasterId, primaryAccount, name, email);
        vm.stopPrank();
    }

    function test_deploySippp() public view {
        assertEq(sippp.admin(), admin, "Admin should match");
        assertNotEq(sippp.appAddress(), address(0), "Public address should not be zero address");
        assertEq(sippp.treasury(), payable(treasury), "Treasury should match");
    }

    function testVerifyApp() public {
        string memory message = "Test message";
        bytes32 messageHash = keccak256(abi.encodePacked(message));

        // Mock the signature using the private key of the publicAddy
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(uint160(app)), messageHash);
        bytes memory rawSig = abi.encodePacked(r, s, v);

        // Mock the recoverStringFromRaw function to return the publicAddy
        vm.mockCall(
            address(sippp),
            abi.encodeWithSelector(RecoverMessage.recoverStringFromRaw.selector, message, rawSig),
            abi.encode(app)
        );

        bool result = sippp.verifyApp(message, rawSig);

        assertTrue(result, "The app address should be verified");
    }

    function test_updatePublicAppAddress() public {
        vm.prank(admin);
        sippp.updatePubAddy(app);

        assertEq(sippp.appAddress(), app, "Public address should match");
    }

    function test_revert_updatePublicAppAddress_NotAdmin() public {
        vm.expectRevert(SiPPP.OnlyAdmin.selector);
        sippp.updatePubAddy(app);
    }

    function test_revert_updatePublicAppAddress_ZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(SiPPP.ZeroAddress.selector);
        sippp.updatePubAddy(address(0));
    }

    //     function test_revokeAppRole() public {
    //         vm.prank(admin);
    //         sippp.revokeAppRole(badApp);

    //         bool hasRole = sippp.hasRole(sippp.APP_BANNED(), badApp);
    //         assertTrue(hasRole, "Bad app should have APP_BANNED");
    //     }

    //     function test_registerUser() public {
    //         vm.prank(app);
    //         sippp.registerUser(encodedUserData);

    //         SiPPPProvenance.UserAccount memory registeredUser = sippp.getUserAccount(userWallet);

    //         assertEq(registeredUser.farcasterId, farcasterId, "Farcaster ID should match");
    //         assertEq(registeredUser.primaryAccount, primaryAccount, "Primary account should match");
    //         assertEq(registeredUser.name, name, "Name should match");
    //         assertEq(registeredUser.email, email, "Email should match");
    //     }

    //     function test_registerDevice() public {
    //         vm.prank(app);
    //         sippp.registerUser(encodedUserData);

    //         vm.prank(app);
    //         sippp.registerDevice(userWallet, encodedUserDevice);

    //         SiPPPProvenance.UserDevice memory registeredDevice = sippp.getUserDevice(userWallet, device.deviceId);

    //         assertEq(registeredDevice.deviceId, device.deviceId, "Device ID should match");
    //         assertEq(registeredDevice.user, device.user, "User should match");
    //         assertEq(registeredDevice.make, device.make, "Make should match");
    //         assertEq(registeredDevice.model, device.model, "Model should match");
    //         assertEq(registeredDevice.serialNumber, device.serialNumber, "Serial number should match");
    //     }

    //     function test_revert_registerDevice_userNotRegistered() public {
    //         vm.prank(app);
    //         vm.expectRevert(SiPPPProvenance.UserNotRegistered.selector);
    //         sippp.registerDevice(userWallet, encodedUserDevice);
    //     }

    //     function test_registerPhoto() public {
    //         vm.prank(app);
    //         sippp.registerUser(encodedUserData);

    //         vm.prank(app);
    //         sippp.registerDevice(userWallet, encodedUserDevice);

    //         SiPPPProvenance.PhotoProvenance memory photo = SiPPPProvenance.PhotoProvenance({
    //             deviceId: 1,
    //             timestamp: block.timestamp,
    //             location: "Test Location",
    //             seedPhrase: "Test Seed Phrase",
    //             seedAlgorithm: "Test Algorithm",
    //             user: userWallet,
    //             photoHash: keccak256(abi.encodePacked("Test Photo")),
    //             algoConfirmed: false
    //         });

    //         bytes memory encodedPhoto = abi.encode(photo);

    //         vm.prank(app);
    //         sippp.registerPhoto(userWallet, photo.deviceId, encodedPhoto);

    //         (
    //             uint256 deviceId,
    //             uint256 timestamp,
    //             string memory location,
    //             string memory seedPhrase,
    //             string memory seedAlgorithm,
    //             address user,
    //             bytes32 photoHash,
    //             bool algoConfirmed
    //         ) = sippp.userPhotos(userWallet, photo.photoHash);

    //         assertEq(deviceId, photo.deviceId, "Device ID should match");
    //         assertEq(timestamp, photo.timestamp, "Timestamp should match");
    //         assertEq(location, photo.location, "Location should match");
    //         assertEq(seedPhrase, photo.seedPhrase, "Seed phrase should match");
    //         assertEq(seedAlgorithm, photo.seedAlgorithm, "Seed algorithm should match");
    //         assertEq(user, photo.user, "User should match");
    //         assertEq(photoHash, photo.photoHash, "Photo hash should match");
    //         assertEq(algoConfirmed, photo.algoConfirmed, "Algo confirmed should match");
    //     }

    //     function test_revert_registerPhoto_userNotRegistered() public {
    //         vm.prank(app);

    //         sippp.registerUser(encodedUserData);

    //         SiPPPProvenance.PhotoProvenance memory photo = SiPPPProvenance.PhotoProvenance({
    //             deviceId: 1,
    //             timestamp: block.timestamp,
    //             location: "Test Location",
    //             seedPhrase: "Test Seed Phrase",
    //             seedAlgorithm: "Test Algorithm",
    //             user: userWallet,
    //             photoHash: keccak256(abi.encodePacked("Test Photo")),
    //             algoConfirmed: false
    //         });

    //         bytes memory encodedPhoto = abi.encode(photo);

    //         vm.prank(app);
    //         vm.expectRevert(SiPPPProvenance.DeviceNotRegistered.selector);
    //         sippp.registerPhoto(userWallet, photo.deviceId, encodedPhoto);

    //         (
    //             uint256 deviceId,
    //             uint256 timestamp,
    //             string memory location,
    //             string memory seedPhrase,
    //             string memory seedAlgorithm,
    //             address user,
    //             bytes32 photoHash,
    //             bool algoConfirmed
    //         ) = sippp.userPhotos(userWallet, photo.photoHash);
    //     }
}
