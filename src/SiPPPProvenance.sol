// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Open Zeppelin
import "@openzeppelin/contracts/access/AccessControl.sol";
// import "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// import {Privy} from "./Privy.sol";

/// @title SippProvenance
/// @author Aphilos.eth
/// @notice This contract is designed to work with the SiPPP mobile app to
///         1. Hold data that provides provenance for every photo taken by the app
///         2. Provides functions that enable any user to verify the authenticity of a photo
contract SiPPPProvenance is AccessControl {
    error OnlyAdmin();
    error UserExists();
    error UserNotRegistered();
    error DeviceNotRegistered();
    error PhotoNotFound();
    error SeedMismatch();

    event UserRegistered(address user, uint256 creationDate);
    event DeviceRegistered(address user, uint256 deviceId, uint256 timestamp);
    event PhotoRegistered(bytes32 photoHash, string location, uint256 timestamp);
    event PhotoProvenanceConfirmed(
        address indexed user,
        bytes32 photoHash,
        string location,
        uint256 timestamp,
        string seedPhrase,
        string seedAlgorithm,
        address app,
        bool algoConfirmed
    );
    event PhotoVerified(bytes32 _photoHash, address requester);

    struct UserDevice {
        uint256 deviceId;
        address user; // what address did you have associated with this device
        string make;
        string model;
        string serialNumber;
    }

    struct PhotoProvenance {
        uint256 deviceId;
        uint256 timestamp;
        string location;
        string seedPhrase;
        string seedAlgorithm;
        address user;
        bytes32 photoHash;
        bool algoConfirmed;
    }

    struct UserAccount {
        uint256 farcasterId;
        uint256 creationDate;
        uint256[] deviceIds;
        address primaryAccount;
        address wallet;
        string name;
        string email;
    }

    bytes32 public constant APP_ROLE = keccak256("APP_ROLE");
    bytes32 public constant APP_BANNED = keccak256("APP_BANNED");

    address public immutable admin;
    address public app;

    /// @dev The goal of these structures is to capture user, photo, and app actions
    ///       such that they can be verified by any user.
    /// @notice The user account is the primary structure that holds all the data
    mapping(address => UserAccount) public registeredUsers;
    mapping(address => mapping(uint256 => UserDevice)) public userDevices;
    mapping(address => mapping(bytes32 => PhotoProvenance)) public userPhotos;

    /// @notice Only admin modifer to restrict access to certain functions
    modifier onlyAdmin() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert OnlyAdmin();
        _;
    }

    /// @notice Only app modifer to restrict access to certain functions
    modifier onlyApp() {
        require(hasRole(APP_ROLE, msg.sender), "Restricted to admins.");
        _;
    }

    /// @notice Constructor to set the admin and app addresses
    /// @param _admin The address of the admin
    /// @param _app The address of the app
    constructor(address _admin, address _app) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        grantAppRole(_app);
        grantAppRole(_admin);

        admin = _admin;
        app = _app;
    }

    /// @notice Enables the admin to grant a new address special permissions
    /// @param newApp The address of the new app
    function grantAppRole(address newApp) public onlyAdmin {
        _grantRole(APP_ROLE, newApp);
    }

    /// @notice Enables the admin to revoke a new address special permissions
    /// @param badApp The address of the new app
    function revokeAppRole(address badApp) public onlyAdmin {
        _grantRole(APP_BANNED, badApp);
    }

    /// @notice Registers a new user
    /// @param _user The encoded user data to register
    function registerUser(bytes memory _user) public onlyApp {
        (address _wallet, uint256 _farcasterId, address _primaryAccount, string memory _name, string memory _email) =
            abi.decode(_user, (address, uint256, address, string, string));

        if (registeredUsers[_wallet].primaryAccount != 0x0000000000000000000000000000000000000000) revert UserExists();

        UserAccount storage newUser = registeredUsers[_wallet];

        newUser.primaryAccount = _primaryAccount;
        newUser.wallet = _wallet;
        newUser.farcasterId = _farcasterId;
        newUser.name = _name;
        newUser.email = _email;
        newUser.creationDate = block.timestamp;

        emit UserRegistered(_wallet, block.timestamp);
    }

    /// @notice Registers a new device
    /// @param _wallet The address of the wallet
    /// @param _device The device to register
    function registerDevice(address _wallet, bytes memory _device) public onlyApp {
        (UserDevice memory device) = abi.decode(_device, (UserDevice));

        if (registeredUsers[_wallet].primaryAccount == 0x0000000000000000000000000000000000000000) {
            revert UserNotRegistered();
        }

        userDevices[_wallet][device.deviceId] = device;

        emit DeviceRegistered(device.user, device.deviceId, block.timestamp);
    }

    /// @notice Registers a new photo
    /// @param _wallet The address of the wallet
    /// @param _deviceId The device ID of the device
    /// @param _photo The photo to register
    function registerPhoto(address _wallet, uint256 _deviceId, bytes memory _photo) public {
        (PhotoProvenance memory photo) = abi.decode(_photo, (PhotoProvenance));

        if (userDevices[_wallet][_deviceId].user == 0x0000000000000000000000000000000000000000) {
            revert DeviceNotRegistered();
        }

        // registeredUsers[_wallet].photos.push(photo);
        userPhotos[_wallet][photo.photoHash] = photo;

        emit PhotoRegistered(photo.photoHash, photo.location, photo.timestamp);
    }

    function confirmPhotoPhrase(address _wallet, bytes memory _device, bytes memory _algoProvenance) public onlyApp {
        (UserDevice memory device) = abi.decode(_device, (UserDevice));
        (PhotoProvenance memory algoProvenance) = abi.decode(_algoProvenance, (PhotoProvenance));

        if (userPhotos[_wallet][algoProvenance.photoHash].photoHash != algoProvenance.photoHash) {
            revert PhotoNotFound();
        }
        string storage storedSeedPhrase = userPhotos[_wallet][algoProvenance.photoHash].seedPhrase;
        if (keccak256(abi.encodePacked(storedSeedPhrase)) == keccak256(abi.encodePacked(algoProvenance.seedPhrase))) {
            revert SeedMismatch();
        }

        userPhotos[_wallet][algoProvenance.photoHash].algoConfirmed = true;

        emit PhotoProvenanceConfirmed(
            _wallet,
            algoProvenance.photoHash,
            algoProvenance.location,
            algoProvenance.timestamp,
            algoProvenance.seedPhrase,
            algoProvenance.seedAlgorithm,
            msg.sender,
            true
        );
    }

    function verifyPhotoProvenance(address _wallet, bytes32 _photoHash) public returns (bool) {
        if (userPhotos[_wallet][_photoHash].photoHash == _photoHash) {
            // photo exists
            if (userPhotos[_wallet][_photoHash].algoConfirmed) {
                // algo confirmed
                emit PhotoVerified(_photoHash, msg.sender);

                return true;
            }
        }

        return false;
    }

    function getUserAccount(address _wallet) public view returns (UserAccount memory) {
        return registeredUsers[_wallet];
    }

    function getUserDevice(address _wallet, uint256 _deviceId) public view returns (UserDevice memory) {
        return userDevices[_wallet][_deviceId];
    }

}
