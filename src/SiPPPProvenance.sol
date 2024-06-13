pragma solidity ^0.8.19;

// Open Zeppelin
import "@openzeppelin/contracts/access/AccessControl.sol";

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
        bytes32 photoHash;
        string location;
        uint256 timestamp;
        string seedPhrase;
        string seedAlgorithm;
        address user;
        bool algoConfirmed;
    }

    struct UserAccount {
        uint256[] deviceIds;
        mapping(uint256 => UserDevice) userDevices;
        bytes32[] photoHashes;
        mapping(bytes32 => PhotoProvenance) photos;
        address primaryAccount;
        address privy; // privy should just be an address, no?
        string name;
        string email;
        uint256 farcasterId;
        uint256 creationDate;
    }

    bytes32 public constant APP_ROLE = keccak256("APP_ROLE");
    bytes32 public constant APP_BANNED = keccak256("APP_BANNED");

    address public immutable admin;
    address public app;

    /// @dev The goal of these structures is to capture user, photo, and app actions
    ///       such that they can be verified by any user.
    /// @notice The user account is the primary structure that holds all the data
    mapping(address => UserAccount) private registeredUsers;

    /// @dev The photoProvenance and appProvenance mappings are used to store the
    ///       provenance of photos taken by the SiPPP app and the app itself.
    /// @notice These mappings are used to store the provenance of photos and the app
    mapping(address => PhotoProvenance) public photoProvenance;

    /// @dev The appProvenance mapping is used to store the provenance of the app
    ///       that is used to take the photos.
    /// @notice This is a mapping of the app address to the photoProvenance struct
    mapping(address => PhotoProvenance) public appProvenance; // App Provenance

    /// @notice Only admin modifer to restrict access to certain functions
    modifier onlyAdmin() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert OnlyAdmin();
        _;
    }

    modifier onlyApp() {
        require(hasRole(APP_ROLE, msg.sender), "Restricted to admins.");
        _;
    }

    constructor(address _admin, address _app) {
        grantAppRole(_admin);
        grantAppRole(_app);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        admin = _admin;
        app = _app;
    }

    // enables the admin to grant a new address special permissions
    function grantAppRole(address newApp) public onlyAdmin {
        _grantRole(APP_ROLE, newApp);
    }

    // enables the admin to grant a new address special permissions
    function revokeAppRole(address badApp) public onlyAdmin {
        _grantRole(APP_BANNED, badApp);
    }

    function registerUser(
        address _privy,
        uint256 _farcasterId,
        address _primaryAccount,
        string memory _name,
        string memory _email
    ) public onlyApp {
        if (registeredUsers[_privy].primaryAccount == 0x0000000000000000000000000000000000000000) revert UserExists();

        UserAccount storage newUser = registeredUsers[_privy];

        newUser.primaryAccount = _primaryAccount;
        newUser.privy = _privy;
        newUser.farcasterId = _farcasterId;
        newUser.name = _name;
        newUser.email = _email;
        newUser.creationDate = block.timestamp;

        emit UserRegistered(_privy, block.timestamp);
    }

    function registerDevice(address _privy, UserDevice memory _device) public onlyApp {
        if (registeredUsers[_privy].primaryAccount != 0x0000000000000000000000000000000000000000) {
            revert UserNotRegistered();
        }

        registeredUsers[_privy].deviceIds.push(_device.deviceId);
        registeredUsers[_privy].userDevices[_device.deviceId] = _device;

        emit DeviceRegistered(_device.user, _device.deviceId, block.timestamp);
    }

    function registerPhoto(address _privy, uint256 _deviceId, PhotoProvenance memory _photo) public {
        if (registeredUsers[_privy].userDevices[_deviceId].user != 0x0000000000000000000000000000000000000000) {
            revert DeviceNotRegistered();
        }

        registeredUsers[_privy].photoHashes.push(_photo.photoHash);
        registeredUsers[_privy].photos[_photo.photoHash] = _photo;

        emit PhotoRegistered(_photo.photoHash, _photo.location, _photo.timestamp);
    }

    function confirmPhotoPhrase(address _privy, UserDevice memory _device, PhotoProvenance memory _algoProvenance)
        public
        onlyApp
    {
        if (registeredUsers[_privy].photos[_algoProvenance.photoHash].photoHash != _algoProvenance.photoHash) {
            revert PhotoNotFound();
        }
        string storage storedSeedPhrase = registeredUsers[_privy].photos[_algoProvenance.photoHash].seedPhrase;
        if (keccak256(abi.encodePacked(storedSeedPhrase)) == keccak256(abi.encodePacked(_algoProvenance.seedPhrase))) {
            revert SeedMismatch();
        }

        registeredUsers[_privy].photos[_algoProvenance.photoHash].algoConfirmed = true;

        emit PhotoProvenanceConfirmed(
            _privy,
            _algoProvenance.photoHash,
            _algoProvenance.location,
            _algoProvenance.timestamp,
            _algoProvenance.seedPhrase,
            _algoProvenance.seedAlgorithm,
            msg.sender,
            true
        );
    }

    function verifyPhotoProvenance(address _privy, bytes32 _photoHash) public returns (bool) {
        if (registeredUsers[_privy].photos[_photoHash].photoHash == _photoHash) {
            // photo exists
            if (registeredUsers[_privy].photos[_photoHash].algoConfirmed) {
                // algo confirmed
                emit PhotoVerified(_photoHash, msg.sender);

                return true;
            }
        }

        return false;
    }
}
