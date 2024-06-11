pragma solidity ^0.8.25;

// Open Zeppelin
import "@openzeppelin/contracts/access/AccessControl.sol";

import {Privy} from "./Privy.sol";

/// @title SippProvenance
/// @author Aphilos.eth
/// @notice This contract is designed to work with the SiPPP mobile app to
///         1. Hold data that provides provenance for every photo taken by the app
///         2. Provides functions that enable any user to verify the authenticity of a photo
contract sippProvenance is AccessControl {

  struct Hardware {
    string make;
    string model;
    string serialNumber;
    address user;
  }

  struct PhotoProvenance {
    Hardware hardware; // Hardware struct can be used for the interface, and provenance.
    string photoHash;
    string location;
    uint256 timestamp;
    string seedPhrase;
    string seedAlgorithm;
    address user;
  }

  struct UserDevice {
    address user; // what address did you have associated with this device
    string name;
    string email;
    uint256 creationDate;
    Hardware hardware; // may have multiple devices
  }

  struct UserAccount {
    UserDevice[] devices;
    address[] hardwareAccounts;
    PhotoProvenance[] photoProvenance;
    mapping(address => PhotoProvenance) public algoProvenance;
    address primaryAccount;
    Privy privy;
  }
  
  // Register user
  mapping(Privy => UserAccount) public registeredUsers; 

  // enables the admin to grant a new address special permissions
  function grantAppRole(address newApp) public onlyAdmin {
      _grantRole(APP_ROLE, newApp);
  }

  // enables the admin to grant a new address special permissions
  function revokeAppRole(address badApp) public onlyAdmin {
      _grantRole(APP_BANNED, badApp);
  }

  modifier onlyAdmin() {
    require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Restricted to admins.");
    _;
  }

  modifier onlyApp() {
    require(hasRole(APP_ROLE, msg.sender), "Restricted to admins.");
    _;
  }
  
  address public admin;
  address public app;
  address private key;
  constructor(address _admin, address _app, uint256 private _key) {
    grantAppRole(DEFAULT_ADMIN_ROLE, _admin);
    grantAppRole(APP_ROLE, _app);
    admin = _admin;
    app = _app;
    key = _key;
  }

  function registerUser(Privy _privy, UserAccount memory _user) public {
    require(registeredUsers[_privy].primaryAccount == 0x0000000000000000000000000000000000000000, "User already registered");
    registeredUsers[_privy].user.push(_user);
    registeredUsers[_privy].primaryAccount = _user.user;
    registeredUsers[_privy].privy = _privy;
  }

  function registerDevice(Privy _privy, UserDevice memory _device) public onlyApp {
    require(registeredUsers[_privy].primaryAccount != 0x0000000000000000000000000000000000000000, "User not registered");
    registeredUsers[_privy].devices.push(_device);
    registeredUsers[_privy].hardwareAccounts.push(_device.user);
  }

  function registerPhoto(Privy _privy, PhotoProvenance memory _photo) public {

    // First find the device and ensure this user is the owner
    bool deviceFound = false;
    for (var i=0; i< registeredUsers[_privy].hardwareAccounts.length; i++) {
      if (registeredUsers[_privy].hardwareAccounts == msg.sender) {
        deviceFound = true;
        dx = i;
        break;
      }
    } 

    if (deviceFound) {registeredUsers[_privy].photoProvenance.push(_photo);}
    else {revert("Device not found");}
  }

  function savePhotoPhrase(Privy _privy, UserDevice memory _device, PhotoProvenance memory _algoProvenance) public onlyApp {
    require( registeredUsers[_privy].algoProvenance[_algoProvenance.photoHash].photoHash == _algoProvenance.photoHash, "Photo not found");
    require( registeredUsers[_privy].algoProvenance[_algoProvenance.photoHash].photoHash == _algoProvenance.photoHash, "Photo not found");

    bool photoFound = false;
    for (var i=0; i< registeredUsers[_privy].photoProvenance.length; i++) {
      if (registeredUsers[_privy].photoProvenance[i].photoHash == _algoProvenance.photoHash) {
        photoFound = true;
        registeredUsers[_privy].algoProvenance[_algoProvenance.photoHash] = _algoProvenance;
        return;
      }
    }
  }
}