pragma solidity ^0.8.25;

// Open Zeppelin
import "@openzeppelin/contracts/access/AccessControl.sol";

import {Privy} from "./Privy.sol";

/// @title SippProvenance
/// @author Aphilos.eth
/// @notice This contract is designed to work with the SiPPP mobile app to
///         1. Hold data that provides provenance for every photo taken by the app
///         2. Provides functions that enable any user to verify the authenticity of a photo
contract SippProvenance is AccessControl {

  event UserRegistered(address user, uint256 creationDate);
  event DeviceRegistered(address user, uint256 deviceId, uint256 timestamp);
  event PhotoRegistered(address photoHash, string location, uint256 timestamp);
  event PhotoProvenanceConfirmed(address indexed user, string photoHash, string location, uint256 timestamp, string seedPhrase, string seedAlgorithm, address app, bool algoConfirmed);
  event PhotoVerified(address _photoHash, address requester);

  struct UserDevice {
    uint256 deviceId;
    address user; // what address did you have associated with this device
    string make;
    string model;
    string serialNumber;
  }

  struct PhotoProvenance {
    uint256 deviceId;
    string photoHash;
    string location;
    uint256 timestamp;
    string seedPhrase;
    string seedAlgorithm;
    address user;
    bool algoConfirmed;
  }

  struct UserAccount {
    address[] devideIds;
    mapping(uint256 => UserDevice) devices;
    address[] photoHashes;
    mapping(address => PhotoProvenance) photos;
    address primaryAccount;
    Privy privy;
    string name;
    string email;
    uint256 farcasterId;
    uint256 creationDate;
  }

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
  
  // The goal of these structures is to capture user, photo, and app actions such that they can be verified by any user.
  mapping(Privy   => UserAccount)    private registeredUsers; // Registered users
  mapping(address => PhotoProvenance) public photoProvenance; // SiPPPed photos
  mapping(address => PhotoProvenance) public appProvenance;   // App Provenance
  address public admin;
  address public app;
  constructor(address _admin, address _app) {
    grantAppRole(DEFAULT_ADMIN_ROLE, _admin);
    grantAppRole(APP_ROLE, _app);
    admin = _admin;
    app = _app;
  }

  function registerUser(
    Privy _privy, 
    uint256 _farcasterId,
    address _primaryAccount, 
    string _name,
    string _email) 
  public onlyApp 
  {
    require(registeredUsers[_privy].primaryAccount == 0x0000000000000000000000000000000000000000, "User already registered");
    registeredUsers[_privy].privy = _privy;
    registeredUsers[_privy].farcasterId = _farcasterId;
    registeredUsers[_privy].primaryAccount = _primaryAccount;
    registeredUsers[_privy].name = _name;
    registeredUsers[_privy].email = _email;
    registeredUsers[_privy].creationDate = block.timestamp;
    emit UserRegistered(_device.user, block.timestamp);
  }

  function registerDevice(Privy _privy, UserDevice memory _device) public onlyApp {
    require(registeredUsers[_privy].primaryAccount != 0x0000000000000000000000000000000000000000, "User not registered");
    registeredUsers[_privy].deviceIds.push(_device.deviceId);
    registeredUsers[_privy].devices[_device.deviceId] = _device;
    emit DeviceRegistered(_device.user, _device.deviceId, block.timestamp);
  }

  function registerPhoto(Privy _privy, uint256 deviceId, PhotoProvenance memory _photo) public {
    require(registeredUsers[_privy].devices[deviceId].user != 0x0000000000000000000000000000000000000000, "Device not found");
    registeredUsers[_privy].photoHashes.push(_photo.photoHash);
    registeredUsers[_privy].photos[_photo.photoHash] = _photo;
    emit PhotoRegistered(_photo.photoHash, _photo.location, _photo.timestamp);
  }

  function confirmPhotoPhrase(Privy _privy, UserDevice memory _device, PhotoProvenance memory _algoProvenance) public onlyApp {
    require( registeredUsers[_privy].photos[_algoProvenance.photoHash].photoHash == _algoProvenance.photoHash, "Photo not found");
    if (registeredUsers[_privy].photos[_algoProvenance.photoHash].seedPhrase == _algoProvenance.seedPhrase) {
      registeredUsers[_privy].photos[_algoProvenance.photoHash].algoConfirmed = true;
      emit PhotoProvenanceConfirmed( _algoProvenance.photoHash, _algoProvenance.location, _algoProvenance.timestamp, _algoProvenance.seedPhrase, true);
    }
  }

  function verifyPhotoProvenance(address memory _photoHash) public view returns (bool) {
    if (registeredUsers[_privy].photos[_photoHash].photoHash == _photoHash) { // photo exists
      if (registeredUsers[_privy].photos[_photoHash].algoConfirmed) { // algo confirmed
        emit PhotoVerified(_photoHash, msg.sender);
        return true;
      }
    }
    return false;
  }
}