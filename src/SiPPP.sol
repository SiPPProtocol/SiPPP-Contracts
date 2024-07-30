// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// constructor
// receive
// fallback
// external
// public
// internal
// private
// view / pure

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

import {RecoverMessage} from "./RecoverMessage.sol";

/// @title SiPPP
/// @notice A contract for registering and verifying photos
contract SiPPP is AccessControl, RecoverMessage {
    error OnlyApp();
    error OnlyAdmin();
    error PhotoNotFound();
    error ZeroAddress();

    event PhotoRegistered(string photoHash, string timestamp);
    event PhotoVerified(string _photoHash, address requester);
    event Verified(bool verified);
    event PublicAddy(address publicAddy);
    event TreasuryUpdated(address _treasury);
    event RevShareUpdated(uint256 _revSharePcnt);
    event AppVerified(bool verified);

    struct TransactionData {
        string timestamp;
        string pinTime;
        uint256 pinSize;
        bytes32 rawSig;
        // bytes photoHex;
        string photoIpfsHash;
    }

    uint256 private s_revenueSharePercentage = 90;

    bytes32 public constant APP_ROLE = keccak256("APP_ROLE");
    bytes32 public constant APP_BANNED = keccak256("APP_BANNED");

    address private s_appAddress;
    address private immutable i_admin;
    address payable private s_treasury;

    // address[] private s_userAddresses;
    // string[] private s_photoIds;

    mapping(address => TransactionData[]) public s_userPhotos;
    mapping(string => bool) private s_photoSippped;
    mapping(address => bool) private s_userSippped;

    /// @notice Only i_admin modifer to restrict access to certain functions
    modifier onlyAdmin() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert OnlyAdmin();
        _;
    }

    /// @notice Only the s_appAddress is allowed
    modifier onlyApp(string calldata message, bytes calldata rawSig) {
        if (!isAppVerified(message, rawSig)) revert OnlyApp(); // this is where the public key verification should be
        _;
    }

    /// @notice Must have Ether value
    modifier positiveMsgValue() {
        if (msg.value <= 0) revert("Please pay with Ether.");
        _;
    }

    constructor(address _admin, address _publicAddy, address payable _treasury) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(APP_ROLE, _publicAddy);

        s_treasury = _treasury;

        s_appAddress = _publicAddy;
        i_admin = _admin;
    }

    receive() external payable {}

    fallback() external payable {}

    /// Public Functions

    /// @notice Verifies the app address
    /// @param message The message to verify
    /// @param rawSig The signature to verify
    /// @return bool Whether the signature is valid
    function isAppVerified(string calldata message, bytes calldata rawSig) public view returns (bool) {
        bool verified = s_appAddress == recoverStringFromRaw(message, rawSig);

        return verified;
    }

    /// @notice Updates the app address
    /// @param _publicAddy The new app address
    function updatePubAddy(address _publicAddy) public onlyAdmin {
        if (_publicAddy == address(0)) revert ZeroAddress();

        s_appAddress = _publicAddy;

        emit PublicAddy(_publicAddy);
    }

    /// @notice Updates the treasury address
    /// @param _treasury The new treasury address
    function updateTreasury(address payable _treasury) public onlyAdmin {
        if (_treasury == address(0)) revert ZeroAddress();

        s_treasury = _treasury;

        emit TreasuryUpdated(_treasury);
    }

    /// @notice Updates the revenue share percentage
    /// @param _revSharePcnt The new revenue share percentage
    function updateRevShareCut(uint256 _revSharePcnt) public onlyAdmin {
        s_revenueSharePercentage = _revSharePcnt;

        emit RevShareUpdated(_revSharePcnt);
    }

    /// @notice Registers a new photo
    /// @param _revShareWallet The address of the wallet
    /// @param _sipppTxn The photo to register
    function registerPhoto(address payable _revShareWallet, bytes memory _sipppTxn) public payable positiveMsgValue {
        (string memory timestamp, string memory pinTime, uint256 pinSize, bytes32 rawSig, string memory photoIpfsHash) =
            abi.decode(_sipppTxn, (string, string, uint256, bytes32, string));

        if (_revShareWallet == address(0)) {
            (bool success,) = s_treasury.call{value: msg.value}("");
            require(success, "Transfer failed");
        } else {
            uint256 _sippp_cut = msg.value * s_revenueSharePercentage / 100;
            uint256 _3rd_party_cut = msg.value - _sippp_cut;

            (bool success1,) = s_treasury.call{value: _sippp_cut}("");
            require(success1, "Transfer failed");

            (bool success2,) = _revShareWallet.call{value: _3rd_party_cut}("");
            require(success2, "Transfer failed");
        }

        // s_photoIds.push(photoIpfsHash);
        // s_userAddresses.push(msg.sender);
        s_userPhotos[msg.sender].push(
            TransactionData({
                timestamp: timestamp,
                pinTime: pinTime,
                pinSize: pinSize,
                rawSig: rawSig,
                photoIpfsHash: photoIpfsHash
            })
        );
        s_photoSippped[photoIpfsHash] = true;

        // todo: what if the user is already sippped? and has many photos?
        // s_userSippped[msg.sender] = true;

        emit PhotoRegistered(photoIpfsHash, timestamp);
    }

    /// @notice Verifies the photo provenance
    /// @param _photoIpfsHash The photo to verify
    /// @return bool Whether the photo is verified
    function verifyPhotoProvenance(
        address, // why wallet? should people need the sippper's wallet to verify?
        string calldata _photoIpfsHash
    ) public returns (bool) {
        if (s_photoSippped[_photoIpfsHash]) {
            emit PhotoVerified(_photoIpfsHash, msg.sender);

            return true;
        }
        return false;
    }

    /// @notice Withdraws the contract balance
    function withdraw() public onlyAdmin {
        (bool success,) = s_treasury.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }

    /// View Functions

    /// @notice Returns the app address
    /// @return address The app address
    function appAddress() public view returns (address) {
        return s_appAddress;
    }

    /// @notice Returns the admin address
    /// @return address The admin address
    function admin() public view returns (address) {
        return i_admin;
    }

    /// @notice Returns the treasury address
    /// @return address payable The treasury address
    function treasury() public view returns (address payable) {
        return s_treasury;
    }

    /// @notice Returns the revenue share percentage
    /// @return uint256 The revenue share percentage
    function revenueSharePercentage() public view returns (uint256) {
        return s_revenueSharePercentage;
    }
}
