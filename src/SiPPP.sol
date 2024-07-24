// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// Open Zeppelin
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {RecoverMessage} from "./RecoverMessage.sol";

/// @title SiPPP
/// @notice A contract for registering and verifying photos
contract SiPPP is AccessControl, RecoverMessage {
    error OnlyApp();
    error OnlyAdmin();
    error PhotoNotFound();

    event PhotoRegistered(string photoHash, uint256 timestamp);
    event PhotoVerified(string _photoHash, address requester);
    event Verified(bool verified);
    event PublicAddy(address publicAddy);
    event TreasuryUpdated(address _treasury);

    struct TransactionData {
        uint256 timestamp;
        uint256 pinTime;
        uint256 pinSize;
        bytes rawSig;
        // bytes photoHex;
        string photoIpfsHash;
    }

    uint256 private REV_SHARE_PCNT = 90;

    bytes32 public constant APP_ROLE = keccak256("APP_ROLE");
    bytes32 public constant APP_BANNED = keccak256("APP_BANNED");

    address private s_appAddress;
    address private immutable s_admin;
    address payable private TREASURY;

    string[] private s_photoIds;

    address[] private s_userAddresses;

    mapping(address => TransactionData[]) public s_userPhotos;
    mapping(string => bool) private s_photoSippped;
    mapping(address => bool) private s_userSippped;

    /// @notice Only s_admin modifer to restrict access to certain functions
    modifier onlyAdmin() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert OnlyAdmin();
        _;
    }

    modifier onlyApp(string calldata message, bytes calldata rawSig) {
        if (!verifyApp(message, rawSig)) revert OnlyApp(); // this is where the public key verification should be
        _;
    }

    modifier positiveMsgValue() {
        if (msg.value <= 0) revert("Please pay with Ether.");
        _;
    }

    constructor(address _admin, address _publicAddy, address payable _treasury) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(APP_ROLE, _publicAddy);

        TREASURY = _treasury;

        s_appAddress = _publicAddy;
        s_admin = _admin;
    }

    /// @notice Verifies the app address
    /// @param message The message to verify
    /// @param rawSig The signature to verify
    /// @return bool Whether the signature is valid
    function verifyApp(string calldata message, bytes calldata rawSig) public returns (bool) {
        bool verified = s_appAddress == recoverStringFromRaw(message, rawSig);
        if (verified) {
            emit Verified(verified);
        }

        return verified;
    }

    /// @notice Updates the app address
    /// @param _publicAddy The new app address
    function updatePubAddy(address _publicAddy) public onlyAdmin {
        s_appAddress = _publicAddy;

        emit PublicAddy(_publicAddy);
    }

    /// @notice Updates the treasury address
    /// @param _treasury The new treasury address
    function updateTreasury(address payable _treasury) public onlyAdmin {
        TREASURY = _treasury;

        emit TreasuryUpdated(_treasury);
    }

    /// @notice Updates the revenue share percentage
    /// @param _revSharePcnt The new revenue share percentage
    function updateRevShareCut(uint256 _revSharePcnt) public onlyAdmin {
        REV_SHARE_PCNT = _revSharePcnt;
    }

    /// @notice Registers a new photo
    /// @param _npm_wallet The address of the wallet
    /// @param _sipppTxn The photo to register
    function registerPhoto(address payable _npm_wallet, TransactionData calldata _sipppTxn)
        public
        payable
        onlyApp(_sipppTxn.photoIpfsHash, _sipppTxn.rawSig)
        positiveMsgValue
    {
        // (TransactionData memory transaction) = abi.decode(_sipppTxn, (TransactionData));

        if (_npm_wallet == address(0)) {
            (bool success,) = TREASURY.call{value: msg.value}("");
            require(success, "Transfer failed");
        } else {
            uint256 _sippp_cut = msg.value * REV_SHARE_PCNT / 100;
            uint256 _3rd_party_cut = msg.value - _sippp_cut;

            (bool success1,) = TREASURY.call{value: _sippp_cut}("");
            require(success1, "Transfer failed");

            (bool success2,) = _npm_wallet.call{value: _3rd_party_cut}("");
            require(success2, "Transfer failed");
        }

        s_photoIds.push(_sipppTxn.photoIpfsHash);
        s_userAddresses.push(msg.sender);
        s_userPhotos[msg.sender].push(_sipppTxn);
        s_photoSippped[_sipppTxn.photoIpfsHash] = true;
        s_userSippped[msg.sender] = true;

        emit PhotoRegistered(_sipppTxn.photoIpfsHash, _sipppTxn.timestamp);
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
}
