// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Open Zeppelin
import "@openzeppelin/contracts/access/AccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title SippProvenance
/// @author Aphilos.eth
/// @notice This contract is designed to work with the SiPPP mobile app to
///         1. Hold data that provides provenance for every photo taken by the app
///         2. Provides functions that enable any user to verify the authenticity of a photo
contract SiPPPProvenance is AccessControl {
    error OnlyApp();
    error OnlyAdmin();
    error UserExists();
    error PhotoNotFound();

    event PhotoRegistered(bytes32 photoHash, uint256 timestamp);
    event PhotoVerified(bytes32 _photoHash, address requester);

    event Verified(bool verified);
    event PublicKey(address publicKey);
    
    struct TransactionData {
        bytes32 photoHash;
        bytes photoHex;
        uint256 pinTime;
        uint256 pinSize;
        bytes signedPhotoHex;
        uint256 timestamp;
    }

    bytes32 public constant APP_ROLE = keccak256("APP_ROLE");
    bytes32 public constant APP_BANNED = keccak256("APP_BANNED");

    address public immutable admin;
    address public app;

    mapping(address => TransactionData[]) public userPhotos;
    bytes[] private photoIds;
    address[] private userAddresses;

    address private PUBLIC_KEY;
    bytes32 private _r;
    bytes32 private _s;
    uint8 private _v;

    /// @notice Only admin modifer to restrict access to certain functions
    modifier onlyAdmin() {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert OnlyAdmin();
        _;
    }

    modifier onlyApp(bytes memory data, bytes memory signature) {
        if (!verifySignedHashIsSipppSigned(data,signature)) revert OnlyApp(); // this is where the public key verification should be
        _;
    }

    constructor(address _admin, address _publicKey) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        admin = _admin;
		    PUBLIC_KEY = _publicKey;
    }

    /// @notice Registers a new photo
    /// @param _wallet The address of the wallet
    /// @param _sipppTransaction The photo to register
    function registerPhoto(
        address _wallet,
        TransactionData memory _sipppTransaction
    ) public payable onlyApp(_sipppTransaction.photoHex, _sipppTransaction.signedPhotoHex) {
        // (TransactionData memory transaction) = abi.decode(_sipppTransaction, (TransactionData));

        photoIds.push(_sipppTransaction.photoHex);
        userAddresses.push(_wallet);
        userPhotos[_wallet].push(_sipppTransaction);

        emit PhotoRegistered(
            _sipppTransaction.photoHash,
            _sipppTransaction.timestamp
        );
    }

    function verifyPhotoProvenance(
        address _wallet,
        bytes32 _photoHash
    ) public returns (bool) {
        if (userPhotos[_wallet].length > 0) {
            for (uint256 i = 0; i < userPhotos[_wallet].length; i++) {
                if (userPhotos[_wallet][i].photoHash == _photoHash) {
                    // photo exists, and signature verification ensures only App can populate this structure
                    emit PhotoVerified(_photoHash, msg.sender);
                    return true;
                }
            }
        }
        return false;
    }

    function verifySignedHashIsSipppSigned(
        bytes memory data,
        bytes memory signature
    ) public returns (bool verified) {
        (_r, _s, _v) = splitSignature(signature);
        verified = verifySignatureWithPublicKey(PUBLIC_KEY, data, _v, _r, _s);
        emit Verified(verified);
        return true; // verified;
    }

    function splitSignature(
        bytes memory signature
    ) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(signature.length == 65, "Invalid signature length");

        assembly {
            // First 32 bytes (r)
            r := mload(add(signature, 32))
            // Next 32 bytes (s)
            s := mload(add(signature, 64))
            // Last byte (v)
            v := byte(0, mload(add(signature, 96)))
        }

        // EIP-2: If v is 0 or 1, it should be treated as 27 or 28 correspondingly
        if (v < 27) {
            v += 27;
        }
        return (r, s, v);
    }

    function verifySignatureWithPublicKey(
        address expectedPublicKey,
        bytes memory data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal returns (bool) {
        bytes32 hash = hashData(data);
        address actualPublicKey = recoverPublicKey(hash, v, r, s);
        emit PublicKey(actualPublicKey);
        emit PublicKey(expectedPublicKey);
        return (actualPublicKey == expectedPublicKey);
    }

    function verifyPublicKey(
        address expectedPublicKey,
        bytes memory data,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal returns (bool) {
        bytes32 hash = hashData(data);
        address actualPublicKey = recoverPublicKey(hash, v, r, s);
        emit PublicKey(actualPublicKey);
        emit PublicKey(expectedPublicKey);
        return (actualPublicKey == expectedPublicKey);
    }

    function recoverPublicKey(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        bytes32 eip712MessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );

        // Recover public key from signature
        // Using ecrecover to get the public key
        // v needs to be adjusted for Ethereum's specification (27 or 28)
        address publicKey = ecrecover(eip712MessageHash, v, r, s);
        return publicKey;
    }

    function hashData(bytes memory data) internal pure returns (bytes32) {
        return keccak256(data);
    }
}
