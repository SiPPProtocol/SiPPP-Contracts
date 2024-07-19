// SPDX-License-Identifier: MIT

pragma solidity ^0.8.21;
// pragma solidity >=0.8.0 <0.9.0;

// Useful for debugging. Remove when deploying to a live network.
import "hardhat/console.sol";
// Open Zeppelin
import "@openzeppelin/contracts/access/AccessControl.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Returns the decimal string representation of value
function itoa(uint value) pure returns (string memory) {

  // Count the length of the decimal string representation
  uint length = 1;
  uint v = value;
  while ((v /= 10) != 0) { length++; }

  // Allocated enough bytes
  bytes memory result = new bytes(length);

  // Place each ASCII string character in the string,
  // right to left
  while (true) {
    length--;

    // The ASCII value of the modulo 10 value
    result[length] = bytes1(uint8(0x30 + (value % 10)));

    value /= 10;

    if (length == 0) { break; }
  }

  return string(result);
}

/**
 *Submitted for verification at Etherscan.io on 2023-09-12
 For more info, see: https://docs.ethers.org
*/

contract RecoverMessage {

  // This is the EIP-2098 compact representation, which reduces gas costs
  struct SignatureCompact {
    bytes32 r;
    bytes32 yParityAndS;
  }

  // This is an expaned Signature representation
  struct SignatureExpanded {
      uint8 v;
      bytes32 r;
      bytes32 s;
  }

  // Helper function
  function _ecrecover(string memory message, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
    // Compute the EIP-191 prefixed message
    bytes memory prefixedMessage = abi.encodePacked(
      "\x19Ethereum Signed Message:\n",
      itoa(bytes(message).length),
      message
    );

    // Compute the message digest
    bytes32 digest = keccak256(prefixedMessage);

    // Use the native ecrecover provided by the EVM
    return ecrecover(digest, v, r, s);
  }

  // Recover the address from an EIP-2098 compact Signature, which packs the bit for
  // v into an unused bit within s, which saves gas overall, costing a little extra
  // in computation, but saves far more in calldata length.
  //
  // This Signature format is 64 bytes in length.
  function recoverStringFromCompact(string calldata message, SignatureCompact calldata sig) public pure returns (address) {

      // Decompose the EIP-2098 signature (the struct is 64 bytes in length)
      uint8 v = 27 + uint8(uint256(sig.yParityAndS) >> 255);
      bytes32 s = bytes32((uint256(sig.yParityAndS) << 1) >> 1);

      return _ecrecover(message, v, sig.r, s);
  }

  // Recover the address from the an expanded Signature struct.
  //
  // This Signature format is 96 bytes in length.
  function recoverStringFromExpanded(string calldata message, SignatureExpanded calldata sig) public pure returns (address) {

      // The v, r and s are included directly within the struct, which is 96 bytes in length
      return _ecrecover(message, sig.v, sig.r, sig.s);
  }

  // Recover the address from a v, r and s passed directly into the method.
  //
  // This Signature format is 96 bytes in length.
  function recoverStringFromVRS(string calldata message, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {

      // The v, r and s are included directly within the struct, which is 96 bytes in length
      return _ecrecover(message, v, r, s);
  }

  // Recover the address from a raw signature. The signature is 65 bytes, which when
  // ABI encoded is 160 bytes long (a pointer, a length and the padded 3 words of data).
  //
  // When using raw signatures, some tools return the v as 0 or 1. In this case you must
  // add 27 to that value as v must be either 27 or 28.
  //
  // This Signature format is 65 bytes of data, but when ABI encoded is 160 bytes in length; 
  // a pointer (32 bytes), a length (32 bytes) and the padded 3 words of data (96 bytes).
  function recoverStringFromRaw(string calldata message, bytes calldata sig) public pure returns (address) {

    // Sanity check before using assembly
    require(sig.length == 65, "invalid signature");

    // Decompose the raw signature into r, s and v (note the order)
    uint8 v;
    bytes32 r;
    bytes32 s;
    assembly {
      r := calldataload(sig.offset)
      s := calldataload(add(sig.offset, 0x20))
      v := calldataload(add(sig.offset, 0x21))
    }

    return _ecrecover(message, v, r, s);
  }

  // This is provided as a quick example for those that only need to recover a signature
  // for a signed hash (highly discouraged; but common), which means we can hardcode the
  // length in the prefix. This means we can drop the itoa and _ecrecover functions above.
  function recoverHashFromCompact(bytes32 hash, SignatureCompact calldata sig) public pure returns (address) {
    bytes memory prefixedMessage = abi.encodePacked(
      // Notice the length of the message is hard-coded to 32
      // here -----------------------v
      "\x19Ethereum Signed Message:\n32",
      hash
    );

    bytes32 digest = keccak256(prefixedMessage);

    // Decompose the EIP-2098 signature
    uint8 v = 27 + uint8(uint256(sig.yParityAndS) >> 255);
    bytes32 s = bytes32((uint256(sig.yParityAndS) << 1) >> 1);

    return ecrecover(digest, v, sig.r, s);
  }
}
//--------------------------------------------------------------------------------
//--------------------------------------------------------------------------------
//--------------------------------------------------------------------------------
contract SiPPP is AccessControl, RecoverMessage {
  
  error OnlyApp();
  error OnlyAdmin();
  error PhotoNotFound();

  event PhotoRegistered(string photoHash, uint256 timestamp);
  event PhotoVerified(string _photoHash, address requester);
  event Verified(bool verified);
  event PublicAddy(address publicAddy);

  bytes32 public constant APP_ROLE = keccak256("APP_ROLE");
  bytes32 public constant APP_BANNED = keccak256("APP_BANNED");

  address private APP_ADDY;
  address private immutable ADMIN;
    
  struct TransactionData {
    string photoIpfsHash;
    uint256 pinTime;
    uint256 pinSize;
    bytes rawSig;
    uint256 timestamp;
  }
  
  mapping(address => TransactionData[]) public userPhotos;
  string[] private photoIds;
  address[] private userAddresses;
  mapping( string => bool ) private photoSippped;
  mapping( address => bool ) private userSippped;

  /// @notice Only ADMIN modifer to restrict access to certain functions
  modifier onlyAdmin() {
    if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert OnlyAdmin();
    _;
  }

  modifier onlyApp(string calldata message, bytes calldata rawSig) {
    if (!verifyApp(message,rawSig)) revert OnlyApp(); // this is where the public key verification should be
    _;
  }

	constructor(address _admin, address _publicAddy) {
    _grantRole(DEFAULT_ADMIN_ROLE, _admin);
		APP_ADDY = _publicAddy; // "0x2C80552A6f2FD1b32d7783E4c5086899da3933b8";
    ADMIN = _admin;
	}

  function verifyApp(string calldata message, bytes calldata rawSig) public returns (bool) {

    bool verified = APP_ADDY == recoverStringFromRaw(message, rawSig);
    if (verified) {
      emit Verified(verified);
    }
    return verified;

    // // If the signature matches the EIP-2098 format, a Signature
    // // can be passed as the struct value directly, since the
    // // parser will pull out the matching struct keys from sig.
    // console.log("recoverStringFromCompact(message, sig) ::: ", await contract.recoverStringFromCompact(message, sig));
    // // '0x0A489345F9E9bc5254E18dd14fA7ECfDB2cE5f21'

    // // Likewise, if the struct keys match an expanded signature
    // // struct, it can also be passed as the struct value directly.
    // console.log("recoverStringFromExpanded(message, sig)", await contract.recoverStringFromExpanded(message, sig));
    // // '0x0A489345F9E9bc5254E18dd14fA7ECfDB2cE5f21'

    // // If using an older API which requires the v, r and s be passed
    // // separately, those members are present on the Signature.
    // console.log(
    //   "recoverStringFromVRS(message, sig.v, sig.r, sig.s)",
    //   await contract.recoverStringFromVRS(message, sig.v, sig.r, sig.s),
    // );
    // // '0x0A489345F9E9bc5254E18dd14fA7ECfDB2cE5f21'

    // // Or if using an API that expects a raw signature.
    // console.log("recoverStringFromRaw(message, rawSig)", await contract.recoverStringFromRaw(message, rawSig));
    // // '0x0A489345F9E9bc5254E18dd14fA7ECfDB2cE5f21'
  }

  function updatePubAddy(address _publicAddy) public onlyAdmin {
    APP_ADDY = _publicAddy;
    emit PublicAddy(_publicAddy);
  }

  /// @notice Registers a new photo
  /// @param _wallet The address of the wallet
  /// @param _sipppTxn The photo to register
  function registerPhoto(
      address _wallet,
      TransactionData calldata _sipppTxn
  ) public payable onlyApp(_sipppTxn.photoIpfsHash, _sipppTxn.rawSig) {
    // (TransactionData memory transaction) = abi.decode(_sipppTxn, (TransactionData));

    photoIds.push(_sipppTxn.photoIpfsHash);
    userAddresses.push(_wallet);
    userPhotos[_wallet].push(_sipppTxn);
    photoSippped[_sipppTxn.photoIpfsHash] = true;
    userSippped[_wallet] = true;

    emit PhotoRegistered(
      _sipppTxn.photoIpfsHash,
      _sipppTxn.timestamp
    );
  }

  function verifyPhotoProvenance(
      address _wallet, // why wallet? should people need the sippper's wallet to verify?
      string calldata _photoIpfsHash
  ) public returns (bool) {
    if (photoSippped[_photoIpfsHash]) {
      emit PhotoVerified(_photoIpfsHash, msg.sender);
      return true;
    }
    return false;
  }
}
