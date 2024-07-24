// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SiPPPHelpers {
    // Returns the decimal string representation of value
    function itoa(uint256 value) public pure returns (string memory) {
        // Count the length of the decimal string representation
        uint256 length = 1;
        uint256 v = value;
        while ((v /= 10) != 0) length++;

        // Allocated enough bytes
        bytes memory result = new bytes(length);

        // Place each ASCII string character in the string,
        // right to left
        while (true) {
            length--;

            // The ASCII value of the modulo 10 value
            result[length] = bytes1(uint8(0x30 + (value % 10)));

            value /= 10;

            if (length == 0) break;
        }

        return string(result);
    }
}
