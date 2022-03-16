//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "hardhat/console.sol";

contract Sha256 {
    function inSha256(bytes memory input) public pure returns (bytes32) {
        bytes32 ret = sha256(input);
        return ret;
    }
}
