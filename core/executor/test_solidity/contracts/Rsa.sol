//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "hardhat/console.sol";

contract Rsa {
    function validate(
        uint32 e,
        bytes memory n,
        bytes memory message,
        bytes memory sig
    ) public returns (bytes32) {
        bytes memory input = abi.encodePacked(
            e,
            uint32(n.length),
            n,
            uint32(message.length),
            message,
            uint32(sig.length),
            sig
        );
        uint32 len = uint32(input.length);
        assembly {
            let output := mload(0x40)
            let ret := call(
                not(0),
                0xf4,
                0x0,
                add(input, 0x20),
                len,
                output,
                32
            )
            if iszero(ret) {
                return(ret, 32)
            }
            return(output, 32)
        }
    }
}
