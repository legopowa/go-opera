// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.1;

import "./LamportLib.sol";
import "./LamportBase.sol";

/*
    @name LamportTest2
    @description Demonstrate how to use the LamportLib library to verify a signature while only storing the hash of a public key
    @author William Doyle
    @date October 3rd 2022
 */
contract LamportTest2 is LamportBase {
    struct AddressValuePair {
        address addr;
        bytes32 value;
    }

    event AddressValuePairsBroadcasted(AddressValuePair[] pairs);

    AddressValuePair[] public pairsArray;

    uint256 constant MAX_PAIRS = 500;

    event Message(string message);
    event MessageWithNumber(string message, uint256 number);
    event MessageWithNumberAndAddress(string message, uint256 number, address addr);
    event EncodedPairs(bytes encodedPairs);
    // function getEncodedPairs(bytes32[2][10] calldata pairs) public {
    //     // Emit the result
    //     emit EncodedPairs(abi.encodePacked(pairs));
    // }
// Define an event

    function getEncodedPairs(
        bytes32[2][10] calldata pairs,
        bytes32[2][256] calldata currentpub,
        string memory messageToBroadcast,
        uint256 numberToBroadcast,
        address addrToBroadcast,
        bytes32 nextPKH

        ) 
            public 
        {
        // Emit the result
        bytes memory firstPart = abi.encodePacked(pairs, messageToBroadcast, numberToBroadcast, addrToBroadcast);
        emit EncodedPairs(abi.encodePacked(firstPart, nextPKH));
        //emit EncodedPairs(abi.encodePacked(currentpub));
    }
        function contractCallTest2(
        bytes32[2][10] calldata pairs,
        bytes32[2][256] calldata currentpub,
        string memory messageToBroadcast,
        uint256 numberToBroadcast,
        address addrToBroadcast,
        bytes[256] calldata sig,
        bytes32 nextPKH

        ) 
            onlyLamportMaster(currentpub, sig, nextPKH, abi.encodePacked(pairs, messageToBroadcast, numberToBroadcast, addrToBroadcast))
            public 
        {
        // Emit the result
        bytes memory firstPart = abi.encodePacked(pairs, messageToBroadcast, numberToBroadcast, addrToBroadcast);
        emit EncodedPairs(abi.encodePacked(firstPart, nextPKH));
        //emit EncodedPairs(abi.encodePacked(currentpub));
    }

    function contractCallTest(
        bytes32[2][10] calldata pairs,
        bytes32[2][256] calldata currentpub,
        bytes32 nextPKH,
        bytes[256] calldata sig
    )
        public
        onlyLamportMaster(currentpub, sig, nextPKH, abi.encodePacked(pairs))
    {
        require(pairs.length <= MAX_PAIRS, "Too many address-value pairs");

        for (uint256 i = 0; i < pairs.length; i++) {
            pairsArray.push(AddressValuePair(address(bytes20(pairs[i][0])), pairs[i][1]));
        }

        emit AddressValuePairsBroadcasted(pairsArray);
    }

    // publish a signed message to the blockchain ... the message is text and a number
    function broadcastnextpkhdcastWithNumber(
        string memory messageToBroadcast,
        uint256 numberToBroadcast,
        bytes32[2][256] calldata currentpub,
        bytes32 nextPKH,
        bytes[256] calldata sig
    )
        public
        onlyLamportOracle(
            currentpub,
            sig,
            nextPKH,
            abi.encodePacked(messageToBroadcast, numberToBroadcast)
        )
    {
        emit MessageWithNumber(messageToBroadcast, numberToBroadcast);
    }

    // publish a signed message to the blockchain ... the message is text, a number, and an address
    function broadcastWithNumberAndAddress(
        string memory messageToBroadcast,
        uint256 numberToBroadcast,
        address addrToBroadcast,
        bytes32[2][256] calldata currentpub,
        bytes32 nextPKH,
        bytes[256] calldata sig
    )
        public
        onlyLamportOracle(
            currentpub,
            sig,
            nextPKH,
            abi.encodePacked(messageToBroadcast, numberToBroadcast, addrToBroadcast)
        )
    {
        emit MessageWithNumberAndAddress(messageToBroadcast, numberToBroadcast, addrToBroadcast);
    }
}
