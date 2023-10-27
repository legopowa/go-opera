// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.1;

contract LamportBase2 {

    bool initialized = false;
    bool public lastVerificationResult;

    // Define different key types
    enum KeyType { MASTER, WORKER, DELETED }

    // Store the keys and their corresponding pkh
    struct Key {
        KeyType keyType;
        bytes32 pkh;
    }

    Key[] public keys; // For iteration
    mapping(bytes32 => Key) public keyData; // For search

    event LogLastCalculatedHash(uint256 hash);
    event VerificationFailed(uint256 hashedData);
    event PkhUpdated(KeyType keyType, bytes32 previousPKH, bytes32 newPKH);
    event KeyAdded(KeyType keyType, bytes32 newPKH);
    event KeyModified(KeyType originalKeyType, bytes32 originalPKH, bytes32 modifiedPKH, KeyType newKeyType);

    // Initial setup of the Lamport system, providing the first MASTER keys and a WORKER key
    function init(bytes32 masterPKH1, bytes32 masterPKH2, bytes32 workerPKH) public {
        require(!initialized, "LamportBase: Already initialized");
        addKey(KeyType.MASTER, masterPKH1);
        addKey(KeyType.MASTER, masterPKH2);
        addKey(KeyType.WORKER, workerPKH);
        initialized = true;
    }

    // Add a new key
    function addKey(KeyType keyType, bytes32 newPKH) private {
        Key memory newKey = Key(keyType, newPKH);
        keys.push(newKey);
        keyData[newPKH] = newKey;
        emit KeyAdded(keyType, newPKH);
    }
    // Search for a key by its PKH, return the key and its position in the keys array
    function getKeyAndPosByPKH(bytes32 pkh) public view returns (KeyType, bytes32, uint) {
        Key memory key = keyData[pkh];
        require(key.pkh != 0, "LamportBase: No such key");

        // Iterate over keys array to find the position
        for (uint i = 0; i < keys.length; i++) {
            if (keys[i].pkh == pkh) {
                return (key.keyType, key.pkh, i);
            }
        }
        revert("LamportBase: No such key");
    }
    function getPKHsByPrivilege(KeyType privilege) public view returns (bytes32[] memory) {
        bytes32[] memory pkhs = new bytes32[](keys.length);
        uint counter = 0;

        for (uint i = 0; i < keys.length; i++) {
            if (keys[i].keyType == privilege) {
                pkhs[counter] = keys[i].pkh;
                counter++;
            }
        }

        // Prepare the array to return
        bytes32[] memory result = new bytes32[](counter);
        for(uint i = 0; i < counter; i++) {
            result[i] = pkhs[i];
        }

        return result;
    }

    // Delete a key
    // function deleteKey(bytes32 firstMasterPKH, bytes32 secondMasterPKH, bytes32 targetPKH) private {
    //     // Check that the two provided keys are master keys
    //     require(keyData[firstMasterPKH].keyType == KeyType.MASTER && keyData[secondMasterPKH].keyType == KeyType.MASTER, "LamportBase: Provided keys are not master keys");

    //     // Disallow master keys from deleting themselves
    //     require(targetPKH != firstMasterPKH && targetPKH != secondMasterPKH, "LamportBase: Master keys cannot delete themselves");

    //     require(keyData[targetPKH].pkh != 0, "LamportBase: No such key");
    //     for (uint i = 0; i < keys.length; i++) {
    //         if (keys[i].pkh == targetPKH) {
    //             delete keyData[targetPKH];
    //             keys[i] = keys[keys.length - 1];
    //             keys.pop();
    //             emit KeyDeleted(keys[i].keyType, targetPKH);
    //             break;
    //         }
    //     }
    // }

    bytes32 private lastUsedDeleteKeyHash;
    bytes32 private storedNextPKH;

    function deleteKeyStepOne(
        bytes32[2][256] calldata currentpub,
        bytes[256] calldata sig,
        bytes32 nextPKH,
        bytes32 deleteKeyHash
    )
        public
        onlyLamportMaster(
            currentpub,
            sig,
            nextPKH,
            abi.encodePacked(deleteKeyHash)
        )
    {
        // Save the used deleteKeyHash in a global variable
        lastUsedDeleteKeyHash = deleteKeyHash;
        storedNextPKH = nextPKH;
    }

    function deleteKeyStepTwo(
            bytes32[2][256] calldata currentpub,
            bytes[256] calldata sig,
            bytes32 nextPKH,
            bytes32 confirmDeleteKeyHash
        )
            public
            onlyLamportMaster(
                currentpub,
                sig,
                nextPKH,
                abi.encodePacked(confirmDeleteKeyHash)
            )
        {
            // Calculate the current public key hash (currentPKH)
            bytes32 currentPKH = keccak256(abi.encodePacked(currentpub));
            
            // Check if storedNextPKH is not the same as the current PKH
            require(currentPKH != storedNextPKH, "LamportBase: Cannot use the same keychain twice for this function");
            
            // Check if the used deleteKeyHash matches the last used deleteKeyHash
            require(lastUsedDeleteKeyHash == confirmDeleteKeyHash, "LamportBase: Keys do not match");
            
            // Execute the delete key logic
            // Assuming firstMasterPKH and secondMasterPKH are correctly verified and provided
            bytes32 firstMasterPKH = storedNextPKH; // Placeholder, replace with the actual value
            bytes32 secondMasterPKH = currentPKH; // Placeholder, replace with the actual value
            bytes32 targetPKH = confirmDeleteKeyHash;
            
            // Check that the two provided keys are master keys
            require(keyData[firstMasterPKH].keyType == KeyType.MASTER && keyData[secondMasterPKH].keyType == KeyType.MASTER, "LamportBase: Provided keys are not master keys");
            
            // Disallow master keys from deleting themselves
            require(targetPKH != firstMasterPKH && targetPKH != secondMasterPKH, "LamportBase: Master keys cannot delete themselves");
            
            // require(keyData[targetPKH].pkh != 0, "LamportBase: No such key (deletion)");
            // for (uint i = 0; i < keys.length; i++) {
            //     if (keys[i].pkh == targetPKH) {
            //         delete keyData[targetPKH];
            //         keys[i] = keys[keys.length - 1];
            //         keys.pop();
            //         emit KeyDeleted(keys[i].keyType, targetPKH);
            //         break;
            //     }
            // }
            require(keyData[targetPKH].pkh != 0, "LamportBase: No such key (deletion)");
            for (uint i = 0; i < keys.length; i++) {
                if (keys[i].pkh == targetPKH) {

                    KeyType originalKeyType = keyData[targetPKH].keyType; // Store the original KeyType
                    // Overwriting the first 7 characters with "de1e7ed" and the rest with random values
                    bytes32 modifiedPKH = 0xde1e7ed000000000000000000000000000000000000000000000000000000000;
                    uint256 randomValue = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)));
                    modifiedPKH ^= bytes32(randomValue); // XOR to keep "de1e7ed" in the first 7 characters
                    
                    // Modify the existing entry instead of deleting it
                    keyData[targetPKH].pkh = modifiedPKH;
                    keyData[targetPKH].keyType = KeyType.DELETED; // Set the keyType to DELETED
                    
                    emit KeyModified(originalKeyType, targetPKH, modifiedPKH, KeyType.DELETED); // Emitting a new event for modification                    
                    break;
                }
            }


            
            // Reset lastUsedDeleteKeyHash
            lastUsedDeleteKeyHash = bytes32(0);
            storedNextPKH = bytes32(0);
        }



    // // get the current public key hash
    // function getPKH() public view returns (bytes32) {
    //     return pkh;
    // }

    // lamport 'verify' logic
    function verify_u256(
        uint256 bits,
        bytes[256] calldata sig,
        bytes32[2][256] calldata pub
    ) public pure returns (bool) {
        unchecked {
            for (uint256 i; i < 256; i++) {
                if (
                    pub[i][((bits & (1 << (255 - i))) > 0) ? 1 : 0] !=
                    keccak256(sig[i])
                ) return false;
            }

            return true;
        }
    }

    modifier onlyLamportMaster(bytes32[2][256] calldata currentpub, bytes[256] calldata sig, bytes32 nextPKH, bytes memory prepacked) {
        require(initialized, "LamportBase: not initialized");

        bytes32 pkh = keccak256(abi.encodePacked(currentpub));
        require(keyData[pkh].keyType == KeyType.MASTER, "LamportBase: Not a master key");

        uint256 hashedData = uint256(keccak256(abi.encodePacked(prepacked, nextPKH)));
        emit LogLastCalculatedHash(hashedData);

        bool verificationResult = verify_u256(hashedData, sig, currentpub);

        lastVerificationResult = verificationResult;

        if (!verificationResult) {
            emit VerificationFailed(hashedData);
            revert("LamportBase: Verification failed");
        } else {
            emit PkhUpdated(keyData[pkh].keyType, pkh, nextPKH);
            updateKey(pkh, nextPKH);
        }

        _;
    }

    // function updateKey(bytes32 oldPKH, bytes32 newPKH) internal {
    //     require(keyData[oldPKH].pkh != 0, "LamportBase: No such key");
    //     keyData[oldPKH].pkh = newPKH; // Update the public key hash in the key data mapping
    //     emit PkhUpdated(keyData[oldPKH].keyType, oldPKH, newPKH);
    // }

    function updateKey(bytes32 oldPKH, bytes32 newPKH) internal {
        require(keyData[oldPKH].pkh != 0, "LamportBase: No such key");

        // Update the public key hash in the key data mapping
        Key memory updatedKey = Key(keyData[oldPKH].keyType, newPKH);
        keyData[newPKH] = updatedKey;

        // Remove the old key from key data
        delete keyData[oldPKH];

        // Update the public key hash in the keys array
        for (uint i = 0; i < keys.length; i++) {
            if (keys[i].pkh == oldPKH) {
                keys[i] = updatedKey;
                break;
            }
        }

        emit PkhUpdated(updatedKey.keyType, oldPKH, newPKH);
    }



    modifier onlyLamportWorker(bytes32[2][256] calldata currentpub, bytes[256] calldata sig, bytes32 nextPKH, bytes memory prepacked) {
        require(initialized, "LamportBase: not initialized");

        bytes32 pkh = keccak256(abi.encodePacked(currentpub));
        require(keyData[pkh].keyType == KeyType.WORKER, "LamportBase: Not a worker key");

        uint256 hashedData = uint256(keccak256(abi.encodePacked(prepacked, nextPKH)));
        emit LogLastCalculatedHash(hashedData);

        bool verificationResult = verify_u256(hashedData, sig, currentpub);

        lastVerificationResult = verificationResult;

        if (!verificationResult) {
           // emit VerificationFailed(hashedData);
            revert("LamportBase: Verification failed");
        } else {
            emit PkhUpdated(keyData[pkh].keyType, pkh, nextPKH);
            updateKey(pkh, nextPKH);
        }

        _;
    }

    bytes32 public lastUsedNextPKH;

    function createMasterKeyStepOne(
        bytes32[2][256] calldata currentpub,
        bytes[256] calldata sig,
        bytes32 nextPKH,
        bytes memory newmasterPKH
    )
        public
        onlyLamportMaster(
            currentpub,
            sig,
            nextPKH,
            newmasterPKH
        )
    {
        // Save the used master NextPKH in a global variable
        lastUsedNextPKH = nextPKH;
    }

    function createMasterKeyStepTwo(
        bytes32[2][256] calldata currentpub,
        bytes[256] calldata sig,
        bytes32 nextPKH,
        bytes32 newmasterPKH
    )
        public
        onlyLamportMaster(
            currentpub,
            sig,
            nextPKH,
            abi.encodePacked(newmasterPKH)
        )
    {
        // Check if the used master NextPKH matches the last used PKH
        bytes32 currentPKH = keccak256(abi.encodePacked(currentpub));
        bool pkhMatched = (lastUsedNextPKH != currentPKH);
        //require(lastUsedNextPKH != nextPKH, "LamportBase: Same master key is being used again, need a separate one");
        lastUsedNextPKH = bytes32(0);
        // If checks pass, add the new master key
        require(pkhMatched, "LamportBase: PKH matches last used PKH (use separate second key)");

        addKey(KeyType.MASTER, newmasterPKH);

        // Reset lastUsedNextPKH
        lastUsedNextPKH = bytes32(0);
    }


    function createWorkerKeyFromMaster(
        bytes32[2][256] calldata currentpub,
        bytes32 nextPKH,
        bytes[256] calldata sig,
        bytes32 newworkerPKH
    )
        public
        onlyLamportMaster(
            currentpub,
            sig,
            nextPKH,
            abi.encodePacked(newworkerPKH)
        )
    {
        
        addKey(KeyType.WORKER, newworkerPKH);
      
    }
}


interface AnonIDContract {
    // Directly referencing the public state variables
    function hourlyUserTxLimit() external view returns (uint256);
    function hourlyValidatorTxLimit() external view returns (uint256);
    function hourlyExchangeTxLimit() external view returns (uint256);
}

contract FireWalletExch is LamportBase2 {

    AnonIDContract anonID = AnonIDContract(0x31337b00000000000daaaaaaaaaaaaa5);
    
    mapping(address => uint256[]) public userTxTimestamps;
    mapping(address => uint256[]) public validatorTxTimestamps;
    uint256 public transactionLimit;


    enum ProtectionMode { None, OneTimeClearance, WhitelistAddress }
    ProtectionMode public currentMode = ProtectionMode.None;
    address public whitelistedAddress;

    function isThisTxFree() external returns (bool) {
        uint256 limit = anonID.hourlyUserTxLimit();
        return checkFreeTransaction(userTxTimestamps[msg.sender], limit);
    }
    
    function isThisValidationFree() external returns (bool) {
        uint256 limit = anonID.hourlyValidatorTxLimit();
        return checkFreeTransaction(validatorTxTimestamps[msg.sender], limit);
    }

    function isThisExchangeTxFree() external returns (bool) {
        uint256 limit = anonID.hourlyExchangeTxLimit();
        return checkFreeTransaction(validatorTxTimestamps[msg.sender], limit);
    }
  
    function checkFreeTransaction(uint256[] storage timestamps, uint256 limit) internal returns (bool) {
        // If the user/validator has less than `limit` transactions in total, it's free
        if (timestamps.length < limit) {
            timestamps.push(block.timestamp);
            return true;
        }

        uint256 nthLastTxTimestamp = timestamps[timestamps.length - limit];

        // If the nth last transaction happened more than an hour ago, it's free
        if (nthLastTxTimestamp <= block.timestamp - 1 hours) {
            timestamps.push(block.timestamp);
            return true;
        } else {
            // If not, the user/validator has to pay
            return false;
        }
    }

    function setTransactionLimit(
        bytes32[2][256] calldata currentpub,
        bytes[256] calldata sig,
        bytes32 nextPKH,
        uint256 newTransactionLimit
    ) 
        public 
        onlyLamportMaster(
            currentpub,
            sig,
            nextPKH,
            abi.encodePacked(newTransactionLimit)
        )
    {
        transactionLimit = newTransactionLimit;
    }

    function setOneTimeClearance(
        bytes32[2][256] calldata currentpub,
        bytes[256] calldata sig,
        bytes32 nextPKH,
        uint256 arbitraryValue
    ) 
        public 
        onlyLamportMaster(
            currentpub,
            sig,
            nextPKH,
            abi.encodePacked(arbitraryValue)
        )
    {
        currentMode = ProtectionMode.OneTimeClearance;
    }

    // this whitelist is just for allowed transaction destination addresses, per user.
    function setWhitelistAddress(
        bytes32[2][256] calldata currentpub,
        bytes[256] calldata sig,
        bytes32 nextPKH,
        address newWhitelistedAddress
    ) 
        public 
        onlyLamportMaster(
            currentpub,
            sig,
            nextPKH,
            abi.encodePacked(newWhitelistedAddress)
        )
    {
        currentMode = ProtectionMode.WhitelistAddress;
        whitelistedAddress = newWhitelistedAddress;
    }
    function deposit() external payable {
        // Simply deposits Ether into the contract. No need for isThisFree check.
    }

    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "Only the owner can withdraw");
        if (anonID.isThisExchangeTxFree()) {
            // Logic to make this transaction free, if applicable.
            // If handled at protocol level, then just proceed.
        }
        payable(msg.sender).transfer(amount);
    }


    function transfer(address recipient, uint256 amount) external ownerOnly {
        require(isTransferAllowed(recipient, amount), "Transfer not allowed due to protection mode or exceeds limit");
        require(msg.sender == owner, "Only the owner can transfer");
        payable(recipient).transfer(amount);
        if (anonID.isThisExchangeTxFree()) {
            // Logic to make this transaction free, if applicable.
            // If handled at protocol level, then just proceed.
        }
        // Reset protection mode based on conditions
        if (currentMode == ProtectionMode.OneTimeClearance) {
            currentMode = ProtectionMode.None;
        } else if (currentMode == ProtectionMode.WhitelistAddress && recipient == whitelistedAddress) {
            currentMode = ProtectionMode.None;
        }
    }

    function transferToken(address tokenAddress, uint256 amount) external {
        require(isTransferAllowed(recipient), "Transfer not allowed due to protection mode");
        require(msg.sender == owner, "Only the owner can transfer tokens");
        if (anonID.isThisExchangeTxFree()) {
            // Logic to make this transaction free, if applicable.
            // If handled at protocol level, then just proceed.
        }
        ERC20 token = ERC20(tokenAddress);
        token.transfer(msg.sender, amount);
        if (currentMode == ProtectionMode.OneTimeClearance) {
            currentMode = ProtectionMode.None;
        } else if (currentMode == ProtectionMode.WhitelistAddress && recipient == whitelistedAddress) {
            currentMode = ProtectionMode.None;
        }
    }

    function isTransferAllowed(address recipient, uint256 amount) internal view returns (bool) {
        if (amount > transactionLimit) return false; // Check against the unified limit
        if (currentMode == ProtectionMode.None) return true;
        if (currentMode == ProtectionMode.OneTimeClearance) return true;
        if (currentMode == ProtectionMode.WhitelistAddress && recipient == whitelistedAddress) return true;
        return false;
    }
}
