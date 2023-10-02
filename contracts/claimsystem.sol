//SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Whitelist is ERC20 {
    ERC20 private token;
    uint256 public maxWalletsPerDatabase;
    uint256 public totalDatabases;

    mapping(uint256 => WhitelistDatabase) public databases;
    struct Wallet {
        bytes20 internalInfo;
        uint256 lastTokenClaimTime;
        uint256 totalTokens;
        bool isSet;
    }
    
    
    event TokensClaimed(address indexed wallet, uint256 amount);

    mapping(address => Wallet) public wallets;

    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    constructor() ERC20("MyToken", "MTK") {

        maxWalletsPerDatabase = 2;
        totalDatabases = 1;
        databases[1] = new WhitelistDatabase(); 
        owner = msg.sender;
        token = this;
    }
    function checkTokens() public view returns (bool canClaim, uint256 tokensToClaim) {
        WhitelistDatabase currentDatabase = getWalletDatabase(msg.sender);
        WhitelistDatabase.Wallet memory wallet = currentDatabase.getWallet(msg.sender);
        require(wallet.isSet, "Wallet not found in database");

        uint256 lastClaimTime = wallet.lastTokenClaimTime;
        uint256 currentTime = block.timestamp;
        if (lastClaimTime > currentTime) {
            lastClaimTime = currentTime;
        }

        //require(wallet.lastTokenClaimTime != currentTime, "currentTime is wallet time for some reason");

        uint256 timeSinceLastClaim = currentTime - lastClaimTime;

        canClaim = timeSinceLastClaim >= 10;
        //tokensToAdd = (timeSinceLastClaim / 30) * 10; // reward 10 tokens every 10 seconds
        uint256 tokensToAdd = SafeMath.mul(SafeMath.div(timeSinceLastClaim, 30), 10);
        tokensToClaim = 0;

        if (canClaim && tokensToAdd > 0) {
            uint256 remainingTokens = wallet.totalTokens % 10;
            if (remainingTokens > 0) {
                uint256 tokensNeeded = 10 - remainingTokens;
                if (tokensToAdd >= tokensNeeded) {
                    tokensToClaim = tokensNeeded;
                }
            } else {
                tokensToClaim = tokensToAdd;
            }
        }
    } 
    modifier onlyOwner() { // used to define function ownership; owner = contract maker
        require(msg.sender == owner, "Whitelist: caller is not the owner");
        _;
    }

    function addWallet(address _wallet, bytes20 _internalInfo) public onlyOwner {
        // adds wallet to database stored on other smart contracts that are made on the fly
        // adds wallet address and 20 bytes of internal info, also the size of a wallet address in hex
        WhitelistDatabase currentDatabase = databases[totalDatabases];
        uint256 currentDatabaseWalletCount = currentDatabase.walletCount();

        if (currentDatabaseWalletCount == maxWalletsPerDatabase) {
            totalDatabases++;
            databases[totalDatabases] = new WhitelistDatabase(); 
            currentDatabase = databases[totalDatabases];
        }

        currentDatabase.addWallet(_wallet, _internalInfo);
    }

    function removeWallet(address _wallet) public onlyOwner {
        // removes wallet from database
        WhitelistDatabase currentDatabase = databases[totalDatabases];
        uint256 currentDatabaseWalletCount = currentDatabase.walletCount();

        if (currentDatabaseWalletCount == 0 && totalDatabases > 1) {
            delete databases[totalDatabases];
            totalDatabases--;
            currentDatabase = databases[totalDatabases];
        }

        currentDatabase.removeWallet(_wallet);
    }
    function claimTokens() public {
        WhitelistDatabase currentDatabase = getWalletDatabase(msg.sender);
        WhitelistDatabase.Wallet memory wallet = currentDatabase.getWallet(msg.sender);
        //Wallet storage wallet = currentDatabase.getWallet(msg.sender);
        require(wallet.isSet, "Wallet not found in database");

        uint256 lastClaimTime = wallet.lastTokenClaimTime;
        uint256 currentTime = block.timestamp;
        if (lastClaimTime > currentTime) {
            lastClaimTime = currentTime;
        }

        require(wallet.lastTokenClaimTime != currentTime, "currentTime is wallet time for some reason");

        uint256 timeSinceLastClaim = currentTime - lastClaimTime;

        require(timeSinceLastClaim >= 10, "Cooldown period has not elapsed yet");
        currentDatabase.setWalletTokenTime(msg.sender, currentTime);
        wallet = currentDatabase.getWallet(msg.sender);

        require(wallet.lastTokenClaimTime == currentTime, "currentTime didn't carry over to wallet");

        //uint256 tokensToAdd = (timeSinceLastClaim / 30) * 10; // reward 10 tokens every 10 seconds
        uint256 tokensToAdd = SafeMath.mul(SafeMath.div(timeSinceLastClaim, 30), 10);

        require(tokensToAdd > 0, "No tokens available to claim");

        uint256 remainingTokens = wallet.totalTokens % 10;
        uint256 tokensToClaim = tokensToAdd;
        if (remainingTokens > 0) {
            uint256 tokensNeeded = 10 - remainingTokens;
            if (tokensToAdd >= tokensNeeded) {
                tokensToClaim = tokensNeeded;
            } else {
                tokensToClaim = 0;
            }
        }

        require(tokensToClaim > 0, "No tokens available to claim");

        uint256 totalTokens2 = currentDatabase.getWallet(msg.sender).totalTokens;
        totalTokens2 += tokensToClaim;
        currentDatabase.setWalletTokenTotal(msg.sender, totalTokens2);

        emit TokensClaimed(msg.sender, tokensToClaim);

        _mint(msg.sender, tokensToClaim); // mint tokens to user's wallet
        uint256 ownerTokens = SafeMath.div(tokensToClaim, 20);
        _mint(owner, ownerTokens); // mint tokens to owner's wallet
    }
    // get wallet info; for debugging purposes
    function getWalletInfo(address _wallet) public view returns (bytes20, uint256, uint256, bool) {
        WhitelistDatabase currentDatabase = getWalletDatabase(_wallet);
        WhitelistDatabase.Wallet memory wallet = currentDatabase.getWallet(_wallet); 
        return (wallet.internalInfo, wallet.lastTokenClaimTime, wallet.totalTokens, wallet.isSet);
    }
    // pull database given wallet is on; debugging purposes
    function getWalletDatabase(address _wallet) public view returns (WhitelistDatabase) {
        for (uint256 i = 1; i <= totalDatabases; i++) {
            WhitelistDatabase currentDatabase = databases[i];
            if (currentDatabase.isWalletInDatabase(_wallet)) {
                return currentDatabase;
            }
        }
        revert("Whitelist: wallet not found in database");
    }
    // total wallet count; debugging purposes
    function getTotalWalletCount() public view returns (uint256) {
        uint256 totalWallets = 0;
        for (uint256 i = 1; i <= totalDatabases; i++) {
            totalWallets += databases[i].walletCount();
        }
        return totalWallets;
    }
    // total token balances
    function getTotalTokenBalance() public view returns (uint256) {
        uint256 totalBalance = 0;
        for (uint256 i = 1; i <= totalDatabases; i++) {
            totalBalance += databases[i].getTokenBalance();
        }
        return totalBalance;
    }


    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Whitelist: new owner is the zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
    fallback() external payable {
        revert("Whitelist: Invalid function call");
    }
} 

contract WhitelistDatabase { 

    struct Wallet {
        bytes20 internalInfo;
        uint256 lastTokenClaimTime;
        uint256 totalTokens;
        bool isSet;
    }
    address public owner;
    constructor () {
        owner = msg.sender;
    }
    uint256 public totalWallets;
    mapping(address => Wallet) public wallets;

    // add and remove wallet functions have to be included on the child databases
    function addWallet(address _wallet, bytes20 _internalInfo) public {
        require(!wallets[_wallet].isSet, "WhitelistDatabase: wallet already in database");

        Wallet memory walletToAdd = Wallet({
            internalInfo: _internalInfo,
            lastTokenClaimTime: block.timestamp,
            totalTokens: 0,
            isSet: true
        });

        wallets[_wallet] = walletToAdd;
        totalWallets++;
    }

    function removeWallet(address _wallet) public {
        require(wallets[_wallet].isSet, "WhitelistDatabase: wallet not in database");

        delete wallets[_wallet];
        totalWallets--;
    }

    function getWalletInfo(address _wallet) public view returns (bytes20, uint256, uint256, bool) {
        require(wallets[_wallet].isSet, "WhitelistDatabase: wallet not in database");
        return(wallets[_wallet].internalInfo, wallets[_wallet].lastTokenClaimTime, wallets[_wallet].totalTokens, wallets[_wallet].isSet);
    }

    function isWalletInDatabase(address _wallet) public view returns (bool) {
        return wallets[_wallet].isSet;
    }

    function walletCount() public view returns (uint256) {
        return totalWallets;
    }
    function getWallet(address _wallet) public view returns (Wallet memory) {
        require(wallets[_wallet].isSet, "WhitelistDatabase: wallet not in database");
        return wallets[_wallet];
    }
    modifier onlyOwner() { // used to define function ownership; owner = contract maker
        require(msg.sender == owner, "WhitelistDatabase: caller is not the owner");
        _;
    }
    // function setWallet(address _wallet, bytes20 _internalInfo, uint256 _lastTokenClaimTime, uint256 _totalTokens, bool _isSet) public onlyOwner {
    //     require(wallets[_wallet].isSet, "WhitelistDatabase: wallet not in database");

    //     wallets[_wallet].internalInfo = _internalInfo;
    //     wallets[_wallet].lastTokenClaimTime = _lastTokenClaimTime;
    //     wallets[_wallet].totalTokens = _totalTokens;
    //     wallets[_wallet].isSet = _isSet;
    // }
    function setWalletTokenTime(address _wallet, uint256 _lastTokenClaimTime) public onlyOwner {
        require(wallets[_wallet].isSet, "WhitelistDatabase: wallet not in database");

        wallets[_wallet].lastTokenClaimTime = _lastTokenClaimTime;
        
    }
    function setWalletTokenTotal(address _wallet, uint256 _totalTokens) public onlyOwner {
        require(wallets[_wallet].isSet, "WhitelistDatabase: wallet not in database");
        wallets[_wallet].totalTokens = _totalTokens;
    }
    function getTokenBalance() public view returns (uint256) {
        return address(this).balance;
    }

}

