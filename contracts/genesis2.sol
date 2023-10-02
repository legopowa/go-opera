// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract GenesisContract is ERC20 {
    // State variables from GenesisContract
    address public owner;
    mapping(address => bool) public whitelistedAddresses;
    mapping(address => bool) public permittedContracts;

    // State variables from Whitelist
    struct Wallet {
        bytes20 internalInfo;
        uint256 lastTokenClaimTime;
        uint256 totalTokens;
        bool isSet;
    }
    mapping(address => Wallet) public wallets;
    uint256 public totalWalletsCount = 0;

    event TokensClaimed(address indexed wallet, uint256 amount);

    constructor() ERC20("Ganpati", "GP") {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier onlyPermitted() {
        require(permittedContracts[msg.sender] || msg.sender == owner, "Not a permitted contract");
        _;
    }

    // Functions from GenesisContract
    function addPermittedContract(address contractAddress) external onlyOwner {
        permittedContracts[contractAddress] = true;
    }
    
    function removePermittedContract(address contractAddress) external onlyOwner {
        permittedContracts[contractAddress] = false;
    }

    function whitelistAddress(address _address) external onlyPermitted {
        whitelistedAddresses[_address] = true;
    }

    function removeWhitelistAddress(address _address) external onlyPermitted {
        whitelistedAddresses[_address] = false;
    }

    function checkTokens() public view returns (bool canClaim, uint256 tokensToClaim) {
        Wallet memory wallet = wallets[msg.sender];
        require(wallet.isSet, "Wallet not registered");

        uint256 currentTime = block.timestamp;
        uint256 timeSinceLastClaim = currentTime - wallet.lastTokenClaimTime;

        canClaim = timeSinceLastClaim >= 10;
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
        return (canClaim, tokensToClaim);
    }


    function addWallet(address _wallet, bytes20 _internalInfo) public onlyOwner {
        require(!wallets[_wallet].isSet, "Whitelist: wallet already exists");

        wallets[_wallet] = Wallet({
            internalInfo: _internalInfo,
            lastTokenClaimTime: block.timestamp,
            totalTokens: 0,
            isSet: true
        });

        totalWalletsCount++;
    }

    function removeWallet(address _wallet) public onlyOwner {
        require(wallets[_wallet].isSet, "Whitelist: wallet not found");

        delete wallets[_wallet];
        totalWalletsCount--;
    }

    function claimTokens() public {
        Wallet storage wallet = wallets[msg.sender];
        require(wallet.isSet, "Wallet not registered");

        uint256 currentTime = block.timestamp;
        uint256 timeSinceLastClaim = currentTime - wallet.lastTokenClaimTime;

        require(timeSinceLastClaim >= 10, "Cooldown period has not elapsed yet");
        wallet.lastTokenClaimTime = currentTime; // Update the last claim time

        // Calculate tokens to add
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

        wallet.totalTokens += tokensToClaim; // Update the total tokens for the wallet

        emit TokensClaimed(msg.sender, tokensToClaim);

        _mint(msg.sender, tokensToClaim); // Mint tokens to user's wallet
        uint256 ownerTokens = SafeMath.div(tokensToClaim, 20);
        _mint(owner, ownerTokens); // Mint tokens to owner's wallet
    }

    // get wallet info; for debugging purposes
    function getWalletInfo(address _wallet) public view returns (bytes20, uint256, uint256, bool) {
        require(wallets[_wallet].isSet, "Whitelist: wallet not found");
        Wallet memory w = wallets[_wallet];
        return (w.internalInfo, w.lastTokenClaimTime, w.totalTokens, w.isSet);
    }
    // pull database given wallet is on; debugging purposes

    // total wallet count; debugging purposes
    function getTotalWalletCount() public view returns (uint256) {
        return totalWalletsCount;
    }

    // total token balances
    function getTokenBalance() public view returns (uint256) {
        return balanceOf(address(this));
    }


    function setWalletTokenTime(address _wallet, uint256 _lastTokenClaimTime) public onlyOwner {
        require(wallets[_wallet].isSet, "Whitelist: wallet not found");
        wallets[_wallet].lastTokenClaimTime = _lastTokenClaimTime;
    }

    function setWalletTokenTotal(address _wallet, uint256 _totalTokens) public onlyOwner {
        require(wallets[_wallet].isSet, "Whitelist: wallet not found");
        wallets[_wallet].totalTokens = _totalTokens;
    }


    fallback() external payable {
        revert("GenesisContract: Invalid function call");
    }
}
