from web3 import Web3

# Create a connection to your local Ganache
w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

# Get list of accounts
accounts = w3.eth.accounts

# Print accounts
for account in accounts:
    print(account)
