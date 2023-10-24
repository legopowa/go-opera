from brownie import accounts, LamportTest2
from brownie.network import gas_price
from brownie.network.gas.strategies import LinearScalingStrategy

gas_strategy = LinearScalingStrategy("60 gwei", "70 gwei", 1.1)

# if network.show_active() == "development":
gas_price(gas_strategy)

def main():
    # Replace `ContractName` with the actual name of your contract
    contract = LamportTest2.deploy({'from': accounts[0]})
    print(f"Contract deployed: {contract.address}")


    with open('contract.txt', 'w') as file:
            # Write the contract address to the file
        file.write(contract.address)
    print("Contract " + contract.address + "address saved to 'contract.txt'")
