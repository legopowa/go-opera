from brownie import accounts, LamportTest2
from brownie.network import gas_price
from brownie.network.gas.strategies import LinearScalingStrategy
#import signal
import sys
import json
import base64
import time
import ast
from typing import List
import codecs
import re
import hashlib
import binascii
from eth_abi import encode
from offchain.KeyTracker_ import KeyTracker, InvalidAddress
from offchain.soliditypack import solidity_pack, solidity_pack_bytes, solidity_pack_pairs
from offchain.soliditypack import _pack 
from time import sleep
from binascii import crc32, hexlify
#from offchain.fortress_functions import validate_pkh, validate_pkh_wait, ValidResponseFound, send_file, send_pubkey, f_save_received_data, f_sign_and_send, send_signed_files
import offchain.data_temp
from offchain.functions import hash_b, sign_hash, verify_signed_hash
from offchain.Types import LamportKeyPair, Sig, PubPair




gas_strategy = LinearScalingStrategy("60 gwei", "70 gwei", 1.1)

# if network.show_active() == "development":
gas_price(gas_strategy)

def main():
    k1 = KeyTracker("master1") # new keys made here
    k2 = KeyTracker("master2")
    k3 = KeyTracker("oracle1")
    # Replace `ContractName` with the actual name of your contract
    contract = LamportTest2.deploy({'from': accounts[0]})
    print(f"Contract deployed: {contract.address}")
    master_key1 = k1.get_next_key_pair()
    master_key2 = k2.get_next_key_pair()
    oracle_key1 = k3.get_next_key_pair()
    master1_pkh = k1.pkh
    master2_pkh = k2.pkh
    oracle_pkh1 = k3.pkh
    print(master1_pkh, master2_pkh, oracle_pkh1)
    contract.init(
        master1_pkh,
        master2_pkh,
        oracle_pkh1
    )
    k1.save("master1")
    k2.save("master2")
    k3.save("oracle1")
    # comparepkh = contract.getKeyAndPosByPKH(master_key1)
    # print(comparepkh[1])
    # print(master_key1)
    # if comparepkh[1] == master_key1:
    #     print("master 1 saved")
    
    # comparepkh = contract.getKeyAndPosByPKH(master_key2)
    # print(comparepkh[1])
    # print(master_key2)
    # if comparepkh[1] == master_key2:
    #     print("master 2 saved")

    # comparepkh = contract.getKeyAndPosByPKH(oracle_key1)
    # print(comparepkh[1])
    # print(oracle_key1)
    # if comparepkh[1] == oracle_key1:
    #     print("oracle 1 saved")


    with open('contract.txt', 'w') as file:
            # Write the contract address to the file
        file.write(contract.address)
    with open('pkhs.txt', 'w') as file:
            # Write the contract address to the file
        file.write("master1 = ")
        file.write(master1_pkh) 
        file.write(" master2 = ")
        file.write(master2_pkh)
        file.write(" oracle = ")
        file.write(oracle_pkh1)
    print("Contract " + contract.address + "address saved to 'contract.txt'; pkhs saved to pkhs.txt")

