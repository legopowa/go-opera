from brownie import accounts, AnonID_noinit, firewallet
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
    contract = AnonID_noinit.deploy({'from': accounts[0]})
    print(f"AnonID deployed: {contract.address}")

    k1 = KeyTracker("master1") # new keys made here
    k2 = KeyTracker("master2")
    k3 = KeyTracker("worker")
    # Replace `ContractName` with the actual name of your contract
    contract2 = AnonID_noinit.deploy({'from': accounts[0]})
    print(f"AnonID deployed: {contract.address}")
    master_key1 = k1.get_next_key_pair()
    master_key2 = k2.get_next_key_pair()
    worker_key1 = k3.get_next_key_pair()
    master1_pkh = k1.pkh
    master2_pkh = k2.pkh
    worker_pkh1 = k3.pkh
    print(master1_pkh, master2_pkh, worker_pkh1)
    contract2.init(
        master1_pkh,
        master2_pkh,
        worker_pkh1
    )
    k1.save("user_master1")
    k2.save("user_master2")
    k3.save("user_worker1")
    comparepkh = contract2.getKeyAndPosByPKH(master_key1)
    print(comparepkh[1])
    print(master_key1)
    if comparepkh[1] == master_key1:
        print("user_master 1 saved")
    
    comparepkh = contract2.getKeyAndPosByPKH(master_key2)
    print(comparepkh[1])
    print(master_key2)
    if comparepkh[1] == master_key2:
        print("user_master 2 saved")

    comparepkh = contract.getKeyAndPosByPKH(worker_key1)
    print(comparepkh[1])
    print(worker_key1)
    if comparepkh[1] == worker_key1:
        print("user_worker 1 saved")


    with open('contract_firewallet.txt', 'w') as file:
            # Write the contract address to the file
        file.write(contract.address)
    with open('firewallet_pkhs.txt', 'w') as file:
            # Write the contract address to the file
        file.write("user_master1 = ")
        file.write(master1_pkh) 
        file.write(" user_master2 = ")
        file.write(master2_pkh)
        file.write(" user_worker = ")
        file.write(worker_pkh1)
    print("Firewall contract " + contract.address + "address saved to 'contract.txt'; pkhs saved to pkhs.txt")

