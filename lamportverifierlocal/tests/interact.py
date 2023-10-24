from web3 import Web3, HTTPProvider
import json
import os
from dotenv import load_dotenv
from lorem import sentence
from offchain.KeyTracker import KeyTracker
from offchain.functions import hash_b, sign_hash, verify_signed_hash

load_dotenv()
private_key = "0xca9134b3cba5f3b221ee45c3ac1ba486a8ea4ffb90d103e8ade66317be815bed"
contract_address = "0xe22F7E8491a02e5Fa9c979b055Bfee9837cC8461"

provider = HTTPProvider('http://localhost:8545')

contract_abi = [   
    {
    "anonymous": False,
    "inputs": [
        {
        "indexed": False,
        "internalType": "string",
        "name": "message",
        "type": "string"
        }
    ],
    "name": "Message",
    "type": "event"
    },
    {
    "anonymous": False,
    "inputs": [
        {
        "indexed": False,
        "internalType": "string",
        "name": "message",
        "type": "string"
        },
        {
        "indexed": False,
        "internalType": "uint256",
        "name": "number",
        "type": "uint256"
        }
    ],
    "name": "MessageWithNumber",
    "type": "event"
    },
    {
    "anonymous": False,
    "inputs": [
        {
        "indexed": False,
        "internalType": "string",
        "name": "message",
        "type": "string"
        },
        {
        "indexed": False,
        "internalType": "uint256",
        "name": "number",
        "type": "uint256"
        },
        {
        "indexed": False,
        "internalType": "address",
        "name": "addr",
        "type": "address"
        }
    ],
    "name": "MessageWithNumberAndAddress",
    "type": "event"
    },
    {
    "inputs": [
        {
        "internalType": "string",
        "name": "messageToBroadcast",
        "type": "string"
        },
        {
        "internalType": "bytes32[2][256]",
        "name": "currentpub",
        "type": "bytes32[2][256]"
        },
        {
        "internalType": "bytes32",
        "name": "nextPKH",
        "type": "bytes32"
        },
        {
        "internalType": "bytes[256]",
        "name": "sig",
        "type": "bytes[256]"
        }
    ],
    "name": "broadcast",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
    },
    {
    "inputs": [
        {
        "internalType": "string",
        "name": "messageToBroadcast",
        "type": "string"
        },
        {
        "internalType": "uint256",
        "name": "numberToBroadcast",
        "type": "uint256"
        },
        {
        "internalType": "bytes32[2][256]",
        "name": "currentpub",
        "type": "bytes32[2][256]"
        },
        {
        "internalType": "bytes32",
        "name": "nextPKH",
        "type": "bytes32"
        },
        {
        "internalType": "bytes[256]",
        "name": "sig",
        "type": "bytes[256]"
        }
    ],
    "name": "broadcastWithNumber",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
    },
    {
    "inputs": [
        {
        "internalType": "string",
        "name": "messageToBroadcast",
        "type": "string"
        },
        {
        "internalType": "uint256",
        "name": "numberToBroadcast",
        "type": "uint256"
        },
        {
        "internalType": "address",
        "name": "addrToBroadcast",
        "type": "address"
        },
        {
        "internalType": "bytes32[2][256]",
        "name": "currentpub",
        "type": "bytes32[2][256]"
        },
        {
        "internalType": "bytes32",
        "name": "nextPKH",
        "type": "bytes32"
        },
        {
        "internalType": "bytes[256]",
        "name": "sig",
        "type": "bytes[256]"
        }
    ],
    "name": "broadcastWithNumberAndAddress",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
    },
    {
    "inputs": [],
    "name": "getPKH",
    "outputs": [
        {
        "internalType": "bytes32",
        "name": "",
        "type": "bytes32"
        }
    ],
    "stateMutability": "view",
    "type": "function"
    },
    {
    "inputs": [
        {
        "internalType": "bytes32",
        "name": "firstPKH",
        "type": "bytes32"
        }
    ],
    "name": "init",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
    },
    {
    "inputs": [
        {
        "internalType": "uint256",
        "name": "bits",
        "type": "uint256"
        },
        {
        "internalType": "bytes[256]",
        "name": "sig",
        "type": "bytes[256]"
        },
        {
        "internalType": "bytes32[2][256]",
        "name": "pub",
        "type": "bytes32[2][256]"
        }
    ],
    "name": "verify_u256",
    "outputs": [
        {
        "internalType": "bool",
        "name": "",
        "type": "bool"
        }
    ],
    "stateMutability": "pure",
    "type": "function"
    }
]

web3 = Web3(provider)
account = web3.eth.account.privateKeyToAccount(private_key)
with open('./contract_abi.json', 'r') as abi_file:
    print(f"Loaded Contract ABI: {contract_abi}") # Debug line



contract = web3.eth.contract(
    address=web3.toChecksumAddress(contract_address),
    abi=contract_abi,
)

pub_key = contract.functions.currentpub()

kt = KeyTracker.load("default")
oldkeys = kt.current_key_pair()

for i in range(256):
    local = oldkeys.pub[i]
    if local[0] != pub_key[i][0] or local[1] != pub_key[i][1]:
        raise Exception("key mismatch")

newkeys = kt.get_next_key_pair()
kt.save(True)

message = f"Hello, World! {sentence()}"

packed = web3.solidityKeccak(['string', 'bytes32[2][256]'], [message, newkeys.pub])
hashed = hash_b(packed)
sig = sign_hash(hashed, oldkeys.pri)

verified = verify_signed_hash(hashed, sig, oldkeys.pub)
print("verified locally", verified)

tx_hash = contract.functions.broadcast(message, newkeys.pub, [f"0x{s}" for s in sig]).transact({'from': account.address})
print("broadcast tx", tx_hash)

tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
print("broadcast result", tx_receipt)

