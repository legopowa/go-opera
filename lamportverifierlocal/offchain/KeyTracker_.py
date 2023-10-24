import os
import json
from typing import List
from web3 import Web3
from offchain.Types import *
from offchain.functions import *
from web3.exceptions import InvalidAddress
from eth_utils import keccak, encode_hex
import binascii

# Assuming the imported classes and functions from the previous translation:
# RandPair, PubPair, LamportKeyPair, mk_key_pair, hash_b

class KeyTracker:
    def __init__(self, _name: str = 'default'):
        self.private_keys: List[List[RandPair]] = []
        self.public_keys: List[List[PubPair]] = []
        self.keys_map: Dict[str, int] = {}
        self.savefile_index = 0  # Add this line in your __init__ method
        self.name: str = _name
        self.w3 = Web3()  # Create an instance of Web3

    @staticmethod
    #def pkh_from_public_key(pub: List[PubPair]) -> str:
    #    packed_pub = Web3.soliditySha3(['bytes32[2][256]'], [pub])
    #    return hash_b(packed_pub.hex())
    def pkh_from_public_key(pub: List[PubPair]) -> str:
        packed_pub = Web3.solidityKeccak(['bytes32[2][256]'], [pub])
        return encode_hex(packed_pub)

    @property
    def pkh(self):
        return KeyTracker.pkh_from_public_key(self.current_key_pair().pub)

    def save(self, trim: bool = False):
        if trim:
            _private_keys = self.private_keys[-9:]
            _public_keys = self.public_keys[-9:]
        else:
            _private_keys = self.private_keys
            _public_keys = self.public_keys

        data = {
            'privateKeys': _private_keys,
            'publicKeys': _public_keys,
            'keysMap': self.keys_map,
            'name': self.name
        }
        os.makedirs('keys', exist_ok=True)

        filename = f'keys/{self.name}_{self.savefile_index}.json'
        with open(filename, 'w') as file:
            json.dump(data, file, indent=2)

        # Switch to the other file for the next save operation
        #self.savefile_index = 1 - self.savefile_index
        self.savefile_index = (self.savefile_index + 1) % 9

    @staticmethod
    def load(self, name: str, contract_pkh: str):
        for file_number in range(9):
            filename = f'keys/{name}_{file_number}.json'
            try:
                with open(filename, 'r') as file:
                    data = json.load(file)
                key_tracker = KeyTracker()

                # Update attributes using correct keys
                key_tracker.private_keys = data.get('privateKeys', [])
                key_tracker.public_keys = data.get('publicKeys', [])
                key_tracker.name = data.get('name', '')
                keys_map = data.get('keysMap', {})

                # Convert keys_map back to dictionary with correct types
                key_tracker.keys_map = {k: int(v) for k, v in keys_map.items()}

                try:
                    key_pair = key_tracker.get_key_pair_by_pkh(contract_pkh)
                    print(f"Loaded key pair for {contract_pkh} from {filename}")
                    return key_pair
                except ValueError:
                    print(f"No key pair for {contract_pkh} found in {filename}. Trying next file.")

            except FileNotFoundError:
                print(f"File {filename} does not exist.")
            except json.JSONDecodeError:
                print(f"File {filename} is not valid JSON.")
            except Exception as e:
                print(f"An unexpected error occurred while loading the file: {e}")

        print(f"No key pair for {contract_pkh} found in any file. Generating new key pair.")
        # If no valid keys found, create a new key pair
        key_tracker = KeyTracker(name=name)
        key_tracker.get_next_key_pair()
        return key_tracker

    def get_next_key_pair(self) -> LamportKeyPair:
        key_pair = mk_key_pair()
        pri = key_pair.pri
        pub = key_pair.pub
        self.private_keys.append(pri)
        self.public_keys.append(pub)
        self.keys_map[self.pkh_from_public_key(pub)] = len(self.public_keys) - 1
        return LamportKeyPair(pri=pri, pub=pub)

    def current_key_pair(self) -> LamportKeyPair:
        if not self.private_keys:
            print('not self private keys(?)')
            return self.get_next_key_pair()
        return LamportKeyPair(pri=self.private_keys[-1], pub=self.public_keys[-1])

    def previous_key_pair(self) -> LamportKeyPair:
        if len(self.private_keys) < 2:
            raise ValueError('no previous key pair')
        return LamportKeyPair(pri=self.private_keys[-2], pub=self.public_keys[-2])

    def get_key_pair_by_pkh(self, pkh: str) -> LamportKeyPair:
        if pkh in self.keys_map:
            index = self.keys_map[pkh]
            return LamportKeyPair(pri=self.private_keys[index], pub=self.public_keys[index])
        else:
            raise ValueError(f"No key pair found for pkh: {pkh}")
