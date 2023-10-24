import lorem
from brownie import web3, accounts, Wei, Contract
from eth_utils import encode_hex, keccak
from typing import List
import json
from pydantic import BaseModel
import time
from offchain.KeyTracker import KeyTracker
from offchain.Types import LamportKeyPair, Sig, PubPair
from offchain.functions import hash_b, sign_hash, verify_signed_hash

ITERATIONS = 3

class LamportTest:
    def __init__(self):
        self.contract = Contract('LamportTest2')

    async def can_broadcast_message_via_broadcast2(self, accs: List[str]):
        print(f"hash_b(0): {hash_b('0x00')}")
        _contract = await self.contract.deploy({'from': accs[0]})
        k = KeyTracker()

        await _contract.init(k.pkh)

        b1 = web3.eth.getBalance(accs[0])
        print(f"balance before: {b1}")

        for i in range(ITERATIONS):
            current_keys = k.currentKeyPair()
            next_keys = k.getNextKeyPair()

            expectedPKH = await _contract.getPKH()
            assert KeyTracker.pkhFromPublicKey(current_keys.pub) == expectedPKH

            nextpkh = KeyTracker.pkhFromPublicKey(next_keys.pub)

            messageToBroadcast = lorem.sentence()
            packed = web3.solidityKeccak(['string', 'bytes32'], [messageToBroadcast, nextpkh])
            callhash = hash_b(encode_hex(packed))
            sig = sign_hash(callhash, current_keys.pri)

            is_valid_sig = verify_signed_hash(callhash, sig, current_keys.pub)
            assert is_valid_sig == True

            print("sig is valid")

            await _contract.broadcast(
                messageToBroadcast,
                current_keys.pub,
                nextpkh,
                list(map(lambda s: f"0x{s}", sig)),
                {'from': accs[0]}
            )

        b2 = web3.eth.getBalance(accs[0])
        print(f"balance after: {b2}")

        b_delta = b1 - b2
        print(f"balance delta: {b_delta}")

        datum = {
            "ts": int(time.time()),
            "avg_gas": str(b_delta / ITERATIONS),
            "iterations": ITERATIONS,
        }

        with open('gas_data2.json', 'r') as json_file:
            gas_data = json.load(json_file)

        gas_data.append(datum)

        with open('gas_data.json', 'w') as json_file:
            json.dump(gas_data, json_file, indent=2)

    # Define other methods...
