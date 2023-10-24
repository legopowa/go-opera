import os
from hashlib import sha3_256
from decimal import Decimal
from typing import List
from offchain.Types import *
from web3 import Web3


# Assuming the imported classes from the previous translation:
# RandPair, PubPair, KeyPair, Sig, LamportKeyPair

def hash(input: str) -> str:
    return Web3.keccak(text=input).hex()

def hash_b(input: str) -> str:
    return Web3.keccak(hexstr=input).hex()

def pub_from_pri(pri: List[RandPair]) -> List[PubPair]:
    return [(hash_b(p[0]), hash_b(p[1])) for p in pri]

def mk_rand_num() -> str:
    return hash(os.urandom(32).hex())[2:] 

def mk_rand_pair() -> RandPair:
    return (mk_rand_num(), mk_rand_num())

def mk_pri_key() -> List[RandPair]:
    return [mk_rand_pair() for _ in range(256)]

def mk_key_pair() -> KeyPair:
    pri = mk_pri_key()
    pub = pub_from_pri([f"0x{p[0]}", f"0x{p[1]}"] for p in pri)
    return KeyPair(pri=pri, pub=pub)

def is_private_key(key: List[RandPair]) -> bool:
    return len(key) == 256


def sign_hash(hmsg: str, pri: List[RandPair]) -> Sig:
    if not is_private_key(pri):
        raise ValueError('invalid private key')
    
    msg_hash_bin = format(int(hmsg, 16), '0256b')

    if len(msg_hash_bin) != 256:
        raise ValueError(f'invalid message hash length: {len(msg_hash_bin)} --> {msg_hash_bin}')

    sig = [pri[i][int(el)] for i, el in enumerate(msg_hash_bin)]
    return sig

'''
def sign_hash(hmsg: str, pri: List[RandPair]) -> Sig:
    if not is_private_key(pri):
        raise ValueError('invalid private key')

    # Try converting hmsg to an integer. If this fails, it's likely hmsg is not a valid hexadecimal string.
    try:
        hmsg_int = int(hmsg, 16)
    except ValueError:
        print(f"Error: hmsg is not a valid hexadecimal string: {hmsg}")
        raise

    msg_hash_bin = format(hmsg_int, '0256b')

    if len(msg_hash_bin) != 256:
        print(f"Error: invalid message hash length: {len(msg_hash_bin)} --> {msg_hash_bin}")
        raise ValueError(f'invalid message hash length: {len(msg_hash_bin)} --> {msg_hash_bin}')

    sig = []
    for i, el in enumerate(msg_hash_bin):
        try:
            sig_element = pri[i][int(el)]
        except IndexError:
            print(f"Error: index {i} out of range for private key list.")
            raise
        except ValueError:
            print(f"Error: unable to convert binary element to integer: {el}")
            raise

        print(f"Appending {sig_element} to signature.")
        sig.append(sig_element)
    return sig
'''
'''
def sign_hash(hmsg: str, pri: List[RandPair]) -> Sig:
    if not is_private_key(pri):
        raise ValueError('invalid private key')
    
    msg_hash_bin = format(int(hmsg, 16), '0256b')

    if len(msg_hash_bin) != 256:
        raise ValueError(f'invalid message hash length: {len(msg_hash_bin)} --> {msg_hash_bin}')

    sig = [pri[255-i][int(el)] for i, el in enumerate(msg_hash_bin)]
    return sig
'''
def verify_signed_hash(hmsg: str, sig: Sig, pub: List[PubPair]) -> bool:
    msg_hash_bin = format(int(hmsg, 16), '0256b')
    pub_selection = [pub[i][int(way)] for i, way in enumerate(msg_hash_bin)]

    for i in range(len(pub_selection)):
        if pub_selection[i] != hash_b(f'0x{sig[i]}'):
            return False

    return True

