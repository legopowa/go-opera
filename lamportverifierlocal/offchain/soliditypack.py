from eth_abi import encode_single
from web3 import Web3
from typing import List
import codecs
import re
import hashlib
import binascii
from binascii import hexlify

def solidity_pack_value_bytes(value: bytes) -> bytes:
    assert len(value) <= 32, "The bytes object is too large."
    return value.rjust(32, b'\0')

def solidity_pack_value(value):
    return binascii.hexlify(value.to_bytes(32, byteorder='big')).decode()

def solidity_pack_array(arr):
    flattened = [str(item) for sublist in arr for item in sublist]
    return ''.join(flattened)

def _pack(type: str, value, isArray: bool = False):
    if type == "address":
        if isArray:
            return bytes.fromhex(value[2:]).rjust(32, b'\x00')
        return bytes.fromhex(value[2:])
    elif type == "string":
        return value.encode('utf-8')
    elif type == "bytes":
        return bytes.fromhex(value[2:])
    elif type == "bool":
        value = '0x01' if value else '0x00'
        if isArray:
            return bytes.fromhex(value[2:]).rjust(32, b'\x00')
        return bytes.fromhex(value[2:])

    regex_number = re.compile("^(u?int)([0-9]*)$")
    match = regex_number.match(type)
    if match:
        size = int(match.group(2) or "256")
        value = int(value).to_bytes(size // 8, 'big')
        if isArray:
            value = value.rjust(32, b'\x00')
        return value

    regex_bytes = re.compile("^bytes([0-9]+)$")
    match = regex_bytes.match(type)
    if match:
        size = int(match.group(1))
        if len(bytes.fromhex(value[2:])) != size:
            raise ValueError(f"invalid value for {type}")
        if isArray:
            return bytes.fromhex(value[2:]).ljust(32, b'\x00')
        return bytes.fromhex(value[2:])

    regex_array = re.compile("^(.*)\\[([0-9]*)\\]$")
    match = regex_array.match(type)
    if match and isinstance(value, list):
        baseType = match.group(1)
        count = int(match.group(2) or str(len(value)))
        if count != len(value):
            raise ValueError(f"invalid array length for {type}")
        result = []
        for val in value:
            result.append(_pack(baseType, val, True))
        return b''.join(result)

    raise ValueError("invalid type")

def solidity_pack(types: List[str], values: List) -> str:
    if len(types) != len(values):
        raise ValueError("wrong number of values; expected %s" % len(types))
    packed_values = []
    for t, v in zip(types, values):
        packed_values.append(_pack(t, v))
    concatenated = b''.join(packed_values)
    return '0x' + concatenated.hex()

# def solidity_pack_bytes(types: List[str], values: List) -> bytes:
#     if len(types) != len(values):
#         raise ValueError("wrong number of values; expected %s" % len(types))
#     packed_values = []
#     for t, v in zip(types, values):
#         packed_values.append(_pack(t, v))
#     concatenated = b''.join(packed_values)
#     return concatenated
# def _pack(type: str, value, isArray: bool = False):
#     if type == "address":
#         if isArray:
#             return value.rjust(32, b'\x00')
#         return bytes.fromhex(value[2:])
#     elif type == "string":
#         return value.encode('utf-8')
#     elif type == "bytes":
#         return bytes.fromhex(value[2:])
#     elif type == "bool":
#         value = '0x01' if value else '0x00'
#         if isArray:
#             return bytes.fromhex(value[2:]).rjust(32, b'\x00')
#         return bytes.fromhex(value[2:])

#     regex_number = re.compile("^(u?int)([0-9]*)$")
#     match = regex_number.match(type)
#     if match:
#         size = int(match.group(2) or "256")
#         if isArray:
#             size = 256
#         value = int(value).to_bytes(size // 8, 'big')
#         return value.rjust(size // 8, b'\x00')

#     regex_bytes = re.compile("^bytes([0-9]+)$")
#     match = regex_bytes.match(type)
#     if match:
#         size = int(match.group(1))
#         if len(bytes.fromhex(value[2:])) != size:
#             raise ValueError(f"invalid value for {type}")
#         if isArray:
#             return bytes.fromhex(value[2:] + '00' * (32 - size))
#         return bytes.fromhex(value[2:])

#     regex_array = re.compile("^(.*)\\[([0-9]*)\\]$")
#     match = regex_array.match(type)
#     if match and isinstance(value, list):
#         baseType = match.group(1)
#         count = int(match.group(2) or str(len(value)))
#         if count != len(value):
#             raise ValueError(f"invalid array length for {type}")
#         result = []
#         for val in value:
#             result.append(_pack(baseType, val, True))
#         return b''.join(result)

#     raise ValueError("invalid type")

# def solidity_pack(types: List[str], values: List) -> str:
#     if len(types) != len(values):
#         raise ValueError("wrong number of values; expected %s" % len(types))
#     packed_values = []
#     for t, v in zip(types, values):
#         packed_values.append(_pack(t, v))
#     concatenated = b''.join(packed_values)
#     return '0x' + codecs.encode(concatenated, 'hex').decode()

# def solidity_pack_bytes(types: List[str], values: List) -> bytes:
#     if len(types) != len(values):
#         raise ValueError("wrong number of values; expected %s" % len(types))
#     packed_values = []
#     for t, v in zip(types, values):
#         packed_values.append(_pack(t, v))
#     concatenated = b''.join(packed_values)
#     return concatenated

def solidity_pack_pairs(pairs):
    packed_pairs = []
    for pair in pairs:
        address = pair[0]
        value = pair[1]
        #print("address, value =", address, value)
        packed_pairs.append(solidity_pack_bytes([address, value]))
    #print(packed_pairs)
    return b''.join(packed_pairs)

def solidity_pack_bytes(values):
    packed_values = []

    for value in values:
        if isinstance(value, int):
            # solidity uses big endian
            packed_value = value.to_bytes((value.bit_length() + 7) // 8, 'big').rjust(32, b'\0')
        elif isinstance(value, str) and re.match(r"^0x[a-fA-F0-9]{40}$", value):
            packed_value = bytes.fromhex(value[2:]).rjust(32, b'\0')
        elif isinstance(value, str):
            packed_value = value.encode('utf-8')
        else:
            raise ValueError("Unsupported type")
            
        packed_values.append(packed_value)
        
    return b''.join(packed_values)
def pack_keys(keys):
    # remove '0x' and concatenate
    packed = ''.join(k[2:] for pair in keys for k in pair)
    # add '0x' prefix back to the result
    return '0x' + packed

def encode_packed_2d_list(data):
    packed_bytes = b""
    for sublist in data:
        for item in sublist:
            # Here we assume that all items are hexadecimal strings.
            # Encode each item individually and add to the result.
            packed_bytes += encode_single('bytes', bytes.fromhex(item[2:]))  # item[2:] to remove '0x' if present

    return Web3.toHex(packed_bytes)
def keccak256(types: List[str], values: List) -> str:
    return Web3.solidityKeccak(types, values).hex()

def sha256(types: List[str], values: List) -> str:
    packed = solidity_pack(types, values)[2:]
    return '0x' + hashlib.sha256(bytes.fromhex(packed)).hexdigest()
def elementary_name(name):
    if name.startswith('int['):
        return 'int256' + name[3:]
    elif name == 'int':
        return 'int256'
    elif name.startswith('uint['):
        return 'uint256' + name[3:]
    elif name == 'uint':
        return 'uint256'
    elif name.startswith('fixed['):
        return 'fixed128x128' + name[3:]
    elif name == 'fixed':
        return 'fixed128x128'
    elif name.startswith('ufixed['):
        return 'ufixed128x128' + name[3:]
    elif name == 'ufixed':
        return 'ufixed128x128'
    return name

def parse_type_n(type_str):
    match = re.match(r"^\D+(\d+).*$", type_str)
    return int(match.group(1)) if match else None

def parse_type_n_array(type_str):
    match = re.match(r"^\D+\d*\[(\d+)\]$", type_str)
    return int(match.group(1)) if match else None

def encode_packed(*args):
    packed_bytes = b""

    for arg in args:
        if isinstance(arg, dict):
            t = arg['type'] if 'type' in arg else arg['t']
            v = arg['value'] if 'value' in arg else arg['v']
        else:
            if isinstance(arg, str) and arg.startswith('0x'):
                t = 'bytes'
                v = arg
            elif isinstance(arg, (int, float)):
                t = 'uint'
                v = arg
            elif isinstance(arg, bool):
                t = 'bool'
                v = arg
            else:
                raise ValueError(f"Cannot auto-detect type for {arg}")

        t = elementary_name(t)
        size_n = parse_type_n(t)
        array_size = parse_type_n_array(t)

        if t == 'bytes':
            # Encode bytes
            packed_bytes += encode_single(t, bytes.fromhex(v[2:]))
        elif t == 'string':
            # Encode string
            packed_bytes += encode_single('bytes', v.encode('utf-8'))
        elif t == 'bool':
            # Encode bool
            packed_bytes += encode_single('bytes', b'\x01' if v else b'\x00')
        elif t == 'address':
            # Encode address
            packed_bytes += encode_single('bytes', bytes.fromhex(v[2:]))
        elif t.startswith('uint'):
            # Encode uint
            if size_n and v > 2**(size_n - 1):
                raise ValueError(f"{v} exceeds {t}")
            packed_bytes += encode_single(f"uint{size_n}", v)
        elif t.startswith('int'):
            # Encode int
            if size_n and abs(v) > 2**(size_n - 1):
                raise ValueError(f"{v} exceeds {t}")
            packed_bytes += encode_single(f"int{size_n}", v)
        else:
            raise ValueError(f"Unsupported or invalid type: {t}")

    return Web3.toHex(packed_bytes)