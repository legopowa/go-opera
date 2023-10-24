import binascii

def compute_crc(data: str) -> int:
    return binascii.crc32(data.encode())

def compute_crc_bytes(data: str) -> int:
    return binascii.crc32(data)