from sha256 import SHA256
import os


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed: bytes, length: int, hash_cls=SHA256):
    counter = 0
    output = b""
    while len(output) < length:
        c = counter.to_bytes(4, "big")
        output += hash_cls(seed + c).digest()
        counter += 1
    return output[:length]


def oaep_encode(message: bytes, k: int, label: bytes = b"", hash_cls=SHA256) -> bytes:
    hLen = hash_cls().digest_size
    mLen = len(message)

    if mLen > k - 2 * hLen - 2:
        raise ValueError("Message too long")

    lHash = hash_cls(label).digest()
    PS = b"\x00" * (k - mLen - 2 * hLen - 2)
    DB = lHash + PS + b"\x01" + message
    seed = os.urandom(hLen)
    dbMask = mgf1(seed, k - hLen - 1, hash_cls)
    maskedDB = xor_bytes(DB, dbMask)
    seedMask = mgf1(maskedDB, hLen, hash_cls)
    maskedSeed = xor_bytes(seed, seedMask)

    return b"\x00" + maskedSeed + maskedDB


def oaep_decode(
    encoded_message: bytes, k: int, label: bytes = b"", hash_cls=SHA256
) -> bytes:
    hLen = hash_cls().digest_size

    Y = encoded_message[0]
    maskedSeed = encoded_message[1 : hLen + 1]
    maskedDB = encoded_message[hLen + 1 :]

    if Y != 0:
        raise ValueError("Decoding error")

    seedMask = mgf1(maskedDB, hLen, hash_cls)
    seed = xor_bytes(maskedSeed, seedMask)

    dbMask = mgf1(seed, k - hLen - 1, hash_cls)
    DB = xor_bytes(maskedDB, dbMask)  # lHash || PS || 0x01 || M

    # get M from DB
    lHash = hash_cls(label).digest()

    if DB[:hLen] != lHash:
        raise ValueError("label hash mismatch")

    for i in range(hLen, len(DB)):
        if DB[i] == 0x01:
            message = DB[i + 1 :]
            break
    else:
        raise ValueError("0x01 separator not found")

    return message
