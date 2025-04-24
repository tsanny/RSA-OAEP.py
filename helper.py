from sha256 import SHA256
import os, random
import base64

def prime_checker(n, k):
    # if n <= 1:
    #     return False
    # if n <= 3:
    #     return True
    # if n % 2 == 0:
    #     return False

    r, s = 0, n-1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r-1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1 # starts and ends with 1
        if prime_checker(p, 40):
            return p

def modinv(a, m):
    """Modular inverse of a % m using extended Euclidean algorithm"""
    y2, y1 = 0, 1
    r, new_r = m, a

    while new_r != 0:
        q = r // new_r
        y2, y1 = y1, y2 - q * y1
        r, new_r = new_r, r - q * new_r

    if r != 1:
        raise ValueError(f"gcd({a}, {m}) != 1")
    return y2 % m


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

def parse_hex_key(file_path):
    with open(file_path, 'r') as f:
        line = f.read().strip()

    parts = line.split(',')
    if len(parts) != 2:
        raise ValueError("Invalid key file format. Expected format: <hex>,<hex>")

    n = int(parts[0], 16)
    e = int(parts[1], 16)
    return n, e
