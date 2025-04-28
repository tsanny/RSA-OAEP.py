from sha256 import SHA256
from typing import Tuple
import os
import random, sympy


def generate_prime(bits: int) -> int:
    """
    Generates a prime number of specified bit length.

    Args:
        bits (int): The bit length of the prime number to generate.

    Returns:
        int: A prime number of the specified bit length.
    """
    lower = 1 << (bits - 1)
    upper = 1 << bits

    return sympy.randprime(lower, upper)


def modinv(a: int, m: int) -> int:
    """
    Modular inverse of a % m using extended Euclidean algorithm

    Args:
        a (int): The number to find the inverse of.
        m (int): The modulus.

    Returns:
        int: The modular inverse of a % m.
    """
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
    """
    Given a seed, generates a pseudorandom mask of a desired length using a hash function.
    In this case, uses SHA256

    Args:
        seed (bytes): The input seed for the mask generation.
        length (int): Desired length of the output mask in bytes.
        hash_cls (class): Hash function class to use

    Returns:
        bytes: A mask of the specified length.
    """
    counter = 0
    output = b""
    while len(output) < length:
        c = counter.to_bytes(4, "big")
        output += hash_cls(seed + c).digest()
        counter += 1
    return output[:length]  # Truncate to asked length


def oaep_encode(message: bytes, k: int, label: bytes = b"", hash_cls=SHA256) -> bytes:
    """
    Prepares a message for secure encryption with RSA by padding it using OAEP scheme.

    Args:
        message (bytes): The input message to encode.
        k (int): The length of the RSA modulus in bytes.
        label (bytes): An optional label associated with the message (default empty).
        hash_cls (class): Hash function class to use (default is SHA256).

    Returns:
        bytes: The OAEP encoded message ready for RSA encryption.
    """
    hLen = hash_cls().digest_size
    mLen = len(message)

    if mLen > k - 2 * hLen - 2:
        raise ValueError("Message too long")

    lHash = hash_cls(label).digest()
    PS = b"\x00" * (k - mLen - 2 * hLen - 2)  # PS is padding made of 0x00 bytes
    DB = lHash + PS + b"\x01" + message  # lHash || PS || 0x01 || M
    seed = os.urandom(hLen)
    dbMask = mgf1(seed, k - hLen - 1, hash_cls)  # dbMask = MGF(seed)
    maskedDB = xor_bytes(DB, dbMask)
    seedMask = mgf1(maskedDB, hLen, hash_cls)  # seedMask = MGF(maskedDB)
    maskedSeed = xor_bytes(seed, seedMask)

    return b"\x00" + maskedSeed + maskedDB


def oaep_decode(
    encoded_message: bytes, k: int, label: bytes = b"", hash_cls=SHA256
) -> bytes:
    """
    Recovers the original message from an OAEP encoded message after RSA decryption.

    Args:
        encoded_message (bytes): The OAEP encoded message after RSA decryption.
        k (int): The length of the RSA modulus in bytes.
        label (bytes): An optional label associated with the message (default empty).
        hash_cls (class): Hash function class to use (default is SHA256).

    Returns:
        bytes: The original decoded message.
    """
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


def parse_hex_key_file(file_path: str) -> Tuple[int, int]:
    """
    Parses a hex key file and returns the modulus (n) and exponent (e).

    Args:
        file_path (str): Path to the key file.

    Returns:
        Tuple[int, int]: Modulus (n) and exponent (e) as integers.
    """
    with open(file_path, "r") as f:
        line = f.read().strip()

    parts = line.split(",")
    if len(parts) != 2:
        raise ValueError("Invalid key file format. Expected format: <hex>,<hex>")

    n = int(parts[0], 16)
    e = int(parts[1], 16)

    return n, e
