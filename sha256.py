import struct
from typing import List, Union

# FIPS 180-4 SHA-256 Implementation with detailed typing and docstrings
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

# SHA-256 Constants (First 32 bits of fractional parts of cube roots of first 64 primes)
K: List[int] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f7,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Initial Hash Values (First 32 bits of fractional parts of square roots of first 8 primes)
H0: int = 0x6a09e667
H1: int = 0xbb67ae85
H2: int = 0x3c6ef372
H3: int = 0xa54ff53a
H4: int = 0x510e527f
H5: int = 0x9b05688c
H6: int = 0x1f83d9ab
H7: int = 0x5be0cd19


def right_rotate(value: int, bits: int) -> int:
    """
    Perform a right rotation on a 32-bit integer.

    Args:
        value (int): 32-bit integer to rotate.
        bits  (int): Number of positions to rotate.

    Returns:
        int: The rotated 32-bit result.
    """
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF


def sha256_pad_message(message: Union[str, bytes]) -> bytes:
    """
    Pad the input message according to the SHA-256 specification.

    The message is padded with a '1' bit, followed by '0' bits, until
    the length (in bits) modulo 512 equals 448, then the original
    message length is appended as a 64-bit big-endian integer.

    Args:
        message (Union[str, bytes]): Input data to pad.

    Returns:
        bytes: Padded message ready for chunk processing.
    """
    if isinstance(message, str):
        message = message.encode('utf-8')

    length_bits = len(message) * 8

    # Append the mandatory '1' bit (0x80)
    padded = message + b'\x80'

    # Append '0' bytes until message length is 56 mod 64 bytes
    while (len(padded) + 8) % 64 != 0:
        padded += b'\x00'

    # Append original length in bits as 64-bit big-endian
    padded += struct.pack('>Q', length_bits)

    return padded


def sha256_chunk_process(chunk: bytes, h: List[int]) -> List[int]:
    """
    Process a single 512-bit (64-byte) chunk of the padded message.

    This performs the SHA-256 message schedule extension and compression.

    Args:
        chunk (bytes): 64-byte block of the padded message.
        h     (List[int]): Current hash state [h0..h7].

    Returns:
        List[int]: Updated hash state after processing this chunk.
    """
    # Unpack into sixteen 32-bit big-endian words
    w: List[int] = list(struct.unpack('>16I', chunk))

    # Extend to 64 words
    for i in range(16, 64):
        s0 = (right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3))
        s1 = (right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10))
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)

    a, b, c, d, e, f, g, hh = h
    # Main compression loop
    for i in range(64):
        S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (hh + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF

        hh, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF

    # Update and return new hash state
    return [
        (h[0] + a) & 0xFFFFFFFF,
        (h[1] + b) & 0xFFFFFFFF,
        (h[2] + c) & 0xFFFFFFFF,
        (h[3] + d) & 0xFFFFFFFF,
        (h[4] + e) & 0xFFFFFFFF,
        (h[5] + f) & 0xFFFFFFFF,
        (h[6] + g) & 0xFFFFFFFF,
        (h[7] + hh) & 0xFFFFFFFF,
    ]


def sha256(message: Union[str, bytes]) -> bytes:
    """
    Compute the SHA-256 digest of the given message.

    Args:
        message (Union[str, bytes]): Input data to hash.

    Returns:
        bytes: 32-byte (256-bit) hash digest.
    """
    padded = sha256_pad_message(message)
    state: List[int] = [H0, H1, H2, H3, H4, H5, H6, H7]

    # Process each 64-byte chunk
    for i in range(0, len(padded), 64):
        state = sha256_chunk_process(padded[i:i+64], state)

    # Produce final digest
    return b''.join(struct.pack('>I', x) for x in state)


class SHA256:
    """
    Stateful SHA-256 hasher supporting incremental updates.
    """
    def __init__(self, data: bytes = b"") -> None:
        """
        Initialize the hasher with optional initial data.

        Args:
            data (bytes): Initial data to hash (default empty).
        """
        self._data: bytes = data

    def update(self, data: Union[str, bytes]) -> None:
        """
        Append more data to the hasher state.

        Args:
            data (Union[str, bytes]): Additional data to include.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._data += data

    def digest(self) -> bytes:
        """
        Compute and return the raw 32-byte hash of all data.

        Returns:
            bytes: 256-bit hash.
        """
        return sha256(self._data)

    def hexdigest(self) -> str:
        """
        Compute and return the hash as a hexadecimal string.

        Returns:
            str: 64-character hex digest.
        """
        return ''.join(f'{b:02x}' for b in self.digest())

    @property
    def digest_size(self) -> int:
        """
        The size of the hash digest in bytes (constant 32 for SHA-256).
        """
        return 32


if __name__ == '__main__':
    while True:
        msg = input('Type your message: ')
        print('SHA-256:', sha256(msg).hex())
        if input('Again? (y/n): ').lower() != 'y':
            break

