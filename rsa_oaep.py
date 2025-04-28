from typing import Dict, Tuple, Optional, List, Union

from helper import oaep_encode, oaep_decode, generate_prime, modinv


class RSA_OAEP:
    def __init__(self) -> None:
        """
        Initialize RSA-OAEP context with default parameters.

        Attributes:
            n: RSA modulus (product of primes p and q) once generated.
            e: Public exponent, typically 65537.
            d: Private exponent (modular inverse of e modulo phi(n)).
            p: First prime factor of n.
            q: Second prime factor of n.
            key_size: Key size in bits (default 2048).
            max_message_length: Maximum bytes per message block for OAEP.
        """
        self.n: Optional[int] = None
        self.e: int = 65537
        self.d: Optional[int] = None
        self.p: Optional[int] = None
        self.q: Optional[int] = None
        self.key_size: int = 2048  # Key length in bits
        # OAEP padding overhead: 2*hLen + 2 bytes (hLen=32 for SHA-256)
        self.max_message_length: int = (self.key_size // 8) - 2 * 32 - 2

    def generate_keys(self) -> Dict[str, Tuple[int, int]]:
        """
        Generate a new RSA key pair suitable for OAEP encryption.

        Process:
            1. Randomly generate two distinct primes p and q of half the key_size.
            2. Compute n = p * q and phi(n) = (p - 1) * (q - 1).
            3. Compute private exponent d = modular inverse of e modulo phi(n).

        Returns:
            Dict[str, Tuple[int, int]]: A dictionary containing:
                - "public_key": Tuple[int, int] = (n, e)
                - "private_key": Tuple[int, int] = (n, d)
        """
        e, key_size = self.e, self.key_size

        while True:
            p = generate_prime(key_size // 2)
            q = generate_prime(key_size // 2)

            if p == q:
                continue

            self.p, self.q = p, q
            n = p * q
            phi = (p-1) * (q-1)
            try:
                d = modinv(e, phi)
            except ValueError:
                continue
            self.n, self.d = n, d
            break

        return {"public_key": (n, e), "private_key": (n, d)}

    def encrypt_block(self, public_key: Tuple[int, int], message_block: bytes) -> bytes:
        """
        Encrypt a single block of data using RSA-OAEP.

        Args:
            public_key (Tuple[int, int]): The RSA public key as (n, e).
            message_block (bytes): A chunk of plaintext not exceeding max_message_length.

        Returns:
            bytes: The ciphertext block of length key_size//8 bytes.
        """
        n, e = public_key
        k: int = (n.bit_length() + 7) // 8  # key length in bytes

        # OAEP encode the plaintext block
        em: bytes = oaep_encode(message_block, k, label=b"")
        m_int: int = int.from_bytes(em, byteorder="big")

        # RSA encryption: c = m^e mod n
        c_int: int = pow(m_int, e, n)
        return c_int.to_bytes(k, byteorder="big")

    def decrypt_block(
        self, private_key: Tuple[int, int], ciphertext_block: bytes
    ) -> bytes:
        """
        Decrypt a single RSA-OAEP encrypted block.

        Args:
            private_key (Tuple[int, int]): The RSA private key as (n, d).
            ciphertext_block (bytes): A ciphertext chunk of key_size//8 bytes.

        Returns:
            bytes: The original plaintext block after OAEP decoding.
        """
        n, d = private_key
        k: int = (n.bit_length() + 7) // 8

        c_int: int = int.from_bytes(ciphertext_block, byteorder="big")
        m_int: int = pow(c_int, d, n)

        em: bytes = m_int.to_bytes(k, byteorder="big")
        message: bytes = oaep_decode(em, k, label=b"")
        return message

    def encrypt(self, public_key: Tuple[int, int], message: Union[str, bytes]) -> bytes:
        """
        Encrypt an arbitrary-length message with RSA-OAEP using block processing.

        Args:
            public_key (Tuple[int, int]): RSA public key (n, e).
            message (Union[str, bytes]): Data to encrypt. Strings are UTF-8 encoded.

        Returns:
            bytes: Ciphertext consisting of a 4-byte block count header + all encrypted blocks.
        """
        # Convert string input to bytes
        message_bytes: bytes = message.encode() if isinstance(message, str) else message

        # Break message into OAEP-compatible blocks
        blocks: List[bytes] = []
        for i in range(0, len(message_bytes), self.max_message_length):
            chunk = message_bytes[i : i + self.max_message_length]
            encrypted_block = self.encrypt_block(public_key, chunk)

            # Verify block size
            if len(encrypted_block) != self.key_size // 8:
                raise ValueError(
                    f"Encrypted block length {len(encrypted_block)} != expected {self.key_size // 8}"
                )

            blocks.append(encrypted_block)

        # Prefix ciphertext with 4-byte number of blocks
        header: bytes = len(blocks).to_bytes(4, byteorder="big")
        return header + b"".join(blocks)

    def decrypt(self, private_key: Tuple[int, int], ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext produced by `encrypt` on multiple blocks.

        Args:
            private_key (Tuple[int, int]): RSA private key (n, d).
            ciphertext (bytes): Data starting with 4-byte block count header.

        Returns:
            bytes: The reconstructed plaintext message.
        """
        # Extract number of blocks from header
        num_blocks: int = int.from_bytes(ciphertext[:4], byteorder="big")
        block_size: int = (private_key[0].bit_length() + 7) // 8

        message: bytes = b""
        offset: int = 4
        for _ in range(num_blocks):
            block = ciphertext[offset : offset + block_size]
            message += self.decrypt_block(private_key, block)
            offset += block_size

        return message
