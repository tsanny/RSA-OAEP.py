from helper import oaep_encode, oaep_decode, generate_prime, modinv
import math

class RSA_OAEP:
    def __init__(self):
        self.n = None
        self.e = 65537
        self.d = None
        self.p = None
        self.q = None
        self.key_size = 2048  # 2048-bit keys
        # Calculate max message length that can be encrypted in one block
        self.max_message_length = (self.key_size // 8) - 2 * 32 - 2 # 2 * hLen + 2 bytes for encoding

    def generate_keys(self):
        """Generate RSA key pair."""
        e, key_size = self.e, self.key_size

        while True:
            p = generate_prime(key_size//2)
            q = generate_prime(key_size//2)

            if p == q: continue

            n = p * q
            phi = (p-1) * (q-1)

            # if math.gcd(e, phi) != 1: continue

            d = modinv(e, phi)
            break

        return {
            'public_key': (n, e),
            'private_key': (n, d)
        }

    def encrypt_block(self, public_key, message_block):
        """RSA-OAEP encryption."""
        n, e = public_key
        k = (n.bit_length() + 7) // 8  # key length in bytes

        em = oaep_encode(message_block, k, label=b"")

        # RSA encryption: c = em^e mod n
        m_int = int.from_bytes(em, byteorder='big')
        c_int = pow(m_int, e, n)
        return c_int.to_bytes(k, byteorder='big')

    def decrypt_block(self, private_key, ciphertext_block):
        """RSA-OAEP decryption."""
        n, d = private_key
        k = (n.bit_length() + 7) // 8

        c_int = int.from_bytes(ciphertext_block, byteorder="big")
        m_int = pow(c_int, d, n)

        em = m_int.to_bytes(k, byteorder="big")
        message = oaep_decode(em, k, label=b"")

        return message

    def encrypt(self, public_key, message):
        """Encryption with block handling"""
        # Use message directly if it's already bytes
        if isinstance(message, str):
            message_bytes = message.encode()
        else:
            message_bytes = message

        # split message into blocks
        blocks = []
        for i in range(0, len(message_bytes), self.max_message_length):
            # if the last block is smaller than max_message_length, pad it
            block = message_bytes[i:i + self.max_message_length]
            encrypted_block = self.encrypt_block(public_key, block)

            # Ensure ciphertext is exactly 256 bytes (2048 bits)
            if len(encrypted_block) != 256:
                raise ValueError(f"Block cipher length is {len(encrypted_block)} bytes, expected 256 bytes")

            blocks.append(encrypted_block)

        # concatenate the encrypted blocks
        # prepend the number of blocks to the ciphertext
        ciphertext = len(blocks).to_bytes(4, byteorder='big') + b''.join(blocks)

        return ciphertext

    def decrypt(self, private_key, ciphertext):
        """Decryption with block handling"""
        # First 4 bytes contain the number of blocks
        num_blocks = int.from_bytes(ciphertext[:4], byteorder='big')
        block_size = (private_key[0].bit_length() + 7) // 8 # key length in bytes

        # Split the ciphertext into blocks and decrypt each
        message = b''
        ciphertext = ciphertext[4:]

        for i in range(num_blocks):
            block = ciphertext[i * block_size:(i + 1) * block_size]
            decrypted_block = self.decrypt_block(private_key, block)
            message += decrypted_block

        return message
