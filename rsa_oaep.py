from helper import oaep_encode, oaep_decode

class RSA_OAEP:
    def __init__(self):
        self.n = None
        self.e = None
        self.d = None
        self.p = None
        self.q = None
        self.key_size = 2048  # 2048-bit keys

    def generate_keys(self):
        """Generate RSA key pair."""
        pass

    def encrypt(self, public_key, message):
        """RSA-OAEP encryption."""
        n, e = public_key
        k = (n.bit_length() + 7) // 8  # key length in bytes

        # Encode message using OAEP
        message_bytes = message.encode()
        em = oaep_encode(message_bytes, k, label=b"", hash_cls=self.hash_cls)

        # RSA encryption: c = em^e mod n
        m_int = int.from_bytes(em, byteorder='big')
        c_int = pow(m_int, e, n)
        ciphertext = c_int.to_bytes(k, byteorder='big')

        return ciphertext

    def decrypt(self, private_key, ciphertext):
        n, d = private_key
        k = (n.bit_length() + 7) // 8

        """RSA-OAEP decryption."""
        c_int = int.from_bytes(ciphertext, byteorder="big")
        m_int = pow(c_int, d, n)

        em = m_int.to_bytes(k, byteorder="big")
        message = oaep_decode(em, k, label=b"")

        return message
