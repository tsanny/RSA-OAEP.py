import struct

# official docs
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

# SHA-256 Constants (First 32 bits of fractional parts of cube roots of first 64 primes)
# These constants are used in the SHA-256 algorithm to perform the compression function.
# Cube roots of the first 64 primes are used to ensure that they are indeed random numbers
# and not backdoors to the algo
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Initial Hash Values (First 32 bits of fractional parts of square roots of first 8 primes)
H0 = 0x6a09e667
H1 = 0xbb67ae85
H2 = 0x3c6ef372
H3 = 0xa54ff53a
H4 = 0x510e527f
H5 = 0x9b05688c
H6 = 0x1f83d9ab
H7 = 0x5be0cd19

# Helper Functions
def right_rotate(n, b):
    return ((n >> b) | (n << (32 - b))) & 0xFFFFFFFF

def sha256_pad_message(message):
    # Convert message to bytes if not already
    if isinstance(message, str):
        message = message.encode('utf-8')

    length_bits = len(message) * 8  # Length in bits

    # The 1 bit is appended to mark the end of the original message.
    # This ensures that different messages (especially those differing
    # only by trailing zeros) will produce different hash values, preventing
    # certain types of collision attacks.
    message += b'\x80'  # Append '1' bit

    # We pad with zeros until 448 bits because we need to append the original
    # message length as a 64-bit big-endian integer, which will bring the total
    # length to 512 bits (64 bytes).
    while (len(message) + 8) % 64 != 0:
        message += b'\x00'

    # Append original length as 64-bit big-endian
    #
    # We use the struct module to pack the length as a 64-bit big-endian integer.
    # The '>' indicates big-endian, 'Q' indicates unsigned long long (64 bits).
    # We then append the packed length to the message.
    message += struct.pack('>Q', length_bits)

    return message

def sha256_chunk_process(chunk, h):

    # Break chunk into 16 32-bit words (big-endian)
    # Here, we use the struct module to unpack the chunk into 16 32-bit words.
    # The '>' indicates big-endian, '16I' indicates 16 unsigned integers (32 bits).
    w = list(struct.unpack('>16I', chunk))

    # Extend the 16 32-bit words to 64 words using the following operations:

    #   w[i] = w[i-16] + s0 + w[i-7] + s1

    # where:
    #   s0 = (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
    #   s1 = (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
    # and the initial 16 words are the 16 words of the chunk.


    for i in range(16, 64):
        s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)

        # This '&' operation is used to ensure that the words are 32 bits.
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)

    # Initialize working variables
    a, b, c, d, e, f, g, hh = h

    # Compression loop
    for i in range(64):
        S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (hh + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF

        hh = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    # Update hash values
    h[0] = (h[0] + a) & 0xFFFFFFFF
    h[1] = (h[1] + b) & 0xFFFFFFFF
    h[2] = (h[2] + c) & 0xFFFFFFFF
    h[3] = (h[3] + d) & 0xFFFFFFFF
    h[4] = (h[4] + e) & 0xFFFFFFFF
    h[5] = (h[5] + f) & 0xFFFFFFFF
    h[6] = (h[6] + g) & 0xFFFFFFFF
    h[7] = (h[7] + hh) & 0xFFFFFFFF

    return h

def sha256(message):
    # Pre-processing (Padding)
    padded_msg = sha256_pad_message(message)

    # Initialize hash values
    h = [H0, H1, H2, H3, H4, H5, H6, H7]

    # Process each 512-bit chunk
    for i in range(0, len(padded_msg), 64):
        chunk = padded_msg[i:i+64]
        h = sha256_chunk_process(chunk, h)

    # Produce final hash
    digest = b''.join(struct.pack('>I', x) for x in h)

    assert len(digest) == 32, "Digest length is not 256 bits"

    return digest

    # return binascii.hexlify(digest).decode('utf-8')
    # return ''.join(f'{byte:02x}' for byte in digest)

class SHA256:
    def __init__(self, data=b""):
        self._data = data

    def update(self, data):
        self._data += data

    def digest(self):
        return sha256(self._data)

    def hexdigest(self):
        return ''.join(f'{b:02x}' for b in self.digest())

    @property
    def digest_size(self):
        return 32

if __name__ == '__main__':
    verdict = 'y'
    while verdict == 'y':
        input_message = input('Type or copy your message here: ')
        print('Your message: ', input_message)
        print('Hash: ', sha256(input_message))
        verdict = input('Do you want to try another text? (y/n): ').lower()
