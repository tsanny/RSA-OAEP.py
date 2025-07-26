# RSA-OAEP Encryption and Decryption

This program encrypts and decrypts messages using the RSA algorithm with OAEP padding.

**How to use:**
1. Ensure the SimPy library is installed (if not, run "pip install simpy").
2. Run `main.py`.
3. In the Key Generation tab, click "Generate Keys" to create a public and private key pair.
4. In the Encryption tab, select the plaintext file to be encrypted and the public key file you generated. The encrypted output will be in the same directory.
5. In the Decryption tab, select the ciphertext file to be decrypted, the private key file you generated, and enter a filename for the decrypted output. The decrypted output will be in the same directory.

**Program Structure:**
- `main.py`: Code to run the program and display the graphical user interface (GUI).
- `file_io.py`: Code for processing plaintext, ciphertext, public key, and private key files.
- `rsa_oaep.py`: Code for key generation, plaintext encryption, and ciphertext decryption using RSA-OAEP implementation.
