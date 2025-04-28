from typing import Dict, Tuple
from rsa_oaep import RSA_OAEP
from helper import parse_hex_key_file


class RSAFileProcessor:
    def __init__(self):
        self.rsa = RSA_OAEP()

    def generate_keys(self) -> Dict[str, Tuple[int, int]]:
        """
        Generate RSA keys save to files.
        Returns the generated keys dictionary.
        """
        generated_keys = self.rsa.generate_keys()

        n = generated_keys["public_key"][0]
        e = generated_keys["public_key"][1]
        d = generated_keys["private_key"][1]

        with open("public_key.txt", "w") as f:
            f.write(f"{hex(n)[2:]},{hex(e)[2:]}")

        with open("private_key.txt", "w") as f:
            f.write(f"{hex(n)[2:]},{hex(d)[2:]}")

        return generated_keys

    def load_public_key(self, key_path: str) -> Tuple[int, int]:
        """Loads a public key from a file and returns it"""
        try:
            n, e = parse_hex_key_file(key_path)
            return (n, e)
        except Exception as e:
            raise ValueError(f"Failed to load public key from {key_path}: {e}")

    def load_private_key(self, key_path: str) -> Tuple[int, int]:
        """Loads a private key from a file and returns it"""
        try:
            n, d = parse_hex_key_file(key_path)
            return (n, d)
        except Exception as e:
            raise ValueError(f"Failed to load private key from {key_path}: {e}")

    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        public_key: Tuple[int, int],
    ) -> str:
        """Encrypt file content using RSA-OAEP"""
        # Read input file
        try:
            with open(input_path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {input_path}")

        # Encrypt the data
        ciphertext = self.rsa.encrypt(public_key, data)

        # Write encrypted data as binary
        with open(output_path, "wb") as f:
            f.write(ciphertext)

        return output_path

    def decrypt_file(
        self, input_path: str, output_path: str, private_key: Tuple[int, int]
    ) -> str:
        """Decrypt file content using RSA-OAEP"""
        # Read encrypted file as binary
        try:
            with open(input_path, "rb") as f:
                ciphertext = f.read().strip()
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {input_path}")
        except ValueError:
            raise ValueError("Invalid encrypted file format - expected hex string")

        # Decrypt the data
        plaintext = self.rsa.decrypt(private_key, ciphertext)

        # Write decrypted data as binary
        with open(output_path, "wb") as f:
            f.write(plaintext)

        return output_path


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="RSA-OAEP File Encryption/Decryption Tool"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Key generation command
    key_parser = subparsers.add_parser("generate-keys", help="Generate RSA key pair")
    key_parser.add_argument("--save", action="store_true", help="Save keys to files")

    # Encryption command
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("input", help="Input file path")
    enc_parser.add_argument(
        "--output", default="encrypted.txt", help="Output file path"
    )

    # Decryption command
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("input", help="Input file path")
    dec_parser.add_argument(
        "--output", default="decrypted.txt", help="Output file path"
    )

    args = parser.parse_args()

    processor = RSAFileProcessor()

    try:
        if args.command == "generate-keys":
            keys = processor.generate_keys(save_to_file=args.save)
            print("Keys generated successfully!")
            print(f"Public key (n, e): {keys['public_key']}")
            print(f"Private key (n, d): {keys['private_key']}")

        elif args.command in ["encrypt", "decrypt"]:
            if args.command == "encrypt":
                output = processor.encrypt_file(args.input, args.output)
                print(f"File encrypted successfully: {output}")
            else:
                output = processor.decrypt_file(args.input, args.output)
                print(f"File decrypted successfully: {output}")

    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)


if __name__ == "__main__":
    main()
