import os
from typing import Dict, Tuple, Optional, List, Literal
from rsa_oaep import RSA_OAEP


class RSAFileProcessor:
    def __init__(self):
        self.rsa = RSA_OAEP()
        self.keys: Optional[Dict[str, Tuple[int, int]]] = None

    def generate_keys(self, save_to_file: bool = True) -> Dict[str, Tuple[int, int]]:
        """Generate RSA keys and optionally save to files"""
        self.keys = self.rsa.generate_keys()

        if save_to_file:
            n = self.keys["public_key"][0]
            e = self.keys["public_key"][1]
            d = self.keys["private_key"][1]

            with open("public_key.txt", "w") as f:
                f.write(f"{hex(n)[2:]},{hex(e)[2:]}")

            with open("private_key.txt", "w") as f:
                f.write(f"{hex(n)[2:]},{hex(d)[2:]}")

        return self.keys

    def encrypt_file(self, input_path: str, output_path: str = "encrypted.txt") -> str:
        """Encrypt file content using RSA-OAEP"""
        if not self.keys:
            raise ValueError("Keys not loaded or generated")

        # Read input file
        try:
            with open(input_path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {input_path}")

        # Encrypt the data
        ciphertext = self.rsa.encrypt(self.keys["public_key"], data)

        # Write encrypted data (hex encoded for text file)
        with open(output_path, "w") as f:
            f.write(ciphertext.hex())

        return output_path

    def decrypt_file(self, input_path: str, output_path: str = "decrypted.txt") -> str:
        """Decrypt file content using RSA-OAEP"""
        if not self.keys:
            raise ValueError("Keys not loaded or generated")

        # Read encrypted file (hex encoded)
        try:
            with open(input_path, "r") as f:
                hex_data = f.read().strip()
                ciphertext = bytes.fromhex(hex_data)
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {input_path}")
        except ValueError:
            raise ValueError("Invalid encrypted file format - expected hex string")

        # Decrypt the data
        plaintext = self.rsa.decrypt(self.keys["private_key"], ciphertext)

        # Write decrypted data as hexadecimal
        with open(output_path, "w") as f:
            f.write(plaintext.hex())

        return output_path

    def process_directory(
        self,
        directory: str,
        operation: Literal["encrypt", "decrypt"] = "encrypt",
        output_dir: str = "processed",
    ) -> List[str]:
        """Process all files in a directory with the specified operation"""
        if not os.path.exists(directory):
            raise FileNotFoundError(f"Directory not found: {directory}")

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        processed_files = []

        for filename in os.listdir(directory):
            input_path = os.path.join(directory, filename)

            if os.path.isfile(input_path):
                output_filename = f"{operation}d_{filename}"
                output_path = os.path.join(output_dir, output_filename)

                try:
                    if operation == "encrypt":
                        result = self.encrypt_file(input_path, output_path)
                    elif operation == "decrypt":
                        result = self.decrypt_file(input_path, output_path)
                    else:
                        raise ValueError(
                            "Invalid operation - use 'encrypt' or 'decrypt'"
                        )

                    processed_files.append(result)
                except Exception as e:
                    print(f"Error processing {filename}: {str(e)}")
                    continue

        return processed_files


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
