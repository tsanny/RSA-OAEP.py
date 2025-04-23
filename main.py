import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from file_io import RSAFileProcessor
from helper import parse_hex_public_key
from rsa_oaep import RSA_OAEP

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title('RSA-OAEP Crypto Application')
        self.root.geometry('900x700')

        self.processor = RSAFileProcessor()
        self.create_widgets()

    def create_widgets(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Key Generation Tab
        self.create_keygen_tab()

        # Encryption Tab
        self.create_encryption_tab()

        # Decryption Tab
        self.create_decryption_tab()

        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var,
                                    relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")

    def create_keygen_tab(self):
        keygen_tab = ttk.Frame(self.notebook)
        self.notebook.add(keygen_tab, text="Key Generation")

        # Key info frame
        key_info_frame = ttk.LabelFrame(keygen_tab, text="Key Information")
        key_info_frame.pack(fill="x", padx=20, pady=10)

        # Public key display
        ttk.Label(key_info_frame, text="Public Key (n, e):").pack(anchor=tk.W)
        self.pub_key_text = tk.Text(key_info_frame, height=3, width=80, wrap=tk.WORD)
        self.pub_key_text.pack(fill="x", padx=5, pady=5)

        # Private key display
        ttk.Label(key_info_frame, text="Private Key (n, d):").pack(anchor=tk.W)
        self.priv_key_text = tk.Text(key_info_frame, height=3, width=80, wrap=tk.WORD)
        self.priv_key_text.pack(fill="x", padx=5, pady=5)

        # Generate keys button
        gen_button = tk.Button(keygen_tab, text="Generate Keys", font=("Arial", 12),
                               width=15, height=2, bg="#FF9800", fg="white",
                               command=self.generate_keys)
        gen_button.pack(pady=20)

    def create_encryption_tab(self):
        encryption_tab = ttk.Frame(self.notebook)
        self.notebook.add(encryption_tab, text="Encryption")

        # Plaintext file input frame
        plaintext_frame = ttk.LabelFrame(encryption_tab, text="Plaintext File")
        plaintext_frame.pack(fill="x", padx=20, pady=10)

        self.plaintext_entry = ttk.Entry(plaintext_frame, width=70)
        self.plaintext_entry.pack(side=tk.LEFT, padx=5, pady=10, fill="x", expand=True)

        plaintext_browse = ttk.Button(plaintext_frame, text="Browse",
                                      command=lambda: self.browse_file(self.plaintext_entry))
        plaintext_browse.pack(side=tk.RIGHT, padx=5, pady=10)

        # Public key file input frame
        pubkey_frame = ttk.LabelFrame(encryption_tab, text="Public Key File")
        pubkey_frame.pack(fill="x", padx=20, pady=10)

        self.pubkey_entry = ttk.Entry(pubkey_frame, width=70)
        self.pubkey_entry.pack(side=tk.LEFT, padx=5, pady=10, fill="x", expand=True)

        pubkey_browse = ttk.Button(pubkey_frame, text="Browse",
                                   command=lambda: self.browse_file(self.pubkey_entry,
                                                                    [("Key files", "*.txt"),
                                                                     ("All files", "*.*")]))
        pubkey_browse.pack(side=tk.RIGHT, padx=5, pady=10)

        # Encrypt button
        encrypt_button = tk.Button(encryption_tab, text="Encrypt", font=("Arial", 12),
                                   width=15, height=2, bg="#4CAF50", fg="white",
                                   command=self.encrypt_file)
        encrypt_button.pack(pady=20)

        # Time label
        self.enc_time_var = tk.StringVar()
        ttk.Label(encryption_tab, textvariable=self.enc_time_var).pack()

        # Ciphertext info
        self.cipher_info_var = tk.StringVar()
        ttk.Label(encryption_tab, textvariable=self.cipher_info_var).pack()

    def create_decryption_tab(self):
        decryption_tab = ttk.Frame(self.notebook)
        self.notebook.add(decryption_tab, text="Decryption")

        # Ciphertext file input frame
        cipher_frame = ttk.LabelFrame(decryption_tab, text="Ciphertext File")
        cipher_frame.pack(fill="x", padx=20, pady=10)

        self.cipher_entry = ttk.Entry(cipher_frame, width=70)
        self.cipher_entry.pack(side=tk.LEFT, padx=5, pady=10, fill="x", expand=True)

        cipher_browse = ttk.Button(cipher_frame, text="Browse",
                                   command=lambda: self.browse_file(self.cipher_entry,
                                                                    [("Encrypted files", "*.enc"),
                                                                     ("All files", "*.*")]))
        cipher_browse.pack(side=tk.RIGHT, padx=5, pady=10)

        # Private key file input frame
        privkey_frame = ttk.LabelFrame(decryption_tab, text="Private Key File")
        privkey_frame.pack(fill="x", padx=20, pady=10)

        self.privkey_entry = ttk.Entry(privkey_frame, width=70)
        self.privkey_entry.pack(side=tk.LEFT, padx=5, pady=10, fill="x", expand=True)

        privkey_browse = ttk.Button(privkey_frame, text="Browse",
                                    command=lambda: self.browse_file(
                                        self.privkey_entry,
                                        [("Key files", "*.txt"), ("All files", "*.*")]
                                    ))
        privkey_browse.pack(side=tk.RIGHT, padx=5, pady=10)

        # Output file frame
        output_frame = ttk.LabelFrame(decryption_tab, text="Output Plaintext File Name")
        output_frame.pack(fill="x", padx=20, pady=10)

        self.dec_output_entry = ttk.Entry(output_frame, width=70)
        self.dec_output_entry.pack(side=tk.LEFT, padx=5, pady=10, fill="x", expand=True)

        # Decrypt button
        decrypt_button = tk.Button(decryption_tab, text="Decrypt", font=("Arial", 12),
                                   width=15, height=2, bg="#2196F3", fg="white",
                                   command=self.decrypt_file)
        decrypt_button.pack(pady=20)

        # Time label
        self.dec_time_var = tk.StringVar()
        ttk.Label(decryption_tab, textvariable=self.dec_time_var).pack()

    def browse_file(self, entry, filetypes=None):
        if filetypes is None:
            filetypes = (("All files", "*.*"),)

        filename = filedialog.askopenfilename(title="Select a file", filetypes=filetypes)
        if filename:
            entry.delete(0, tk.END)
            entry.insert(0, filename)

    def generate_keys(self):
        try:
            start_time = time.time()
            keys = self.processor.generate_keys(save_to_file=True)
            end_time = time.time()

            # Display keys
            self.pub_key_text.delete(1.0, tk.END)
            self.pub_key_text.insert(tk.END, f"n: {keys['public_key'][0]}\ne: {keys['public_key'][1]}")

            self.priv_key_text.delete(1.0, tk.END)
            self.priv_key_text.insert(tk.END, f"n: {keys['private_key'][0]}\nd: {keys['private_key'][1]}")

            self.update_status(f"Keys generated in {(end_time - start_time) * 1000:.2f} ms")
            messagebox.showinfo("Success",
                                "New RSA keys generated successfully!\nSaved to public_key.txt and private_key.txt")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")
            self.update_status("Key generation failed")

            raise e

    def encrypt_file(self):
        plaintext_file = self.plaintext_entry.get()
        pubkey_file = self.pubkey_entry.get()
        output_file = 'encrypted.enc'

        if not plaintext_file:
            messagebox.showerror("Error", "Please select a plaintext file")
            return
        if not pubkey_file:
            messagebox.showerror("Error", "Please select a public key file")
            return

        try:
            n, e = parse_hex_public_key(pubkey_file)

            # Load public key from file
            # with open(pubkey_file, 'r') as f:
            #     n, e = map(int, f.read().strip().split(','))
            print(n, e)
            public_key = (n, e)

            # Read plaintext file
            with open(plaintext_file, 'rb') as f:
                plaintext = f.read()

            start_time = time.time()

            # Encrypt using RSA-OAEP
            rsa = RSA_OAEP()
            ciphertext = rsa.encrypt(public_key, plaintext)
            print(ciphertext)

            # Ensure ciphertext is exactly 256 bytes (2048 bits)
            # if len(ciphertext) != 256:
            #     raise ValueError(f"Ciphertext length is {len(ciphertext)} bytes, expected 256 bytes")

            # Write ciphertext to file
            with open(output_file, 'wb') as f:
                f.write(ciphertext)

            end_time = time.time()

            self.enc_time_var.set(f"Encryption completed in {(end_time - start_time) * 1000:.2f} ms")
            self.cipher_info_var.set(f"Ciphertext size: {len(ciphertext)} bytes (256 bytes expected)")
            self.update_status(f"File encrypted successfully: {output_file}")
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved to: {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.update_status("Encryption failed")
            self.enc_time_var.set("")
            self.cipher_info_var.set("")

            raise e

    def decrypt_file(self):
        cipher_file = self.cipher_entry.get()
        privkey_file = self.privkey_entry.get()
        output_file = self.dec_output_entry.get() or 'decrypted.bin'

        if not cipher_file:
            messagebox.showerror("Error", "Please select a ciphertext file")
            return
        if not privkey_file:
            messagebox.showerror("Error", "Please select a private key file")
            return

        try:
            # Load private key from file
            with open(privkey_file, 'r') as f:
                n, d = map(int, f.read().strip().split(','))
            private_key = (n, d)

            # Read ciphertext file
            with open(cipher_file, 'rb') as f:
                ciphertext = f.read()

            start_time = time.time()

            # Decrypt using RSA-OAEP
            rsa = RSA_OAEP()
            plaintext = rsa.decrypt(private_key, ciphertext)

            # Write plaintext to file
            with open(output_file, 'wb') as f:
                f.write(plaintext)

            end_time = time.time()

            self.dec_time_var.set(f"Decryption completed in {(end_time - start_time) * 1000:.2f} ms")
            self.update_status(f"File decrypted successfully: {output_file}")
            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved to: {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.update_status("Decryption failed")
            self.dec_time_var.set("")

            raise e

    def update_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()


def main():
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
