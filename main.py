import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

from file_io import RSAFileProcessor

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
        self.pub_key_text = tk.Text(key_info_frame, height=3, width=80, wrap=tk.WORD, state=tk.DISABLED)
        self.pub_key_text.pack(fill="x", padx=5, pady=5)

        # Private key display
        ttk.Label(key_info_frame, text="Private Key (n, d):").pack(anchor=tk.W)
        self.priv_key_text = tk.Text(key_info_frame, height=3, width=80, wrap=tk.WORD, state=tk.DISABLED)
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
                                   command=lambda: self.browse_file(self.pubkey_entry, [("Text files", "*.txt"), ("All files", "*.*")]))
        pubkey_browse.pack(side=tk.RIGHT, padx=5, pady=10)

        # Encrypt button
        encrypt_button = tk.Button(encryption_tab, text="Encrypt File", font=("Arial", 12),
                                   width=15, height=2, bg="#4CAF50", fg="white",
                                   command=self.encrypt_file)
        encrypt_button.pack(pady=20)

        # Info text
        self.encryption_info_var = tk.StringVar()
        ttk.Label(encryption_tab, textvariable=self.encryption_info_var).pack()

    def create_decryption_tab(self):
        decryption_tab = ttk.Frame(self.notebook)
        self.notebook.add(decryption_tab, text="Decryption")

        # Ciphertext file input frame
        ciphertext_frame = ttk.LabelFrame(decryption_tab, text="Ciphertext File")
        ciphertext_frame.pack(fill="x", padx=20, pady=10)

        self.ciphertext_entry = ttk.Entry(ciphertext_frame, width=70)
        self.ciphertext_entry.pack(side=tk.LEFT, padx=5, pady=10, fill="x", expand=True)

        ciphertext_browse = ttk.Button(ciphertext_frame, text="Browse",
                                       command=lambda: self.browse_file(self.ciphertext_entry, [("Binary files", "*.bin"), ("All files", "*.*")]))
        ciphertext_browse.pack(side=tk.RIGHT, padx=5, pady=10)

        # Private key file input frame
        privkey_frame = ttk.LabelFrame(decryption_tab, text="Private Key File")
        privkey_frame.pack(fill="x", padx=20, pady=10)

        self.privkey_entry = ttk.Entry(privkey_frame, width=70)
        self.privkey_entry.pack(side=tk.LEFT, padx=5, pady=10, fill="x", expand=True)

        privkey_browse = ttk.Button(privkey_frame, text="Browse",
                                    command=lambda: self.browse_file(self.privkey_entry, [("Text files", "*.txt"), ("All files", "*.*")]))
        privkey_browse.pack(side=tk.RIGHT, padx=5, pady=10)

        # Decrypt button
        decrypt_button = tk.Button(decryption_tab, text="Decrypt File", font=("Arial", 12),
                                   width=15, height=2, bg="#2196F3", fg="white",
                                   command=self.decrypt_file)
        decrypt_button.pack(pady=20)

        # Info text
        self.decryption_info_var = tk.StringVar()
        ttk.Label(decryption_tab, textvariable=self.decryption_info_var).pack()


    def browse_file(self, entry, filetypes=None):
        if filetypes is None:
            filetypes = [("All files", "*.*")]
        filename = filedialog.askopenfilename(filetypes=filetypes)
        if filename:
            entry.delete(0, tk.END)
            entry.insert(0, filename)


    def generate_keys(self):
        self.update_status("Generating keys...")
        try:
            # Call generate_keys and get the dictionary back
            keys = self.processor.generate_keys()
            pub_key = keys['public_key']
            priv_key = keys['private_key']

            # Display keys directly from the returned dictionary
            self.pub_key_text.config(state=tk.NORMAL)
            self.pub_key_text.delete('1.0', tk.END)
            self.pub_key_text.insert(tk.END, f"n={hex(pub_key[0])}\ne={hex(pub_key[1])}")
            self.pub_key_text.config(state=tk.DISABLED)

            self.priv_key_text.config(state=tk.NORMAL)
            self.priv_key_text.delete('1.0', tk.END)
            self.priv_key_text.insert(tk.END, f"n={hex(priv_key[0])}\nd={hex(priv_key[1])}")
            self.priv_key_text.config(state=tk.DISABLED)

            # Construct paths for the message box
            messagebox.showinfo("Success", "Keys generated and saved to 'public_key.txt' and 'private_key.txt'")
            self.update_status("Keys generated successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {e}")
            self.update_status("Key generation failed.")

    def encrypt_file(self):
        plaintext_path = self.plaintext_entry.get()
        pubkey_path = self.pubkey_entry.get()

        if not plaintext_path or not pubkey_path:
            messagebox.showerror("Error", "Please select both plaintext file and public key file.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".bin",
                                                   filetypes=[("Binary files", "*.bin")],
                                                   title="Save Encrypted File As")
        if not output_path:
            return

        self.encryption_info_var.set(f"Encrypting file...")
        self.update_status(f"Encrypting {plaintext_path}...")
        try:
            # 1. Load the public key using the processor
            public_key_tuple = self.processor.load_public_key(pubkey_path)

            # 2. Call encrypt_file, passing the loaded key tuple
            start_time = time.time()
            self.processor.encrypt_file(input_path=plaintext_path,
                                        output_path=output_path,
                                        public_key=public_key_tuple) # Pass the key tuple
            end_time = time.time()

            self.encryption_info_var.set(f"Encryption completed in {(end_time - start_time) * 1000:.2f} ms")
            messagebox.showinfo("Success", f"File encrypted successfully to {output_path}")
            self.update_status("Encryption complete.")
        except FileNotFoundError as e:
             messagebox.showerror("Error", f"File not found: {e}")
             self.update_status("Encryption failed: File not found.")
        except ValueError as e: # Catches key loading errors too
             messagebox.showerror("Error", f"Encryption failed: {e}")
             self.update_status(f"Encryption failed: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred during encryption: {e}")
            self.update_status("Encryption failed: Unexpected error.")

    def decrypt_file(self):
        ciphertext_path = self.ciphertext_entry.get()
        privkey_path = self.privkey_entry.get()

        if not ciphertext_path or not privkey_path:
            messagebox.showerror("Error", "Please select both ciphertext file and private key file.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".bin",
                                                   filetypes=[("All files", "*.*")],
                                                   title="Save Decrypted File As")
        if not output_path:
            return

        self.decryption_info_var.set("Decrypting file...")
        self.update_status(f"Decrypting {ciphertext_path}...")
        try:
            # 1. Load the private key using the processor
            private_key_tuple = self.processor.load_private_key(privkey_path)

            # 2. Call decrypt_file, passing the loaded key tuple
            start_time = time.time()
            self.processor.decrypt_file(input_path=ciphertext_path,
                                        output_path=output_path,
                                        private_key=private_key_tuple) # Pass the key tuple
            end_time = time.time()

            self.decryption_info_var.set(f"Decryption completed in {(end_time - start_time) * 1000:.2f} ms")
            messagebox.showinfo("Success", f"File decrypted successfully to {output_path}")
            self.update_status("Decryption complete.")
        except FileNotFoundError as e:
             messagebox.showerror("Error", f"File not found: {e}")
             self.update_status("Decryption failed: File not found.")
        except ValueError as e: # Catches key loading errors too
             messagebox.showerror("Error", f"Decryption failed: {e}")
             self.update_status(f"Decryption failed: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred during decryption: {e}. Check if the key is correct and the file is not corrupted.")
            self.update_status("Decryption failed: Unexpected error or invalid data/key.")
            raise e

    def update_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()


def main():
    root = tk.Tk()
    CryptoApp(root)
    root.mainloop()

if __name__ == '__main__':
    main()
