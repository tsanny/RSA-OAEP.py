# RSA-OAEP Encryption and Decryption

Program ini digunakan untuk melakukan enkripsi dan dekripsi pesan menggunakan algoritma RSA dengan padding OAEP.

**Cara pakai:**
1. Pastikan library SimPy sudah ter-install (jika belum, jalankan perintah "pip install simpy").
2. Jalankan main.py.
3. Pada tab Key Generation, klik Generate Keys untuk menghasilkan pasangan kunci (public dan private key)
4. Pada tab Encryption, pilih file plaintext yang akan dienkripsi dan file public key yang telah terbuat. Hasil enkripsi dapat dilihat pada direktori yang sama.
5. Pada tab Decryption, pilih file ciphertext yang akan didekripsi, file private key yang telah terbuat, dan tuliskan nama file untuk output hasil dekripsi. Hasil dekripsi dapat dilihat pada direktori yang sama.

Struktur program:
- `main.py`: Kode untuk menjalankan program beserta menampilkan *graphical user interface* (GUI)
- `file_io.py`: Kode untuk memproses *file* *plaintext, ciphertext, public key, dan private key*
- `rsa_oaep.py`: Kode untuk membuat key, mengenkripsi *plaintext*, dan mendekripsi *ciphertext* dengan implementasi RSA-OAEP
- `sha256.py`: Kode implementasi *hashing function* untuk proses masking pada enkripsi dan dekripsi RSA-OAEP
- `helper.py`: Kode berisi fungsi-fungsi untuk mendukung implementasi RSA-OAEP