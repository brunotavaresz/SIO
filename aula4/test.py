import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(algorithm):  
    if algorithm == "AES":
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) 
    elif algorithm == "ChaCha20":
        key = os.urandom(32)
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    else:
        raise ValueError("Unsupported algorithm")

    encryptor = cipher.encryptor()
    ct = encryptor.update(b"a secret message") + encryptor.finalize()

    if algorithm == "AES":
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        decrypted_message = decryptor.update(ct) + decryptor.finalize()
        return key, iv, ct, decrypted_message
    elif algorithm == "ChaCha20":
        decryptor = Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor()
        decrypted_message = decryptor.update(ct) + decryptor.finalize()
        return key, nonce, ct, decrypted_message

def main():
    algorithm = "ChaCha20"  # ou "AES"
    key, iv_or_nonce, ct, decrypted_message = encrypt(algorithm)
    
    print("Key:", key.hex())
    
    if len(iv_or_nonce) == 16:
        print("IV:", iv_or_nonce.hex())
    elif len(iv_or_nonce) == 12:
        print("Nonce:", iv_or_nonce.hex())
    
    print("Ciphertext:", ct.hex())
    print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
