import os, struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(algorithm): 
    if algorithm == "AES":
        key = os.urandom(32) 
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) 
    elif algorithm == "ChaCha20":
        key = os.urandom(32)  
        nonce = os.urandom(16)  
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    else:
        raise ValueError("Unsupported algorithm")

    encryptor = cipher.encryptor()
    ct = encryptor.update(b"a secret message") + encryptor.finalize()

    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ct) + decryptor.finalize()

    return key, nonce if algorithm == "ChaCha20" else iv, ct, decrypted_message

def main():

    # Encrypt using AES
    key, iv, ct, decrypted_message = encrypt("AES")
    print("AES:")
    print("Key:", key)
    print("IV:", iv)
    print("Ciphertext:", ct)
    print("Decrypted Message:", decrypted_message)

    # Encrypt using ChaCha20
    key, nonce, ct, decrypted_message = encrypt("ChaCha20")
    print("ChaCha20:")
    print("Key:", key)
    print("Nonce:", nonce)
    print("Ciphertext:", ct)
    print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
