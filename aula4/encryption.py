import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def read_message_from_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def encrypt(algorithm, message): 
    if algorithm == "AES":
        key = os.urandom(32) 
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_message = padder.update(message) + padder.finalize()
    elif algorithm == "ChaCha20":
        key = os.urandom(32)  
        nonce = os.urandom(16)  
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        padded_message = message
    else:
        raise ValueError("Unsupported algorithm")

    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_message) + encryptor.finalize()
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(ct) + decryptor.finalize()
    
    if algorithm == "AES":
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    else:
        decrypted_message = decrypted_padded_message

    return key, iv if algorithm == "AES" else nonce, ct, decrypted_message

def save_encryption_results(output_file, key, iv_or_nonce, ct, decrypted_message):
    with open(output_file, 'wb') as file:
        file.write(b"Key: " + key + b"\n")
        file.write(b"IV / Nonce: " + iv_or_nonce + b"\n")
        file.write(b"Ciphertext: " + ct + b"\n")
        file.write(b"Decrypted Message: " + decrypted_message + b"\n")

def main(file_path, algorithm):
    message = read_message_from_file(file_path)
    key, iv_or_nonce, ct, decrypted_message = encrypt(algorithm, message)
    
    print(f"{algorithm}:")
    print("Key:", key)
    print("IV / Nonce:", iv_or_nonce)
    print("Ciphertext:", ct)
    print("Decrypted Message:", decrypted_message)
    
    output_file = "encryption_result.txt"
    save_encryption_results(output_file, key, iv_or_nonce, ct, decrypted_message)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Uso: python encryption.py <caminho_do_ficheiro> <algoritmo>")
        print("Algoritmo deve ser 'AES' ou 'ChaCha20'.")
    else:
        file_path = sys.argv[1]
        algorithm = sys.argv[2]
        main(file_path, algorithm)
