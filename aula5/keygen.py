import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_key_pair(pub_filename, priv_filename, key_size, password=None):
    # chave privada RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # serializar chave privada
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    )

    # chave privada guardar
    with open(priv_filename, 'wb') as priv_file:
        priv_file.write(pem_priv)

    # chave pública
    public_key = private_key.public_key()

    # serializar chave pública
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # chave pública guardar
    with open(pub_filename, 'wb') as pub_file:
        pub_file.write(pem_pub)

    return private_key, public_key

if __name__ == "__main__":
    
    pub_filename = sys.argv[1]
    priv_filename = sys.argv[2]
    key_size = int(sys.argv[3])

    generate_rsa_key_pair(pub_filename, priv_filename, key_size)
    print(f"Chaves RSA de {key_size} bits geradas e guardadas nos ficheiros: {pub_filename}, {priv_filename}")
