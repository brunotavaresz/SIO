from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_key_pair(pub_filename, priv_filename, key_size, password=None):
    # Gerar chave privada RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # Serializar a chave privada
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    )

    # Guardar chave privada no ficheiro
    with open(priv_filename, 'wb') as priv_file:
        priv_file.write(pem_priv)

    # Obter e serializar a chave pública
    public_key = private_key.public_key()
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Guardar chave pública no ficheiro
    with open(pub_filename, 'wb') as pub_file:
        pub_file.write(pem_pub)

def load_private_key(filename, password=None):
    # Carregar a chave privada a partir do ficheiro
    with open(filename, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
        )
    return private_key

if __name__ == "__main__":
    pub_filename = './public_key.pem'
    priv_filename = './private_key.pem'
    key_size = 2048
    password = b'mypassword'  # Pode definir uma senha aqui

    # Gerar e guardar chaves RSA
    generate_rsa_key_pair(pub_filename, priv_filename, key_size, password)

    # Carregar a chave privada do ficheiro
    loaded_private_key = load_private_key(priv_filename, password)
    print("Chave privada carregada com sucesso!")
