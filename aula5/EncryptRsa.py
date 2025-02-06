import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o","--Origin", help="Origin file")
    parser.add_argument("-d","--Destination", help="Destination for the encrypted file")
    parser.add_argument("-p","--Public", help="Public key")
    args = parser.parse_args()
    with open(args.Public, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
        )
    with open(args.Origin, "rb") as f:
        data = f.read()
    encrypted = public_key.encrypt(
        data,
        PKCS1v15()
    )
    
    with open(args.Destination, "wb") as f:
        f.write(encrypted)
    

if __name__ == "__main__":
    main()
        