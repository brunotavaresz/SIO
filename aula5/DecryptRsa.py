import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o","--Origin", help="Origin file")
    parser.add_argument("-d","--Destination", help="Destination for the encrypted file")
    parser.add_argument("-p","--Private", help="Private key")
    args = parser.parse_args()
    
    with open(args.Private, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
    with open(args.Origin, "rb") as f:
        data = f.read()
    decrypted = private_key.decrypt(
        data,
        PKCS1v15()
    )
    
    with open(args.Destination, "wb") as f:
        f.write(decrypted)


if __name__ == "__main__":
    main()