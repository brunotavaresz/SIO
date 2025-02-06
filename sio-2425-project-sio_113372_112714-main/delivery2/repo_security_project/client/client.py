import os
import ast
import sys
import argparse
import logging
import json
import requests
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from base64 import b64encode
import os
import requests
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])
    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        print('REP_PUB_KEY: ', rep_pub_key)
        if os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    return state

def parse_args(state):
    parser = argparse.ArgumentParser()

    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")
    parser.add_argument("-c", "--command", help="Command to execute")
    parser.add_argument('arg0', nargs='?', default=None)
    parser.add_argument('arg1', nargs='?', default=None)
    parser.add_argument('arg2', nargs='?', default=None)
    parser.add_argument('arg3', nargs='?', default=None)
    parser.add_argument('arg4', nargs='?', default=None)
    parser.add_argument('arg5', nargs='?', default=None)

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    if args.key:
        if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
            logger.error(f'Key file not found or invalid: {args.key[0]}')
            sys.exit(-1)

        with open(args.key[0], 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')

    if args.repo:
        state['REP_ADDRESS'] = args.repo[0]
        logger.info('Overriding REP_ADDRESS from command line')
    
    if args.command:
        logger.info("Command: " + args.command)
       
    return state, {'command': args.command, 'arg0': args.arg0, 'arg1': args.arg1, 'arg2': args.arg2, 'arg3': args.arg3, 'arg4': args.arg4, 'arg5': args.arg5}

def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
      logger.debug('Creating state folder')
      os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))



def generate_aes_key():
    return os.urandom(32)  

def encrypt_data(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return b64encode(cipher.iv + encrypted_data).decode('utf-8')


def encrypt_all_data(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return b64encode(cipher.iv + encrypted_data).decode('utf-8')

def encrypt_aes_key_with_public_key(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher.encrypt(aes_key)
    return encrypted_aes_key


def rep_subject_credentials(password, credentials_file):
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        derived_key = kdf.derive(password.encode())

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())  # Use password directly
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        salt_base64 = base64.b64encode(salt).decode('utf-8')
        private_key_base64 = private_bytes.decode('utf-8')  
        public_key_base64 = public_bytes.decode('utf-8') 


        with open(credentials_file, 'w') as cred_file:

            cred_file.write(f"Salt (Base64 Encoded):\n{salt_base64}\n\n")
            cred_file.write(f"Private Key (Base64 Encoded, PEM Format):\n{private_key_base64}\n\n")
            cred_file.write(f"Public Key (Base64 Encoded, PEM Format):\n{public_key_base64}\n\n")

        print(f"Credentials saved to {credentials_file}.")

        private_key_file = "private_key_" + credentials_file
        public_key_file = "public_key_" + credentials_file

        with open(private_key_file, 'wb') as private_file:
            private_file.write(private_bytes)
        print(f"Private key saved to {private_key_file}.")

        with open(public_key_file, 'wb') as public_file:
            public_file.write(public_bytes)
        print(f"Public key saved to {public_key_file}.")

    except Exception as e:
        print(f"Error generating keys: {e}")
        sys.exit(1)


def rep_create_org(org, username, name, email, pubkey, state):
    if not org or not username or not name or not email or not pubkey:
        logger.error("Todos os parâmetros (org, username, name, email, pubkey) são obrigatórios.")
        return
    print("REP_PUB_KEY: ", state['REP_PUB_KEY'])

    if not isinstance(pubkey, str) or not pubkey.strip():
        logger.error("Caminho da chave pública inválido.")
        return

    try:
        with open(pubkey, 'r') as f:
            public_key = f.read()
    except FileNotFoundError:
        logger.error(f'Arquivo de chave pública não encontrado: {pubkey}')
        return
    except IOError as e:
        logger.error(f'Erro ao abrir o arquivo de chave pública: {str(e)}')
        return

    data = {
        "organization": org,
        "username": username,
        "full_name": name,
        "email": email,
        "public_key": public_key
    }
    print("Rep_pub_key: ", state['REP_PUB_KEY'])

    aes_key = generate_aes_key()


    encrypted_data = encrypt_all_data(json.dumps(data), aes_key)

    data_to_send = {
        "encrypted_data": encrypted_data,
        "aes_key": base64.b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
    }
    
    url = 'http://127.0.0.1:5000/organization/create'

    try:
        response = requests.post(url, json=data_to_send)
        response.raise_for_status() 
        logger.info(f'Organização {org} criada com sucesso.')
    except requests.exceptions.HTTPError as err:
        logger.error(f'Erro ao criar organização: {err}')
        logger.error(f'Resposta do servidor: {response.text}')
    except requests.exceptions.RequestException as e:
        logger.error(f'Erro ao fazer a requisição: {str(e)}')


    
def rep_list_orgs():

    url = f'http://127.0.0.1:5000/organization/list'
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        organizations = response.json()
        if organizations:
            logger.info(f"Organizações registradas: {organizations}")
        else:
            logger.info("Nenhuma organização registrada.")
    except requests.exceptions.HTTPError as err:
        logger.error(f"Erro ao listar organizações: {err}")
        logger.error(f"Resposta do servidor: {response.text}")
    except Exception as err:
        logger.error(f"Erro ao fazer a requisição: {err}")


def rep_create_session(organization, username, password, credentials_file, session_file, state):
    if not organization or not username or not password or not credentials_file or not session_file:
        print("Error: parameters (organization, username, password, credentials_file, session_file).")
        print("Usage: rep_create_session <organization> <username> <password> <credentials_file> <session_file>")
        return None

    url = 'http://localhost:5000/session/create'

    aes_key = generate_aes_key()

    data = {
        "organization": organization,
        "username": username,
        "password": password,
        "credentials_file": credentials_file,
        "session_file": session_file,
    }
    
    data_to_send = {
        'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
    }
    try:
        response = requests.post(url, json=data_to_send)
        
        if response.status_code == 200:
            print(f"Session created successfully for username {username} in organization {organization}.")
        else:
            print(f"Error creating session: {response.text}")
            return None
            
    except Exception as e:
        print(f"Error creating session: {str(e)}")
        return None

    
def rep_add_subject(session_file, username, name, email, credentials_file, state):
    if not session_file or not username or not name or not email or not credentials_file:
        print("Error: parameters (session_file, username, name, email, credentials_file)")
        print("Usage: rep_add_subject <session_file> <username> <name> <email> <credentials_file>")
        return

    try:
        aes_key = generate_aes_key()

        try:
            with open(credentials_file, 'r') as f:
                public_key = f.read()
        except FileNotFoundError:
            print(f"Error: Credentials file '{credentials_file}' not found.")
            return
        
        payload = {
            "session_file": session_file,
            "username": username,
            "name": name,
            "email": email,
            "public_key": public_key,
        }

        data_to_send = {
            'encrypted_data': encrypt_all_data(json.dumps(payload), aes_key),
             'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }

        response = requests.post("http://localhost:5000/subjects/add", json=data_to_send)

        if response.status_code == 201:
            print(f"Subject'{username}' add with success.")
        else:
            print(f"Error adding subject: {response.json().get('error')}")

    except Exception as e:
        print(f"Error making request: {str(e)}")


def rep_list_subjects(session_file, state, filter_username=None):
    try:

        url = 'http://localhost:5000/subjects/list'


        data = {
            'session_file': session_file,
            'filter_username': filter_username
        }
        aes_key = generate_aes_key()
        data_to_send = {
        'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
    }

        response = requests.post(url, json=data_to_send)

        if response.status_code == 200:
            encrypted_subjects = response.json().get('encrypted_subjects')
            if encrypted_subjects:
                private_key_path = input("Enter the private key file path: ")
                password = input("Enter the private key password (or press Enter if none): ")
                private_key = load_private_key(private_key_path, password)
                decrypted_subjects = json.loads(decrypt_with_private_key(encrypted_subjects, private_key))
                for sub in decrypted_subjects:
                    print(f"Username: {sub.get('username')}, Status: {sub.get('status')}")
            else:
                print("No subjects found.")
        else:
            print(f"Error: {response.json().get('error')}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")


import json
import requests

def rep_suspend_subject(session_file, username, state):
    if not session_file or not username:
        print("Error: All parameters (session_file, username) are required.")
        print("Usage: rep_suspend_subject <session_file> <username>")
        return

    data = {
        "session_file": session_file,
        "username": username
    }
    aes_key = generate_aes_key()
    data_to_send = {
        'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
    }

    api_url = "http://127.0.0.1:5000/subjects/suspend"

    try:
        response = requests.post(api_url, json=data_to_send)
        print(response.json())
        if response.status_code == 200:
            print(f"Subject '{username}' suspended successfully.")
        else:
            print(f"Error: {response.json().get('message')}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the API: {e}")


def rep_activate_subject(session_file, username,state):

    if not session_file or not username:
        print("Error: All parameters (session_file, username) are required.")
        print("Usage: rep_activate_subject <session_file> <username>")
        return


    api_url = "http://127.0.0.1:5000/subjects/activate"

    data = {
        "username": username,
        "session_file": session_file
    }
    aes_key = generate_aes_key()
    data_to_send = {
        'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }

    try:
        response = requests.post(api_url, json=data_to_send)
        if response.status_code == 200:
            print(f"Subject '{username}' activated successfully.")
        else:
            print(f"Error activating subject: {response.json().get('message')}")
    except requests.exceptions.RequestException as e:
            print(f"Error connecting to the API: {e}")


def rep_add_doc(session_file, document_handle, file_path, state):
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        payload = {
            'session_file': session_file,
            'document_handle': document_handle,
            'file_path': file_path
        }

        aes_key = generate_aes_key()
        payload_encrypted = encrypt_all_data(json.dumps(payload), aes_key)
   
        data_to_send = {
        "encrypted_data": payload_encrypted,
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }

        response = requests.post('http://127.0.0.1:5000/document/create', json=data_to_send)

        if response.status_code == 200:
            print(f"Document uploaded successfully: {response.json()}")
        else:
            print(f"Error uploading document: {response.status_code} - {response.text}")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        raise

def rep_get_doc_metadata(session_file, document_name, state):
    try:
        payload = {
            'session_file': session_file,
            'document_name': document_name
        }

        aes_key = generate_aes_key()
        payload['aes_key'] = aes_key.hex()
        payload_encrypted = encrypt_all_data(json.dumps(payload), aes_key)
        data_to_send = {
            "encrypted_data": payload_encrypted,
            'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
            }
        
        response = requests.post('http://127.0.0.1:5000/document/metadata', json=data_to_send)

        if not response.ok:
            print(f"Server error: {response.status_code} - {response.text}")
            return None
        
        print(response.json())

        return response.json()
        
    except Exception as e:
        raise Exception(f"Error fetching document metadata: {str(e)}")

def rep_list_docs(session_file, state, creator=None, date_filter=None, date_value=None):
    try:
      payload = {
          "session_file": session_file
      }
      
      if creator:
          payload["creator"] = creator
      if date_filter and date_value:
          payload["date_filter"] = date_filter
          payload["date_value"] = date_value
      aes_key = generate_aes_key()
      encrypted_data = encrypt_all_data(json.dumps(payload), aes_key)
      data_to_send = {
            "encrypted_data": encrypted_data,
            'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }
      
      response = requests.post('http://127.0.0.1:5000/document/list', json=data_to_send)
      if response.status_code == 200:
            encrypted_data  = response.json().get('document_handles')
            private_key_path = input("Enter the private key file path: ")
            password = input("Enter the private key password (or press Enter if none): ")
            private_key = load_private_key(private_key_path, password)
            decrypted_response = decrypt_with_private_key(encrypted_data, private_key)
            response_data = json.loads(decrypted_response)
            for org in response_data:
                print(f"Documents found for organization: {org}")
                for doc in response_data[org]:
                    print(f"- {doc}")
            
      else:
              print(f"Error uploading document: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        raise


def rep_delete_doc(session_file, document_name, state):
    payload = {
        "session_file": session_file,
        "document_name": document_name
    }
    aes_key = generate_aes_key()
    encrypted_payload = encrypt_all_data(json.dumps(payload), aes_key)
    data_to_send = {
        "encrypted_payload": encrypted_payload,
        "aes_key": b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }
    try:
        response = requests.post('http://127.0.0.1:5000/document/delete', json=data_to_send)
        response.raise_for_status()  
        print(f"Document '{document_name}' deleted successfully.")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error sending request: {e}")
        return None    

def rep_get_doc_file(session_file, document_name, state, output_file=None):

    try:
        payload = {
            "session_file": session_file,
            "document_name": document_name
        }
        
        if output_file:
            payload["output_file"] = output_file  
        
        aes_key = generate_aes_key()
        payload["aes_key"] = aes_key.hex()
        encrypted_payload = encrypt_all_data(json.dumps(payload), aes_key)

        data_to_send = {
            "encrypted_data": encrypted_payload,
            "aes_key": b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')    
        }
        
        response = requests.post("http://127.0.0.1:5000/document/get", json=data_to_send)

        if response.status_code == 200:
            if output_file:
                with open(output_file, "wb") as f:
                    f.write(response.content)
                print(f"File successfully saved to {output_file}")
            else:
                print(response.content.decode('utf-8'))
        else:
            print(f"Error: {response.status_code} - {response.json().get('error', 'Unknown error')}")

    except Exception as e:
        print(f"Error in rep_get_doc_file: {str(e)}")

def rep_decrypt_file(encrypted_file, encryption_metadata):
    try:
        metadata = load_json(encryption_metadata)



        alg = metadata['restricted_metadata']['alg'] 
        key = (metadata['restricted_metadata']['key']) 

        if alg == "AES-GCM-SHA256":
            print("Decrypting file using AES algorithm...")
            iv = (metadata['iv']) 
            with open(encrypted_file, 'rb') as enc_file:
                print(f"Reading encrypted file: {encrypted_file}")
                ciphertext = enc_file.read()
            print(f"Encrypted file read successfully: {ciphertext}")

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            padder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = padder.update(padded_plaintext) + padder.finalize()

            if 'hash' in metadata:
                expected_hash = metadata['hash']
                file_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
                file_hash.update(plaintext)
                generated_hash = file_hash.finalize().hex()

                if generated_hash != expected_hash:
                    raise ValueError("Integrity check failed: File has been tampered with.")

            sys.stdout.buffer.write(plaintext)
            print("\nFile decrypted successfully.")

        else:
            raise ValueError(f"Unsupported algorithm: {alg}")

    except Exception as e:
        print(f"Error decrypting file: {e}")
        sys.exit(1)

def rep_get_file(file_handle, state, output_file=None):

    try:
        payload = {
        "file_handle": file_handle
        }
        aes_key = generate_aes_key()
        payload["aes_key"] = aes_key.hex()
        encrypted_payload = encrypt_all_data(json.dumps(payload), aes_key)
        data_to_send = {
        "encrypted_payload": encrypted_payload,
        "aes_key": b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }

        response = requests.post('http://127.0.0.1:5000/document/download', json=data_to_send)
        response.raise_for_status()  

        if output_file:

            with open(output_file, 'wb') as f:
                f.write(response.content)
            print(f"File {file_handle} downloaded successfully to {output_file}.")
        else:
            output_path = "../client/" + file_handle + ".encrypted"
            with open(output_path, 'wb') as f:
                f.write(response.content)
            print(f"File {file_handle} downloaded successfully to {output_path}.")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file: {str(e)}")

# ---------------------------------------------------------------------------------------------------------------
# 2 delivery

from datetime import datetime


def load_json(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        return None
    except json.JSONDecodeError:
        print(f"Error: Error processing the JSON file: {file_path}")
        return None


def rep_assume_role(session_file, role, state):
    if not session_file or not role:
        print("Error: All parameters (session_file, role) are mandatory.")
        print("Usage: rep_assume_role <session_file> <role>")
        return None

    url = 'http://localhost:5000/session/assume_role'

    try:

        aes_key = generate_aes_key()
        
        data = {
            'session_file': session_file,
            'role': role
        }
        data_to_send = {
            'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
            'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }

        response = requests.post(url, json=data_to_send)

        if response.status_code == 200:
            print(f"Role {role} assumed successfully.")
        else:
            print(f"Error assuming the role: {response.text}")
    except Exception as e:
        print(f"Error assuming the role: {str(e)}")

def rep_drop_role(session_file, role, state):
    if not session_file or not role:
        print("Error: All parameters (session_file, role) are mandatory.")
        print("Usage: rep_drop_role <session_file> <role>")
        return None
    print(f"Removing role {role} from session file {session_file}")
    url = 'http://localhost:5000/session/drop_role'
    
    try:

        aes_key = generate_aes_key()
        
        data = {
            'session_file': session_file,
            'role': role
        }
        data_to_send = {
            'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
            'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }

        response = requests.post(url, json=data_to_send)
        
        if response.status_code == 200:
            print(f"Role {role} removed successfully.")
        else:
            print(f"Error removing the role: {response.text}")

    except Exception as e:
        print(f"Error removing the role: {str(e)}")


def rep_list_roles(session_file, state):

    aes_key = generate_aes_key()

    data = {
        'session_file': session_file
    }

    data_to_send = {
        'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
    }

    url = 'http://localhost:5000/roles/list'
    try:
        response = requests.post(url, json=data_to_send)
        if response.status_code == 200:
            encrypted_data = response.json().get('encrypted_data')

            if encrypted_data:
                private_key_path = input("Enter the private key file path: ")
                password = input("Enter the private key password (or press Enter if none): ")
                private_key = load_private_key(private_key_path, password)
                decrypted_response = decrypt_with_private_key(encrypted_data, private_key)

                decrypted_data = json.loads(decrypted_response)

                active_roles = decrypted_data.get('active_roles', [])
                inactive_roles = decrypted_data.get('past_roles', [])
                
                if active_roles:
                    print("Active role: ", active_roles[0])
                else:
                    print("No active roles")

                if inactive_roles:
                    for a in inactive_roles:
                        print("Inactive role: ", a)
                else:
                    print("No inactive roles")

            else:
                print("Error: No encrypted data found in response.")
        else:
            print(f"Error listing roles: {response.json().get('error', 'Unknown error')}")
    except Exception as e:
        print(f"Error listing roles: {str(e)}")



from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from base64 import b64encode, b64decode

def load_private_key(private_key_path, password=None):

    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode() if password else None,
            backend=default_backend()
        )
    return private_key

def decrypt_with_private_key(encrypted_data, private_key):
   
    decrypted_data = private_key.decrypt(
        b64decode(encrypted_data),
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode('utf-8')  

def rep_list_role_subjects(session_file, role, state):
    if not session_file or not role:
        print("Error: Both session_file and role are required.")
        return 

    url = 'http://localhost:5000/roles/subjects'

    try:
        data = {
            'session_file': session_file,
            'role': role
        }

        aes_key = generate_aes_key()
        data_encrypted = encrypt_all_data(json.dumps(data), aes_key)
        data_to_send = {
            'encrypted_data': data_encrypted,
            'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }

        response = requests.post(url, json=data_to_send)
        if response.status_code == 200:
            encrypted_subjects = response.json().get('subjects')
            print
            if encrypted_subjects:
                
                private_key_path = input("Enter the private key file path: ")
                password = input("Enter the private key password (or press Enter if none): ")
                private_key = load_private_key(private_key_path, password)

                decrypted_subjects = decrypt_with_private_key(encrypted_subjects, private_key)

                print(f"Decrypted subjects for role '{role}': {decrypted_subjects}")
            else:
                print(f"No subjects found for role '{role}'.")
        else:
            print(f"Error: {response.json().get('error', 'Unknown error')}")

    except Exception as e:
        print(f"Error: {str(e)}")


def rep_add_role(session_file, role,state):
    if not session_file or not role:
        print("Error: Both session_file and role are required.")
        return
    url = 'http://localhost:5000/role/add'
    data = {
        'session_file': session_file,
        'role': role
    }
    aes_key = generate_aes_key()
    data_encrypted = encrypt_all_data(json.dumps(data), aes_key)
    data_to_send = {
        'data': data_encrypted,
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
    }
    try:
        response = requests.post(url, json=data_to_send)
        if response.status_code == 200:
            print(f"Role '{role}' added successfully.")
        else:
            print(f"Error adding role:\n {response.json().get('error', 'Unknown error')}")
    except Exception as e:
            print(f"Error adding role: {str(e)}")

def rep_suspend_role(session_file, role, state):
    if not session_file or not role:
        print("Error: session_file and role are required.")
        return

    url = 'http://localhost:5000/role/suspend'
    data = {
        'session_file': session_file,
        'role': role
    }
    aes_key = generate_aes_key()
    data_encrypted = encrypt_all_data(json.dumps(data), aes_key)
    data_to_send = {
        'data': data_encrypted,
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }

    try:
        response = requests.post(url, json=data_to_send)
        if response.status_code == 200:
            print(f"Role '{role}' suspended successfully.")
        else:
            print(f"Error suspending role:\n {response.json().get('error', 'Unknown error')}")
    except Exception as e:
        print(f"Error suspending role: {str(e)}")




def rep_reactivate_role(session_file, role, state):
    if not session_file or not role:
        print("Error: session_file and role are required.")
        return

    url = 'http://localhost:5000/role/reactivate'
    data = {
        'session_file': session_file,
        'role': role
    }
    aes_key = generate_aes_key()
    data_encrypted = encrypt_all_data(json.dumps(data), aes_key)
    data_to_send = {
        'data': data_encrypted,
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
    }

    try:
        response = requests.post(url, json=data_to_send)
        if response.status_code == 200:
            print(f"Role '{role}' reactivated successfully.")
        else:
            print(f"Error reactivating role:\n {response.json().get('error', 'Unknown error')}")
    except Exception as e:
        print(f"Error reactivating role: {str(e)}")


def rep_add_permission(session_file, role, permission, state):
    

    PERMISSOES = [
        "ROLE_ACL",
        "ROLE_DOWN",
        "ROLE_UP",
        "ROLE_NEW",
        "ROLE_MOD",
        "SUBJECT_NEW",
        "SUBJECT_UP",
        "SUBJECT_DOWN",
        "DOC_NEW",
        "DOC_READ",
        "DOC_DELETE"
    ]

    if permission in PERMISSOES:

        aes_key = generate_aes_key()

        if not session_file or not role or not permission:
            print("Error: session_file, role, and permission are required.")
            return

        url = 'http://localhost:5000/permission/add'
        data = {
            'session_file': session_file,
            'role': role,
            'permission': permission
        }

        data_to_send = {
            'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
            'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }
        

        try:
            response = requests.post(url, json=data_to_send)
            if response.status_code == 200:
                print(f"Permission '{permission}' added to role '{role}' successfully.")
            else:
                print(f"Error adding permission:\n {response.json().get('error', 'Unknown error')}")
        except Exception as e:
            print(f"Error adding permission: {str(e)}")

    else:

        aes_key = generate_aes_key()

        url = 'http://localhost:5000/add_permission'
        data = {
            'session_file': session_file,
            'role': role,
            'permission': permission
        }

        data_to_send = {
            'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
            'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }

        try:
            response = requests.post(url, json=data_to_send)
            if response.status_code == 200:
                print(f"Role '{role}' added to '{permission}' successfully.")
                return response.json() 
            else:
                return {"error": f"Failed to add permission: {response.text}"}
        
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}

def rep_remove_permission(session_file, role, permission, state):

    PERMISSOES = [
        "ROLE_ACL",
        "ROLE_DOWN",
        "ROLE_UP",
        "ROLE_NEW",
        "ROLE_MOD",
        "SUBJECT_NEW",
        "SUBJECT_UP",
        "SUBJECT_DOWN",
        "DOC_NEW",
        "DOC_READ",
        "DOC_DELETE"
    ]
    
    if permission in PERMISSOES:
        if not session_file or not role or not permission:
            print("Error: session_file, role, and permission are required.")
            return
        
        aes_key = generate_aes_key()

        url = 'http://localhost:5000/permission/remove'
        data = {
            'session_file': session_file,
            'role': role,
            'permission': permission
        }

        data_to_send = {
            'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
            'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }

        try:
            response = requests.post(url, json=data_to_send)
            if response.status_code == 200:
                print(f"Permission '{permission}' removed from role '{role}' successfully.")
            else:
                print(f"Error removing permission:\n {response.json().get('error', 'Unknown error')}")
        except Exception as e:
            print(f"Error removing permission: {str(e)}")

    else:

        aes_key = generate_aes_key()

        url = 'http://localhost:5000/remove_permission'
        data = {
            'session_file': session_file,
            'role': role,
            'permission': permission
        }

        data_to_send = {
            'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
            'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
        }

        try:
            response = requests.post(url, json=data_to_send)

            if response.status_code == 200:
                print(f"Role '{role}' removed from '{permission}' successfully.")
                return response.json() 
            else:
                return {"error": f"Failed to remove permission: {response.text}"}
        
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}



def rep_acl_doc(session_file, doc_name, sign, role, permission, state):
    if sign not in ["+", "-"]:
        print("Error: Invalid sign. Use '+' to add or '-' to remove.")
        return
        

    url = 'http://localhost:5000/acl_doc'
    data = {
        'session_file': session_file,
        'doc_name': doc_name,
        'sign': sign,
        'role': role,
        'permission': permission
    }
    aes_key = generate_aes_key()
    data_to_send = {
        'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
    }

    try:
        response = requests.post(url, json=data_to_send)
        if response.status_code == 200:
            print(f"ACL updated successfully for document '{doc_name}'.")
        else:
            error_message = response.json().get('error', 'Unknown error')
            print(f"Error updating ACL: {error_message}")
    except requests.exceptions.RequestException as e:
        print(f"Error communicating with the server: {str(e)}")

def rep_list_role_permissions(session_file, role, state):
    if not session_file or not role:
        print("Error: session_file and role are required.")
        return
    data = {
        'session_file': session_file,
        'role': role
    }
    aes_key = generate_aes_key()
    data_to_send = {
        'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
    }
                                                             
    url = 'http://localhost:5000/role/permissions'
    try:
        response = requests.post(url, json=data_to_send)
        
        if response.status_code == 200:
            encrypted_permissions = response.json().get('permissions')
            if encrypted_permissions:
                private_key_path = input("Enter the private key file path: ")
                password = input("Enter the private key password (or press Enter if none): ")
                private_key = load_private_key(private_key_path, password)
                decrypted_permissions = (decrypt_with_private_key(encrypted_permissions, private_key))

                print(f"Permissions for role '{role}':")
                decrypted_permissions = ast.literal_eval(decrypted_permissions)

                for permission in decrypted_permissions:
                    print(permission)
        else:
            print(f"Error listing permissions:\n {response.json().get('error', 'Unknown error')}")
    except Exception as e:
        print(f"Error listing permissions: {str(e)}")

def rep_list_subject_roles(session_file, username, state):
    if not session_file or not username:
        print("Error: session_file and username are required.")
        return

    aes_key = generate_aes_key()

    url = 'http://localhost:5000/subject/roles'
    data = {
        'session_file': session_file,
        'username': username
    }

    data_to_send = {
        'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
    }

    try:
        response = requests.post(url, json=data_to_send)
        if response.status_code == 200:
            encrypted_roles = response.json().get('roles', None)

            if encrypted_roles:
  
                private_key_path = input("Enter the private key file path: ")

                password = input("Enter the private key password (or press Enter if none): ")

                private_key = load_private_key(private_key_path, password)

                decrypted_roles = decrypt_with_private_key(encrypted_roles, private_key)

                roles = json.loads(decrypted_roles) 
                print(f"Roles for user '{username}': {roles}")
            else:
                print("No roles found or encrypted data is missing.")
        else:
            print(f"Error fetching roles:\n {response.json().get('error', 'Unknown error')}")
    except Exception as e:
        print(f"Error: {str(e)}")

def rep_list_permission_roles(session_file, permission, state):
    if not session_file or not permission:
        print("Error: session_file and permission are required.")
        return

    aes_key = generate_aes_key()

    data = {
        'session_file': session_file,
        'permission': permission
        }

    data_to_send = {
        'encrypted_data': encrypt_all_data(json.dumps(data), aes_key),
        'aes_key': b64encode(encrypt_aes_key_with_public_key(aes_key, state['REP_PUB_KEY'])).decode('utf-8')
    }
    url = 'http://localhost:5000/permission/roles'
    try:
        response = requests.post(url, json=data_to_send)
        if response.status_code == 200:
            encrypted_roles = response.json().get('roles', None)
            if not encrypted_roles:
                print("Error: No encrypted roles received from the server.")
                return

            private_key_path = input("Enter the private key file path: ")
            password = input("Enter the private key password (or press Enter if none): ")
            private_key = load_private_key(private_key_path, password)

            decrypted_roles = decrypt_with_private_key(encrypted_roles, private_key)
            roles = json.loads(decrypted_roles)

            if roles:
                print(f"Roles with permission '{permission}':")
                for role in roles:
                    print(role)
            else:
                print(f"No roles found with permission '{permission}'.")
        else:
            print(f"Error listing roles:\n {response.json().get('error', 'Unknown error')}")
    except Exception as e:
        print(f"Error listing roles: {str(e)}")


def main():
    state = load_state()
    state = parse_env(state)
    state, args = parse_args(state)
    if 'REP_ADDRESS' not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if 'REP_PUB_KEY' not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)
    
    logger.debug("Arguments: " + str(args))


    print("Program name:", args["command"])
    

    if args["command"]  == "rep_create_org":
        rep_create_org(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"], state)

    elif args["command"] == "rep_list_orgs":
        rep_list_orgs()

    elif args["command"] == "rep_create_session":
        rep_create_session(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"],state)

    elif args["command"] == "rep_add_subject":
        rep_add_subject(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"], state)

    elif args["command"] == "rep_list_subjects":
        if not args["arg0"]:
            print("Error session_file is required.")
            return
        session_file = args["arg0"]
        username = args["arg1"] if args["arg1"] else None
        rep_list_subjects(session_file, state, filter_username=username)

        
    elif args["command"] == "rep_suspend_subject":
        rep_suspend_subject(args["arg0"], args["arg1"], state)

    elif args["command"] == "rep_activate_subject":
        rep_activate_subject(args["arg0"], args["arg1"], state)

    elif args["command"] == "rep_add_doc":
        rep_add_doc(args["arg0"], args["arg1"], args["arg2"], state)

    elif args["command"] == "rep_get_doc_metadata":
        rep_get_doc_metadata(args["arg0"], args["arg1"], state)

    elif args["command"] == "rep_subject_credentials":
        # Verificar se o arg1 termina com '.pem'
        if args["arg1"].endswith(".pem"):
            rep_subject_credentials(args["arg0"], args["arg1"])
        else:
            print("Error argument 1 must end with '.pem'")


    elif args["command"] == "rep_list_docs":
        session_file = args["arg0"]
        username = args["arg1"] if args["arg1"] else None
        date_filter = args["arg2"] if args["arg2"] else None
        data_value = args["arg3"] if args["arg3"] else None
        rep_list_docs(session_file, state, date_filter=date_filter, date_value=data_value)

    elif args["command"] == "rep_delete_doc":
        rep_delete_doc(args["arg0"], args["arg1"], state)

    elif args["command"] == "rep_get_file":
        file_handle = args["arg0"]
        file = args["arg1"] if args["arg1"] else None
        rep_get_file(file_handle,state,  file)

    elif args["command"] == "rep_get_doc_file":
        session_file = args["arg0"]
        document_name = args["arg1"]
        output_file = args["arg2"]
        if not session_file or not document_name:
            print("Error: session_file and document_name are required.")
            return

        rep_get_doc_file(session_file, document_name, state, output_file)

    elif args["command"] == "rep_decrypt_file":
        rep_decrypt_file(args["arg0"], args["arg1"])

    elif args["command"] == "rep_assume_role":
        rep_assume_role(args["arg0"], args["arg1"], state)

    elif args["command"] == "rep_drop_role":
        rep_drop_role(args["arg0"], args["arg1"], state)

    elif args["command"] == "rep_list_roles":
        rep_list_roles(args["arg0"], state)

    elif args["command"] == "rep_list_role_subjects":
        rep_list_role_subjects(args["arg0"], args["arg1"], state)
    elif args["command"] == "rep_add_role":
        rep_add_role(args["arg0"], args["arg1"], state)

    elif args["command"] == "rep_add_permission":
        rep_add_permission(args["arg0"], args["arg1"], args["arg2"], state)


    elif args["command"] == "rep_remove_permission":
        rep_remove_permission(args["arg0"], args["arg1"], args["arg2"],state)

    elif args["command"] == "rep_acl_doc":
        sign = args["arg2"]  # '+' para adicionar, '-' para remover

        if sign not in ('+', '-'):
            raise ValueError("Sinal inválido. Use '+' para adicionar ou '-' para remover.")

        rep_acl_doc(args["arg0"], args["arg1"], sign, args["arg3"], args["arg4"], state)

    elif args["command"] == "rep_list_role_permissions":
        rep_list_role_permissions(args["arg0"], args["arg1"], state)

    elif args["command"] == "rep_suspend_role":
        rep_suspend_role(args["arg0"], args["arg1"], state)
    elif args["command"] == "rep_list_permission_roles":
        rep_list_permission_roles(args["arg0"], args["arg1"], state)

    
    elif args["command"] == "rep_list_subject_roles":
        rep_list_subject_roles(args["arg0"], args["arg1"], state)
    elif args["command"] == "rep_reactivate_role":
        rep_reactivate_role(args["arg0"], args["arg1"], state)


    else:
        logger.error("Invalid command")




if __name__ == "__main__":
    main()