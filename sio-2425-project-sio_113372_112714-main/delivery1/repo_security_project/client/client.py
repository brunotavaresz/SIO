import os
import sys
import argparse
import logging
import json
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
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

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)

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
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
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


# Função para gerar uma chave de criptografia AES
def generate_aes_key():
    return os.urandom(32)  # 256-bit chave AES

# Função para criptografar os dados com AES
def encrypt_data(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return b64encode(cipher.iv + encrypted_data).decode('utf-8')

# Função para criptografar todos os dados com AES
def encrypt_all_data(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    # Certificando-se de que os dados são compatíveis com o tamanho do bloco AES (padded)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    # Retorna o vetor de inicialização (IV) concatenado com os dados criptografados
    return b64encode(cipher.iv + encrypted_data).decode('utf-8')

# comando local
def rep_subject_credentials(password, credentials_file):
    try:
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Generate a salt and derive a key from the password
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        # Derived key, though we use password directly to encrypt the private key
        derived_key = kdf.derive(password.encode())

        # Serialize and encrypt the private key with the password
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())  # Use password directly
        )

        # Serialize the public key
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Base64 encode the salt, private key, and public key to make them easier to store in text form
        salt_base64 = base64.b64encode(salt).decode('utf-8')
        private_key_base64 = private_bytes.decode('utf-8')  # private key is already in PEM format
        public_key_base64 = public_bytes.decode('utf-8')  # public key is already in PEM format

        # Write everything into the .pem file
        with open(credentials_file, 'w') as cred_file:
            # Write the base64-encoded salt, private key, and public key in a readable format
            cred_file.write(f"Salt (Base64 Encoded):\n{salt_base64}\n\n")
            cred_file.write(f"Private Key (Base64 Encoded, PEM Format):\n{private_key_base64}\n\n")
            cred_file.write(f"Public Key (Base64 Encoded, PEM Format):\n{public_key_base64}\n\n")

        print(f"Credentials saved to {credentials_file}.")

        # Save the private and public keys into separate files in PEM format
        private_key_file = "private_key" + ".pem"
        public_key_file = "public_key" + ".pem"

        # Save private key in PEM format
        with open(private_key_file, 'wb') as private_file:
            private_file.write(private_bytes)
        print(f"Private key saved to {private_key_file}.")

        # Save public key in PEM format
        with open(public_key_file, 'wb') as public_file:
            public_file.write(public_bytes)
        print(f"Public key saved to {public_key_file}.")

    except Exception as e:
        print(f"Error generating keys: {e}")
        sys.exit(1)


def rep_create_org(org, username, name, email, pubkey):
    # Verificar se todos os argumentos foram fornecidos
    if not org or not username or not name or not email or not pubkey:
        logger.error("Todos os parâmetros (org, username, name, email, pubkey) são obrigatórios.")
        return

    # Verificar se o caminho da chave pública é válido
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

    # Preparar os dados para enviar ao servidor (sem criptografar ainda)
    data = {
        "organization": org,
        "username": username,
        "full_name": name,
        "email": email,
        "public_key": public_key
    }

    # Gerar a chave AES
    aes_key = generate_aes_key()

    # Criptografar todos os dados (não apenas a chave pública)
    encrypted_data = encrypt_all_data(json.dumps(data), aes_key)

    # Preparar o payload para enviar
    data_to_send = {
        "encrypted_data": encrypted_data,  # Dados criptografados
        "aes_key": b64encode(aes_key).decode('utf-8')  # Chave AES em base64
    }

    logger.info(f"Payload being sent: {data_to_send}")
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

    print("rep_create_org: org=%s, username=%s, name=%s, email=%s, pubkey=%s" % (org, username, name, email, pubkey))


    
def rep_list_orgs():

    url = f'http://127.0.0.1:5000/organization/list'
    
    try:
        # pedido GET
        response = requests.get(url)
        response.raise_for_status()
        
        # Mostrar as organizações
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


def save_session(session_file, session_data):
    # Carregar os dados de sessão existentes do arquivo
    try:
        with open(session_file, 'r') as f:
            existing_sessions = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_sessions = {}

    # Adicionar ou atualizar os dados da sessão
    existing_sessions[session_data['session_id']] = session_data

    # Salvar os dados atualizados no arquivo
    with open(session_file, 'w') as f:
        json.dump(existing_sessions, f, indent=4)


def rep_create_session(organization, username, password, credentials_file, session_file):
    # Verificar se todos os parâmetros necessários estão presentes
    if not organization or not username or not password or not credentials_file or not session_file:
        print("Erro: Todos os parâmetros (organization, username, password, credentials_file, session_file) são obrigatórios.")
        print("Usage: rep_create_session <organization> <username> <password> <credentials_file> <session_file>")
        return None

    url = 'http://localhost:5000/session/create'
    
    # Gerar chave AES
    aes_key = generate_aes_key()

    # Criptografar o password e o username
    encrypted_username = encrypt_data(username, aes_key)
    encrypted_password = encrypt_data(password, aes_key)

    data = {
        "organization": organization,
        "username": encrypted_username,
        "password": encrypted_password,
        "credentials_file": credentials_file,
        "session_file": session_file,
        "aes_key": b64encode(aes_key).decode('utf-8')  # Enviar a chave AES em base64
    }
    
    print(f"Creating session with data: {data}")

    try:
        response = requests.post(url, json=data)
        
        if response.status_code == 200:
            session_data = response.json()

            if 'session_id' not in session_data or 'session_keys' not in session_data:
                print("Error: Incomplete session data received from server")
                return None
                
            confidentiality_key = bytes.fromhex(session_data['session_keys']['confidentiality_key'])
            integrity_key = bytes.fromhex(session_data['session_keys']['integrity_key'])
            
            # Adicionar status ativo à sessão
            session_data["status"] = "active"
            
            # Salvar os dados da sessão no arquivo
            save_session(session_file, session_data)

            print(f"Session created successfully with session ID: {session_data['session_id']}")
            return session_data
        else:
            print(f"Error creating session: {response.text}")
            return None
            
    except Exception as e:
        print(f"Error creating session: {str(e)}")
        return None

    
def rep_add_subject(session_file, username, name, email, credentials_file):
    """ Adiciona um novo sujeito à organização associada à sessão atual. """
    # Verificar se todos os parâmetros necessários estão presentes
    if not session_file or not username or not name or not email or not credentials_file:
        print("Erro: Todos os parâmetros (session_file, username, name, email, credentials_file) são obrigatórios.")
        print("Usage: rep_add_subject <session_file> <username> <name> <email> <credentials_file>")
        return

    try:
        # Carregar os dados de sessão
        sessions = load_session_data(session_file)
        session_id = list(sessions.keys())[0]  # Assume que existe apenas uma sessão no ficheiro (logo le so o primeiro que aparecer)
        session_data = sessions[session_id]

        # Verificar se a sessão está ativa
        if session_data.get("status") != "active":
            print("Erro: Sessão não está ativa.")
            return

        # Recuperar a organização associada à sessão
        organization = session_data.get("organization")
        if not organization:
            print("Erro: Organização não encontrada na sessão.")
            return

        # Gerar chave AES para criptografar os dados
        aes_key = generate_aes_key()

        # Criptografar os dados
        encrypted_username = encrypt_data(username, aes_key)
        encrypted_name = encrypt_data(name, aes_key)
        encrypted_email = encrypt_data(email, aes_key)

        # Carregar a chave pública do ficheiro da credentials.pem
        try:
            with open(credentials_file, 'r') as f:
                public_key = f.read()
        except FileNotFoundError:
            print(f"Erro: Ficheiro de credenciais '{credentials_file}' não encontrado.")
            return

        # payload para a requisição com dados criptografados e a chave AES
        payload = {
            "session_file": session_file,
            "session_id": session_id,
            "username": encrypted_username,
            "name": encrypted_name,
            "email": encrypted_email,
            "public_key": public_key,
            "organization": organization,
            "aes_key": b64encode(aes_key).decode('utf-8')  # Enviar a chave AES em base64
        }

        # Fazer a requisição POST ao servidor
        response = requests.post("http://localhost:5000/subjects/add", json=payload)

        if response.status_code == 201:
            print(f"Sujeito '{username}' adicionado com sucesso!")
        else:
            print(f"Erro ao adicionar sujeito: {response.json()}")

    except Exception as e:
        print(f"Erro ao fazer a requisição: {str(e)}")

def load_session_data(sessions_file):
    """ Carrega os dados do arquivo de sessões e retorna o dicionário de sessões. """
    try:
        with open(sessions_file, 'r') as file:
            sessions_data = json.load(file)
            return sessions_data
    except FileNotFoundError:
        print(f"Erro: Arquivo de sessões '{sessions_file}' não encontrado.")
        exit(1)
    except json.JSONDecodeError:
        print("Erro ao decodificar o arquivo JSON de sessões.")
        exit(1)

def rep_list_subjects(session_file, filter_username=None):
    try:
        # Obter o session_id a partir do arquivo de sessão
        session_id, organization = get_session_info_from_file(session_file)

        if not session_id:
            print(f"Error: Session ID not found in file {session_file}")
            return

        # Definir a URL do endpoint
        url = 'http://localhost:5000/subjects/list'

        # Construir os dados para enviar na solicitação
        data = {
            'session_file': session_file,
            'session_id': session_id,
            'filter_username': filter_username
        }

        # Enviar a solicitação POST para o servidor
        response = requests.post(url, json=data)

        # Verificar o status da resposta
        if response.status_code == 200:
            response_data = response.json()
            print("Subjects list:")
            subjects = response_data.get('subjects', [])
            if filter_username:
                # Se o username foi passado, verificar e exibir apenas o subject correspondente
                subject = next((s for s in subjects if s['username'] == filter_username), None)
                if subject:
                    print(f"Username: {subject['username']}, Status: {subject['status']}")
                else:
                    print("Subject not found.")
            else:
                # Caso não tenha filtrado pelo username, exibir todos os subjects
                for subject in subjects:
                    print(f"Username: {subject['username']}, Status: {subject['status']}")
        else:
            print(f"Error: {response.json().get('error')}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

def get_session_info_from_file(session_file):
    """
    Função para obter o session_id e a organização a partir do arquivo de sessões.
    """
    try:
        with open(session_file, 'r') as f:
            sessions = json.load(f)  # Carregar o arquivo JSON
            # Buscar o session_id e a organização para a sessão ativa
            for session_id, session_data in sessions.items():
                if session_data['status'] == 'active':
                    return session_id, session_data['organization']
    except Exception as e:
        print(f"Error reading session file: {e}")
        return None, None

def rep_suspend_subject(session_file, username):
    """
    Suspende um sujeito usando o ficheiro de sessões especificado.
    """
    # Verificar se os parâmetros obrigatórios estão presentes
    if not session_file or not username:
        print("Erro: Todos os parâmetros (session_file, username) são obrigatórios.")
        print("Usage: rep_suspend_subject <session_file> <username>")
        return

    try:
        # Carregar o conteúdo do ficheiro de sessão
        with open(session_file, 'r') as f:
            sessions = json.load(f)
    except FileNotFoundError:
        print(f"Error: O ficheiro {session_file} não foi encontrado.")
        return
    except json.JSONDecodeError:
        print(f"Error: O ficheiro {session_file} está corrompido.")
        return

    # Verificar se existe alguma sessão ativa
    session_id = None
    for session in sessions.values():
        if session['status'] == 'active':
            session_id = session['session_id']
            break

    if not session_id:
        print("Erro: Não há sessão ativa encontrada.")
        return

    # URL da API para suspender o sujeito
    api_url = "http://127.0.0.1:5000/subjects/suspend"
    headers = {"Content-Type": "application/json"}
    
    # Dados a enviar
    data = {
        "session_id": session_id,
        "username": username,
        "session_file": session_file
    }

    # Enviar a requisição POST
    try:
        response = requests.post(api_url, json=data, headers=headers)
        if response.status_code == 200:
            print(f"Sujeito '{username}' suspenso com sucesso.")
        else:
            print(f"Erro ao suspender sujeito: {response.json().get('error')}")
    except requests.exceptions.RequestException as e:
        print(f"Erro ao conectar à API: {e}")


def rep_activate_subject(session_file, username):
    """
    Ativa um sujeito usando o arquivo de sessões especificado.
    """
    # Verificar se os parâmetros obrigatórios estão presentes
    if not session_file or not username:
        print("Erro: Todos os parâmetros (session_file, username) são obrigatórios.")
        print("Usage: rep_activate_subject <session_file> <username>")
        return

    # Carregar o conteúdo do arquivo de sessão
    try:
        with open(session_file, 'r') as f:
            sessions = json.load(f)
    except FileNotFoundError:
        print(f"Error: O arquivo {session_file} não foi encontrado.")
        return
    except json.JSONDecodeError:
        print(f"Error: O arquivo {session_file} está corrompido.")
        return

    # Verificar se existe alguma sessão ativa
    session_id = None
    for session in sessions.values():
        if session['status'] == 'active':
            session_id = session['session_id']
            break

    if not session_id:
        print("Erro: Não há sessão ativa encontrada.")
        return

    # URL da API para ativar o sujeito
    api_url = "http://127.0.0.1:5000/subjects/activate"
    headers = {"Content-Type": "application/json"}
    
    # Dados a enviar
    data = {
        "session_id": session_id,
        "username": username,
        "session_file": session_file
    }

    # Enviar a requisição POST
    try:
        response = requests.post(api_url, json=data, headers=headers)
        if response.status_code == 200:
            print(f"Sujeito '{username}' ativado com sucesso.")
        else:
            print(f"Erro ao ativar sujeito: {response.json().get('error')}")
    except requests.exceptions.RequestException as e:
        print(f"Erro ao conectar à API: {e}")


def rep_add_doc(session_file, document_handle, file_path):
    """Main function to upload document."""
    try:
        # Verifica se o arquivo existe
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        payload = {
            'session_file': session_file,
            'document_handle': document_handle,
            'file_path': file_path
        }

        aes_key = generate_aes_key()
        payload['aes_key'] = aes_key.hex()
        payload_encrypted = encrypt_all_data(json.dumps(payload), aes_key)
   
        data_to_send = {
        "encrypted_data": payload_encrypted,  # Dados criptografados
        "aes_key": b64encode(aes_key).decode('utf-8')  # Chave AES em base64
        }

        # Enviar a requisição para o servidor
        response = requests.post('http://127.0.0.1:5000/document/create', json=data_to_send)

        # Verifique se a resposta foi bem-sucedida
        if response.status_code == 200:
            print(f"Document uploaded successfully: {response.json()}")
        else:
            print(f"Error uploading document: {response.status_code} - {response.text}")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        raise

def rep_get_doc_metadata(session_file, document_name):
    """Send user arguments to the server to fetch metadata."""
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
            "aes_key": b64encode(aes_key).decode('utf-8')
            }
        
        response = requests.post('http://127.0.0.1:5000/document/metadata', json=data_to_send)

        if not response.ok:
            raise Exception(f"Server returned error: {response.status_code} - {response.text}")
        
        # print the metadata
        print(response.json())

        # Parse and display the response
        return response.json()
        
    except Exception as e:
        raise Exception(f"Error fetching document metadata: {str(e)}")

def rep_list_docs(session_file, creator=None, date_filter=None, date_value=None):
    """Sends a request to the server to list documents with optional filters."""
    # Prepare the request payload
    try:
      payload = {
          "session_file": session_file
      }
      
      if creator:
          payload["creator"] = creator
      if date_filter and date_value:
          payload["date_filter"] = date_filter
          payload["date_value"] = date_value
      
      # Send the POST request to the server
      response = requests.post('http://127.0.0.1:5000/document/list', json=payload)
      if response.status_code == 200:
              # Parse and display the response
            response_data = response.json()
            document_handle = response_data.get('document_handles')
            organization = response_data.get('organization')
            print(f"Documents for organization '{organization}':{document_handle}")
      else:
              print(f"Error uploading document: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        raise


def rep_delete_doc(session_file, document_name):
    """Sends a request to the server to delete a document."""
    # Prepare the request payload
    payload = {
        "session_file": session_file,
        "document_name": document_name
    }
    aes_key = generate_aes_key()
    payload["aes_key"] = aes_key.hex()
    encrypted_payload = encrypt_all_data(json.dumps(payload), aes_key)
    data_to_send = {
        "encrypted_payload": encrypted_payload,
        "aes_key": b64encode(aes_key).decode('utf-8')
        }
    # Send the POST request to the server
    try:
        response = requests.post('http://127.0.0.1:5000/document/delete', json=data_to_send)
        response.raise_for_status()  # Raise an error for bad HTTP status codes
        print(f"Document '{document_name}' deleted successfully.")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error sending request: {e}")
        return None    

def rep_get_doc_file(session_file, document_name, output_file=None):
    """
    Envia dados ao servidor para obter e descriptografar um arquivo.
    O servidor faz toda a verificação de permissões e descriptografia.
    """
    try:
        # Preparar os dados para enviar ao servidor
        payload = {
            "session_file": session_file,
            "document_name": document_name
        }
        
        if output_file:
            payload["output_file"] = output_file  # Incluir nome do arquivo de saída, se fornecido
        
        aes_key = generate_aes_key()
        payload["aes_key"] = aes_key.hex()
        encrypted_payload = encrypt_all_data(json.dumps(payload), aes_key)

        data_to_send = {
            "encrypted_payload": encrypted_payload,
            "aes_key": b64encode(aes_key).decode('utf-8')
        }
        
        # Fazer a requisição ao servidor
        response = requests.post("http://127.0.0.1:5000/document/get", json=data_to_send)

        if response.status_code == 200:
            # Caso sucesso, processar a resposta
            if output_file:
                # Salvar o conteúdo retornado no arquivo
                with open(output_file, "wb") as f:
                    f.write(response.content)
                print(f"File successfully saved to {output_file}")
            else:
                # Imprimir o conteúdo no stdout
                print(response.content.decode('utf-8'))
        else:
            # Exibir erro retornado pelo servidor
            print(f"Error: {response.status_code} - {response.json().get('error', 'Unknown error')}")

    except Exception as e:
        print(f"Error in rep_get_doc_file: {str(e)}")

def rep_decrypt_file(encrypted_file, encryption_metadata):
    try:
        # Load the encryption metadata (both public and restricted parts)
        with open(encryption_metadata, 'r') as meta_file:
            metadata = json.load(meta_file)

        # Extract public metadata
        document_handle = metadata['document_handle']
        name = metadata['name']
        create_date = metadata['create_date']
        creator = metadata['creator']
        file_handle = metadata['file_handle']
        acl = metadata['acl']
        deleter = metadata.get('deleter', None)

        # Extract restricted (non-public) metadata
        alg = metadata['alg']
        key = bytes.fromhex(metadata['key'])  # The encryption key, assumed to be in hex

        # Decrypt the file using the specified algorithm
        if alg == "AES":
            iv = bytes.fromhex(metadata['iv'])  # IV should also be part of the metadata
            with open(encrypted_file, 'rb') as enc_file:
                ciphertext = enc_file.read()

            # Set up the AES decryption (e.g., CBC mode)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            # Decrypt the ciphertext
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Unpad the decrypted plaintext (AES CBC usually requires padding)
            padder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = padder.update(padded_plaintext) + padder.finalize()

            # Optional integrity check (e.g., hash verification)
            if 'hash' in metadata:
                expected_hash = metadata['hash']
                file_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
                file_hash.update(plaintext)
                generated_hash = file_hash.finalize().hex()

                if generated_hash != expected_hash:
                    raise ValueError("Integrity check failed: File has been tampered with.")

            # Print the decrypted content
            sys.stdout.buffer.write(plaintext)
            print("\nFile decrypted successfully.")

        else:
            raise ValueError(f"Unsupported algorithm: {alg}")

    except Exception as e:
        print(f"Error decrypting file: {e}")
        sys.exit(1)

def rep_get_file(file_handle, output_file=None):

    try:
        payload = {
        "file_handle": file_handle
        }
        aes_key = generate_aes_key()
        payload["aes_key"] = aes_key.hex()
        encrypted_payload = encrypt_all_data(json.dumps(payload), aes_key)
        data_to_send = {
        "encrypted_payload": encrypted_payload,
        "aes_key": b64encode(aes_key).decode('utf-8')
        }
        # Request the file from the server
        response = requests.post('http://127.0.0.1:5000/document/download', json=data_to_send)
        response.raise_for_status()  # Raise an exception for HTTP errors

        if output_file:
            # Save the file to the specified path

            with open(output_file, 'wb') as f:
                f.write(response.content)
            print(f"File {file_handle} downloaded successfully to {output_file}.")
        else:
            # Write file content to stdout
            output_path = "../client/" + file_handle + ".encrypted"
            with open(output_path, 'wb') as f:
                f.write(response.content)
            print(f"File {file_handle} downloaded successfully to {output_path}.")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file: {str(e)}")



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
    
    """ Do something """
    logger.debug("Arguments: " + str(args))


    print("Program name:", args["command"])


    if args["command"]  == "rep_create_org":
        rep_create_org(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])

    elif args["command"] == "rep_list_orgs":
        rep_list_orgs()

    elif args["command"] == "rep_create_session":
        rep_create_session(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])

    elif args["command"] == "rep_add_subject":
        rep_add_subject(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])

    elif args["command"] == "rep_list_subjects":
        if not args["arg0"]:
            print("Erro: Caminho para o arquivo de sessões não fornecido.")
            return
        session_file = args["arg0"]
        username = args["arg1"] if args["arg1"] else None
        rep_list_subjects(session_file, filter_username=username)

        
    elif args["command"] == "rep_suspend_subject":
        rep_suspend_subject(args["arg0"], args["arg1"])

    elif args["command"] == "rep_activate_subject":
        rep_activate_subject(args["arg0"], args["arg1"])

    elif args["command"] == "rep_add_doc":
        rep_add_doc(args["arg0"], args["arg1"], args["arg2"])

    elif args["command"] == "rep_get_doc_metadata":
        rep_get_doc_metadata(args["arg0"], args["arg1"])

    elif args["command"] == "rep_subject_credentials":
        # Verificar se o arg1 termina com '.pem'
        if args["arg1"].endswith(".pem"):
            rep_subject_credentials(args["arg0"], args["arg1"])
        else:
            print("Erro: o argumento arg1 deve ter a extensão .pem")


    elif args["command"] == "rep_list_docs":
        session_file = args["arg0"]
        username = args["arg1"] if args["arg1"] else None
        date_filter = args["arg2"] if args["arg2"] else None
        data_value = args["arg3"] if args["arg3"] else None
        rep_list_docs(session_file, creator=username, date_filter=date_filter, date_value=data_value)

    elif args["command"] == "rep_delete_doc":
        rep_delete_doc(args["arg0"], args["arg1"])

    elif args["command"] == "rep_get_file":
        file_handle = args["arg0"]
        file = args["arg1"] if args["arg1"] else None
        rep_get_file(file_handle, file)

    elif args["command"] == "rep_get_doc_file":
        session_file = args["arg0"]
        document_name = args["arg1"]
        output_file = args["arg2"]
        if not session_file or not document_name:
            print("Error: session_file and document_name are required.")
            return

        rep_get_doc_file(session_file, document_name, output_file)

    elif args["command"] == "decrypt_file":
        rep_decrypt_file(args["arg0"], args["arg1"])

    else:
        logger.error("Invalid command")


if __name__ == "__main__":
    main()