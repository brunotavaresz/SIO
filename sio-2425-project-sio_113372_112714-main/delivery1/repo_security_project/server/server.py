from flask import Flask, request, jsonify, send_file
import json
import os
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from base64 import b64decode
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

ORG_FILE = '../server/organizations.json'
SESSION_FILE = '../server/sessions.json'
SERVER_DIR = '../server/files'
CLIENT_DIR = '../client'
DOCUMENTS_DIR = '../server/docs'
SUBJECT_FILE = '../server/subjects.json'


def load_json(file_path):
    """ Carrega e retorna o conteúdo de um arquivo JSON """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}
    
def save_json(file_path, data):
    """ Salva os dados no arquivo JSON """
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def validate_password(plain_password, private_key_pem, salt):
    """
    Validate the password by attempting to decrypt the private key.
    """
    try:
        # Attempt to load the private key with the provided password
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=plain_password.encode(),
            backend=default_backend()
        )
        return True
    except Exception as e:
        print(f"Password validation failed: {e}")
        return False
    
# Função para descriptografar os dados com AES
def decrypt_data(encrypted_data, aes_key):
    encrypted_data = b64decode(encrypted_data)  # Decodificar os dados em base64
    iv = encrypted_data[:16]  # vetor de inicialização (IV)
    ciphertext = encrypted_data[16:]  # text cifrado
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode('utf-8')

# Função para criar organização
@app.route('/organization/create', methods=['POST'])
def create_organization():
    try:
        data = request.json
        encrypted_data = data['encrypted_data']  # Dados criptografados
        aes_key = b64decode(data['aes_key'])  # Chave AES recebida em base64

        # Descriptografar os dados
        decrypted_data = decrypt_data(encrypted_data, aes_key)

        # Converter os dados descriptografados de volta para um dicionário
        data_dict = json.loads(decrypted_data)

        # Extrair os dados da organização
        organization_name = data_dict['organization']
        username = data_dict['username']
        full_name = data_dict['full_name']
        email = data_dict['email']
        public_key = data_dict['public_key']  # Chave pública que foi criptografada

        # Verificar se a organização já existe
        organizations = load_json(ORG_FILE)
        if organization_name in organizations:
            return jsonify({'error': 'Organization already exists'}), 400

        # Criar o subject inicial (admin)
        subject = {
            'username': username,
            'full_name': full_name,
            'email': email,
            'public_key': public_key,
            'status': 'active',
            'permissions': {
                'ROLE_ACL': True,
                'SUBJECT_NEW': True,
                'SUBJECT_UP': True,
                'SUBJECT_DOWN': True,
                'DOC_NEW': True,
                'DOC_READ': True,
                'DOC_DELETE': True
            }
        }

        # Definir a organização e adicionar o subject inicial
        organizations[organization_name] = {
            'name': organization_name,
            'subjects': [subject],
            'acl': {
                'manager': username,  # O administrador inicial é o gerente
            }
        }

        # Salvar a organização no arquivo JSON
        save_json(ORG_FILE, organizations)

        return jsonify({'message': 'Organization created successfully', 'organization': organization_name}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    
def manual_base64_decode(data):
    """
    Helper function to handle base64 decoding with proper padding.
    """
    data = data.strip()
    padding = b'=' * ((4 - len(data) % 4) % 4)
    return base64.b64decode(data + padding)


def read_pem_file(file_path):
    """
    Read the PEM file and extract salt and keys.
    """
    try:
        with open(file_path, 'r') as pem_file:
            content = pem_file.read()

        # Extract the parts using string parsing
        salt_line = [line for line in content.split('\n') if line.strip()][1]
        salt = base64.b64decode(salt_line)

        # Extract private key PEM block
        private_key_lines = []
        in_private_key = False
        for line in content.split('\n'):
            if "-----BEGIN ENCRYPTED PRIVATE KEY-----" in line:
                in_private_key = True
                private_key_lines.append(line)
            elif "-----END ENCRYPTED PRIVATE KEY-----" in line:
                private_key_lines.append(line)
                in_private_key = False
            elif in_private_key:
                private_key_lines.append(line)

        private_key = '\n'.join(private_key_lines)
        
        # Extract public key PEM block
        public_key_lines = []
        in_public_key = False
        for line in content.split('\n'):
            if "-----BEGIN PUBLIC KEY-----" in line:
                in_public_key = True
                public_key_lines.append(line)
            elif "-----END PUBLIC KEY-----" in line:
                public_key_lines.append(line)
                in_public_key = False
            elif in_public_key:
                public_key_lines.append(line)

        public_key = '\n'.join(public_key_lines)

        return salt, private_key.encode(), public_key.encode()

    except Exception as e:
        print(f"Error reading PEM file: {str(e)}")
        return None, None, None


@app.route('/session/create', methods=['POST'])
def create_session():
    try:
        data = request.json
        print(f"Received data: {data}")

        organization = data['organization']
        encrypted_username = data['username']
        encrypted_password = data['password']
        credentials_file = data['credentials_file']
        session_file = data['session_file']
        aes_key = b64decode(data['aes_key'])  # Chave AES recebida em base64

        # Descriptografar o username e o password
        username = decrypt_data(encrypted_username, aes_key)
        password = decrypt_data(encrypted_password, aes_key)

        # Carregar dados existentes de organizações e sessões
        organizations = load_json(ORG_FILE)
        sessions = load_json(session_file)

        # Verificar se a organização existe
        if organization not in organizations:
            return jsonify({'error': 'Organization does not exist'}), 400

        # Verificar se o username existe na organização
        subject_found = False
        for subject in organizations[organization]['subjects']:
            if subject['username'] == username:
                subject_found = True
                break

        if not subject_found:
            return jsonify({'error': 'Subject not found in the organization'}), 400

        # Ler o arquivo de credenciais para obter os dados necessários
        print(f"Reading credentials from {credentials_file}")
        salt, private_key_pem, public_key_pem = read_pem_file(credentials_file)
        if not all([salt, private_key_pem, public_key_pem]):
            return jsonify({'error': 'Failed to read credentials file'}), 400

        # Validar a senha
        if not validate_password(password, private_key_pem, salt):
            return jsonify({'error': 'Invalid password'}), 400

        # Gerar as chaves da sessão
        confidentiality_key = os.urandom(32).hex()  # 256-bit key for AES
        integrity_key = os.urandom(32).hex()        # 256-bit key for HMAC

        # Gerar um novo session_id
        session_id = os.urandom(16).hex()
        login_time = datetime.now().isoformat()

        # Verificar se já existe uma sessão ativa com esse session_id
        if session_id in sessions:
            return jsonify({'error': 'Session already exists with the same session ID'}), 400

        # Criar um objeto de sessão com a organização específica
        session = {
            'session_id': session_id,
            'username': username,
            'organization': organization,  # Armazena apenas a organização associada
            'login_time': login_time,
            'status': 'active',
            'public_key': public_key_pem.decode('utf-8'),
            'session_keys': {
                'confidentiality_key': confidentiality_key,
                'integrity_key': integrity_key
            }
        }

        # Adicionar a nova sessão ao dicionário de sessões
        sessions[session_id] = session

        # Salvar os dados atualizados de sessões no arquivo
        save_json(session_file, sessions)

        # Resposta contendo os dados relevantes da sessão
        response_data = {
            'session_id': session_id,
            'session_keys': {
                'confidentiality_key': confidentiality_key,
                'integrity_key': integrity_key
            },
            'public_key': public_key_pem.decode('utf-8'),
            'login_time': login_time,
            'status': 'active',
            'username': username,  # Inclui o username na resposta
            'organization': organization  # Inclui apenas a organização associada à sessão
        }

        print(f"Session created successfully with ID: {session_id}")
        return jsonify(response_data), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

    
@app.route('/subjects/list', methods=['POST'])
def list_subjects():
    try:
        data = request.json
        session_file = data.get('session_file')  # Recebe o caminho do arquivo de sessão
        session_id = data.get('session_id')
        filter_username = data.get('filter_username')

        if not session_file:
            return jsonify({'error': 'session_file is required'}), 400

        # Carregar as sessões ativas do arquivo especificado
        sessions = load_json(session_file)
        
        # Validar sessão
        if session_id not in sessions:
            return jsonify({'error': 'Invalid session'}), 401
            
        session = sessions[session_id]

        # Carregar os dados das organizações
        organizations = load_json(ORG_FILE)
        organization = session['organization']

        if organization not in organizations:
            return jsonify({'error': 'Organization not found'}), 404

        # Obter a lista de subjects com seus status
        subjects = organizations[organization]['subjects']
        
        # Filtrar pelo username, se especificado
        if filter_username:
            subjects = [subject for subject in subjects if subject['username'] == filter_username]
            if not subjects:
                return jsonify({'error': 'Subject not found'}), 404

        # Retornar os subjects com seus status existentes
        response_data = {
            'subjects': subjects
        }

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    
@app.route('/subjects/add', methods=['POST'])
def add_subject():
    try:
        data = request.json
        session_file = data.get('session_file')
        session_id = data.get('session_id')
        encrypted_username = data.get('username')
        encrypted_name = data.get('name')
        encrypted_email = data.get('email')
        public_key = data.get('public_key')
        organization = data.get('organization')
        aes_key = b64decode(data.get('aes_key'))  # Chave AES recebida em base64

        # Descriptografar os dados
        username = decrypt_data(encrypted_username, aes_key)
        name = decrypt_data(encrypted_name, aes_key)
        email = decrypt_data(encrypted_email, aes_key)

        # Carregar os dados de sessão e organização
        sessions = load_json(session_file)
        organizations = load_json(ORG_FILE)

        # Validar sessão
        if session_id not in sessions:
            return jsonify({'error': 'Invalid session'}), 401
        session = sessions[session_id]
        if session['status'] != 'active':
            return jsonify({'error': 'Session is not active'}), 401

        # Validar organização
        if organization not in organizations:
            return jsonify({'error': 'Organization not found'}), 404

        # Verificar se o user é o manager da organização
        requester_username = session['username']
        org_data = organizations[organization]
        if org_data['acl']['manager'] != requester_username:
            return jsonify({'error': 'Permission denied: Only manager can add subjects'}), 403

        # Verificar se o user já existe na organização
        for subject in org_data['subjects']:
            if subject['username'] == username:
                return jsonify({'error': f"Subject with username '{username}' already exists in the organization."}), 409

        # Adicionar o novo sujeito
        new_subject = {
            'username': username,
            'name': name,
            'email': email,
            'public_key': public_key,
            'status': 'active'  # O subject começa com status 'active'
        }
        org_data['subjects'].append(new_subject)

        # Salvar os dados atualizados da organização
        save_json(ORG_FILE, organizations)

        return jsonify({'message': f"Subject '{username}' added successfully."}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/subjects/suspend', methods=['POST'])
def suspend_subject():
    try:
        data = request.json
        session_id = data.get('session_id')
        username = data.get('username')
        session_file = data.get('session_file')

        # Verificar se o caminho do arquivo de sessão foi fornecido
        if not session_file:
            return jsonify({'error': 'session_file path is required'}), 400

        # Carregar os dados de sessão e organização
        sessions = load_json(session_file)
        organizations = load_json(ORG_FILE)

        # Validar sessão
        if session_id not in sessions:
            return jsonify({'error': 'Invalid session'}), 401
        session = sessions[session_id]
        if session['status'] != 'active':
            return jsonify({'error': 'Session is not active'}), 401

        # Validar organização
        organization = session['organization']
        if organization not in organizations:
            return jsonify({'error': 'Organization not found'}), 404

        # Verificar se o usuário é o manager da organização
        requester_username = session['username']
        org_data = organizations[organization]
        if org_data['acl']['manager'] != requester_username:
            return jsonify({'error': 'Permission denied: Only manager can suspend subjects'}), 403

        # Encontrar o sujeito e alterar seu status
        for subject in org_data['subjects']:
            if subject['username'] == username:
                subject['status'] = 'suspended'
                save_json(ORG_FILE, organizations)
                return jsonify({'message': f"Subject '{username}' suspended successfully."}), 200

        return jsonify({'error': 'Subject not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/subjects/activate', methods=['POST'])
def activate_subject():
    try:
        data = request.json
        session_id = data.get('session_id')
        username = data.get('username')
        session_file = data.get('session_file')

        # Verificar se o caminho do arquivo de sessão foi fornecido
        if not session_file:
            return jsonify({'error': 'session_file path is required'}), 400

        # Carregar os dados de sessão e organização
        sessions = load_json(session_file)
        organizations = load_json(ORG_FILE)

        # Validar sessão
        if session_id not in sessions:
            return jsonify({'error': 'Invalid session'}), 401
        session = sessions[session_id]
        if session['status'] != 'active':
            return jsonify({'error': 'Session is not active'}), 401

        # Validar organização
        organization = session['organization']
        if organization not in organizations:
            return jsonify({'error': 'Organization not found'}), 404

        # Verificar se o usuário é o manager da organização
        requester_username = session['username']
        org_data = organizations[organization]
        if org_data['acl']['manager'] != requester_username:
            return jsonify({'error': 'Permission denied: Only manager can activate subjects'}), 403

        # Encontrar o sujeito e alterar seu status
        for subject in org_data['subjects']:
            if subject['username'] == username:
                subject['status'] = 'active'
                save_json(ORG_FILE, organizations)
                return jsonify({'message': f"Subject '{username}' activated successfully."}), 200

        return jsonify({'error': 'Subject not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/organization/list', methods=['GET'])
def list_organizations():
    """
    Retorna a lista de organizações registradas.
    """
    try:
        organizations = load_json(ORG_FILE)
        org_list = list(organizations.keys())  # so nomes de organizações
        return jsonify({'organizations': org_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def load_session(session_file):
    """Carregar e validar o arquivo de sessão."""
    try:
        sessions = load_json(session_file)
        active_session = None
        for session_id, session_data in sessions.items():
            if session_data.get('status') == 'active':
                active_session = session_data
                print(f"Active session found: {active_session}")
                break
        
        if not active_session:
            raise ValueError("No active session found")
        
        if 'session_keys' not in active_session:
            raise ValueError("Session data missing 'session_keys'")
        
        return active_session
    except Exception as e:
        raise Exception(f"Failed to load session: {str(e)}")

def check_user_in_org(username, organization):
    """Verifica se o username está na organização."""
    organizations = load_json(ORG_FILE)
    if organization not in organizations:
        raise ValueError("Organization does not exist")
    
    for subject in organizations[organization]['subjects']:
        if subject['username'] == username:
            return True
    return False

def encrypt_file(file_path, confidentiality_key):
    """Criptografa o arquivo usando AES-CBC com padding."""
    with open(file_path, 'rb') as f:
        file_content = f.read()
    
    iv = os.urandom(16)  # 128-bit IV para AES-CBC
    cipher = AES.new(confidentiality_key, AES.MODE_CBC, iv)

    # Aplicar padding para garantir múltiplo do tamanho do bloco
    padded_content = pad(file_content, AES.block_size)
    encrypted_content = cipher.encrypt(padded_content)


    hmac = HMAC(confidentiality_key, hashes.SHA256())
    hmac.update(encrypted_content)
    file_hmac = hmac.finalize()

    return encrypted_content, iv, file_hmac

@app.route('/document/create', methods=['POST'])
def rep_add_doc():
    try:
        data = request.json
        encrypted_data = data['encrypted_data']  # Dados criptografados
        aes_key = b64decode(data['aes_key'])  # Chave AES recebida em base64

        # Descriptografar os dados
        decrypted_data = decrypt_data(encrypted_data, aes_key)

        # Converter os dados descriptografados de volta para um dicionário
        data_dict = json.loads(decrypted_data)

        session_file = data_dict['session_file']
        document_handle = data_dict['document_handle']
        file_path = data_dict['file_path']

        print(f"Received data: {data_dict}")

        # Carregar a sessão e validar
        session_data = load_session(session_file)
        username = session_data['username']
        organization = session_data['organization']

        # Verificar se o usuário pertence à organização
        if not check_user_in_org(username, organization):
            return jsonify({'error': 'User does not belong to the organization'}), 403

        # Obter e converter a chave de confidencialidade
        hex_key = session_data['session_keys']['confidentiality_key']
        confidentiality_key = bytes.fromhex(hex_key)

        # Criptografar o arquivo
        encrypted_content, iv, file_hmac = encrypt_file(file_path, confidentiality_key)

        file_handle = os.urandom(16).hex()
        create_date = datetime.now().isoformat()
        file_name = os.path.basename(file_path)

        # Save encrypted file
        encrypted_file_path = os.path.join(SERVER_DIR, f"{file_handle}.encrypted")
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_content)

        # Preparar os metadados
        public_metadata = {
            'document_handle': document_handle,
            'name': file_name,
            'create_date': create_date,
            'creator': username,
            'file_handle': file_handle,
            'acl': [],
            'deleter': None
        }

        restricted_metadata = {
            'alg': 'AES-GCM-SHA256',
            'key': base64.b64encode(confidentiality_key).decode('utf-8')
        }

        # Salvar metadados públicos
        os.makedirs(CLIENT_DIR, exist_ok=True)
        

        # Salvar metadados públicos + privados
        os.makedirs(SERVER_DIR, exist_ok=True)
        metadata_with_private = {
            'public_metadata': public_metadata,
            'restricted_metadata': restricted_metadata,
            'iv': base64.b64encode(iv).decode('utf-8'),
            'hmac': base64.b64encode(file_hmac).decode('utf-8')
        }

        metadata_path = os.path.join(SERVER_DIR, f"{document_handle}_private.meta")
        with open(metadata_path, 'w') as f:
            json.dump(metadata_with_private, f, indent=4)

        # Atualizar o ORG_FILE com o document_handle
        update_org_file(organization, document_handle)

        return jsonify({
            'message': 'Document added successfully',
            'document_handle': document_handle
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def update_org_file(organization, document_handle):
    """Atualiza o ORG_FILE com o novo documento associado à organização."""
    try:
        # Carregar o ORG_FILE
        if os.path.exists(ORG_FILE):
            with open(ORG_FILE, 'r') as f:
                org_data = json.load(f)
        else:
            org_data = {}

        # Garantir que a organização existe no ORG_FILE
        if organization not in org_data:
            org_data[organization] = {'docs': []}

        # Adicionar o document_handle ao array docs da organização, se ainda não estiver lá
        if 'docs' not in org_data[organization]:
            org_data[organization]['docs'] = []

        if document_handle not in org_data[organization]['docs']:
            org_data[organization]['docs'].append(document_handle)

        # Salvar as alterações de volta no ORG_FILE
        with open(ORG_FILE, 'w') as f:
            json.dump(org_data, f, indent=4)
    except Exception as e:
        raise Exception(f"Erro ao atualizar ORG_FILE: {str(e)}")
    
def load_org_file():
    """Load the organization file."""
    try:
        if os.path.exists(ORG_FILE):
            with open(ORG_FILE, 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        raise ValueError(f"Failed to load organization file: {str(e)}")

@app.route('/document/metadata', methods=['POST'])
def get_document_metadata():
    """API to fetch public metadata for a document."""
    try:
        data = request.json
        encrypted_data = data['encrypted_data']  # Dados criptografados
        aes_key = b64decode(data['aes_key'])  # Chave AES recebida em base64

        # Descriptografar os dados
        decrypted_data = decrypt_data(encrypted_data, aes_key)
        # Converter os dados descriptografados de volta para um dicionário
        data_dict = json.loads(decrypted_data)

        session_file = data_dict['session_file']
        document_name = data_dict['document_name']

        if not session_file or not document_name:
            return jsonify({'error': 'Missing session_file or document_name'}), 400

        # Load the session
        session_data = load_session(session_file)
        username = session_data['username']
        organization = session_data['organization']

        # Load the organization file
        org_data = load_org_file()

        if organization not in org_data:
            return jsonify({'error': f"Organization '{organization}' not found"}), 404

        # Find the user in the organization's subjects and check DOC_READ permission
        user_permissions = None
        for subject in org_data[organization]['subjects']:
            if subject['username'] == username:
                user_permissions = subject.get('permissions', {})
                break

        if not user_permissions:
            return jsonify({'error': f"User '{username}' not found in organization '{organization}'"}), 404

        if not user_permissions.get('DOC_READ', False):
            return jsonify({'error': 'Permission denied: DOC_READ required'}), 403

        # Check if the document exists in the organization
        if 'docs' not in org_data[organization]:
            return jsonify({'error': f"No documents found for organization '{organization}'"}), 404

         # Check if the document exists in the organization
        if 'docs' not in org_data[organization]:
            return jsonify({'error': f"No documents found for organization '{organization}'"}), 404

        # Logging for debugging purposes
        print(f"Docs found for organization '{organization}': {org_data[organization]['docs']}")

        # Find the document by name
        doc_handle = None
        for handle in org_data[organization]['docs']:
            private_metadata_path = os.path.join(SERVER_DIR, f"{handle}_private.meta")
            if not os.path.exists(private_metadata_path):
                continue

            with open(private_metadata_path, 'r') as f:
                metadata = json.load(f)
                
                if metadata['public_metadata']['document_handle'] == document_name:
                    doc_handle = handle
                    break

        if not doc_handle:
            return jsonify({'error': f"Document '{document_name}' not found in organization '{organization}'"}), 404

        # Load the private metadata and return only the public metadata
        private_metadata_path = os.path.join(SERVER_DIR, f"{doc_handle}_private.meta")
        if not os.path.exists(private_metadata_path):
            return jsonify({'error': f"Metadata file for document '{document_name}' not found"}), 404

        with open(private_metadata_path, 'r') as f:
            metadata = json.load(f)

        # Extract only the public_metadata section
        public_metadata = metadata.get('public_metadata', {})
        #save a file with the public metadata in client_dir
        with open(os.path.join(CLIENT_DIR, '{doc_handle}public_metadata.json'), 'w') as f:
            json.dump(public_metadata, f)

        return jsonify(public_metadata), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/document/list', methods=['POST'])
def list_documents():
    """API to list document handles of an organization, with optional filters."""
    try:
        data = request.json
        session_file = data.get('session_file')
        creator = data.get('creator')
        date_value = data.get('date_value')
        date_filter = data.get('date_filter')

        if not session_file:
            return jsonify({'error': 'Missing session_file'}), 400

        # Load the session
        session_data = load_session(session_file)
        organization = session_data['organization']

        # Load the organization file
        org_data = load_org_file()

        if organization not in org_data:
            return jsonify({'error': f"Organization '{organization}' not found"}), 404

        # Retrieve all documents for the organization
        if 'docs' not in org_data[organization]:
            return jsonify({'error': f"No documents found for organization '{organization}'"}), 404

        documents = []
        for doc_handle in org_data[organization]['docs']:
            private_metadata_path = os.path.join(SERVER_DIR, f"{doc_handle}_private.meta")
            if not os.path.exists(private_metadata_path):
                continue

            with open(private_metadata_path, 'r') as f:
                metadata = json.load(f)
                documents.append(metadata['public_metadata'])

        # Apply filters
        if creator:
            documents = [doc for doc in documents if doc.get('creator') == creator]

        if date_filter and date_value:
            try:
                date_value = datetime.strptime(date_value, "%d-%m-%Y")
            except ValueError:
                return jsonify({'error': 'Invalid date format. Use DD-MM-YYYY'}), 400

            if date_filter == "nt":  # Newer than
                documents = [doc for doc in documents if datetime.fromisoformat(doc['create_date']) > date_value]
            elif date_filter == "ot":  # Older than
                documents = [doc for doc in documents if datetime.fromisoformat(doc['create_date']) < date_value]
            elif date_filter == "et":  # Equal to
                documents = [doc for doc in documents if datetime.fromisoformat(doc['create_date']).date() == date_value.date()]
            else:
                return jsonify({'error': 'Invalid date filter. Use "nt", "ot", or "et"'}), 400

        # Extract document handles
        document_handles = [doc['document_handle'] for doc in documents]

        # Return the filtered list of document handles
        return jsonify({
            'document_handles': document_handles,
            'organization': organization
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/document/delete', methods=['POST'])
def delete_document():
    """
    API endpoint to clear the file_handle of a document.
    Requires DOC_DELETE permission.
    """
    try:
        # Parse request data
        data = request.json
        aes_key = b64decode(data['aes_key'])
        encrypted_data = data['encrypted_payload']
        decrypted_data = decrypt_data(encrypted_data, aes_key)
        data_dict = json.loads(decrypted_data)
        """data = request.json
        encrypted_data = data['encrypted_data']  # Dados criptografados
        aes_key = b64decode(data['aes_key'])  # Chave AES recebida em base64

        # Descriptografar os dados
        decrypted_data = decrypt_data(encrypted_data, aes_key)
        # Converter os dados descriptografados de volta para um dicionário
        data_dict = json.loads(decrypted_data)"""

        session_file = data_dict['session_file']
        document_name = data_dict['document_name']
        
        if not session_file or not document_name:
            return jsonify({'error': 'Missing session_file or document_name'}), 400

        # Load the session file and extract session data
        session_data = load_session(session_file)
        username = session_data['username']
        organization = session_data['organization']

        # Verify DOC_DELETE permission
        org_data = load_org_file()
        org_info = org_data.get(organization)

        if not org_info:
            return jsonify({'error': f"Organization '{organization}' not found"}), 404

        user_permissions = None
        for subject in org_info.get('subjects', []):
            if subject['username'] == username:
                user_permissions = subject.get('permissions', {})
                break

        if not user_permissions or not user_permissions.get('DOC_DELETE', False):
            return jsonify({'error': 'Permission denied: DOC_DELETE required'}), 403

        # Find the document in the organization
        doc_handle = None
        for handle in org_info.get('docs', []):
            metadata_path = os.path.join(SERVER_DIR, f"{handle}_private.meta")
            if not os.path.exists(metadata_path):
                continue

            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                if metadata['public_metadata']['document_handle'] == document_name:
                    doc_handle = handle
                    break

        if not doc_handle:
            return jsonify({'error': f"Document '{document_name}' not found in organization '{organization}'"}), 404

        # Clear the file_handle in the document's metadata
        metadata_path = os.path.join(SERVER_DIR, f"{doc_handle}_private.meta")
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)

        file_handle = metadata['public_metadata'].get('file_handle')
        if not file_handle:
            return jsonify({'error': 'No file_handle exists for this document'}), 404

        metadata['public_metadata']['file_handle'] = None
        metadata['public_metadata']['deleter'] = username

        # Save the updated metadata back to file
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=4)

        return jsonify({
            'file_handle': file_handle,
            'message': f"File handle cleared for document '{document_name}'"
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/document/get', methods=['POST'])
def get_document_file():
    """
    Endpoint para validar sessão, permissões e retornar um arquivo descriptografado.
    """
    try:
        
        data = request.json
        encrypted_data = data['encrypted_payload']
        aes_key = b64decode(data['aes_key'])
        decrypted_data = decrypt_data(encrypted_data, aes_key)
        data_dict = json.loads(decrypted_data)
        session_file = data_dict['session_file']
        document_name = data_dict['document_name']

        if not session_file or not document_name:
            return jsonify({"error": "Missing session_file or document_name"}), 400

        # Validar a sessão
        session_data = load_session(session_file)
        username = session_data["username"]
        organization = session_data["organization"]

        # Validar permissões do usuário
        org_data = load_org_file()
        if organization not in org_data:
            return jsonify({"error": f"Organization '{organization}' not found"}), 404

        user_permissions = None
        for subject in org_data[organization]["subjects"]:
            if subject["username"] == username:
                user_permissions = subject.get("permissions", {})
                break

        if not user_permissions or not user_permissions.get("DOC_READ", False):
            return jsonify({"error": "Permission denied: DOC_READ required"}), 403

        # Localizar o documento na organização
        doc_handle = None
        for handle in org_data[organization].get("docs", []):
            metadata_path = os.path.join(SERVER_DIR, f"{handle}_private.meta")
            if not os.path.exists(metadata_path):
                continue

            with open(metadata_path, "r") as f:
                metadata = json.load(f)
                if metadata["public_metadata"]["document_handle"] == document_name:
                    doc_handle = handle
                    break

        if not doc_handle:
            return jsonify({"error": f"Document '{document_name}' not found"}), 404

        # Carregar metadados e descriptografar o arquivo
        metadata_path = os.path.join(SERVER_DIR, f"{doc_handle}_private.meta")
        with open(metadata_path, "r") as f:
            metadata = json.load(f)

        # Obter dados necessários para descriptografia
        file_handle = metadata["public_metadata"].get("file_handle")
        if not file_handle:
            return jsonify({"error": "File handle not found"}), 404

        aes_key = b64decode(metadata["restricted_metadata"]["key"])
       
        iv =  base64.b64decode(metadata["iv"])
        print(len(iv))

        # Localizar o arquivo criptografado
        encrypted_file_path = os.path.join(SERVER_DIR, f"{file_handle}.encrypted")
        if not os.path.exists(encrypted_file_path):
            return jsonify({"error": "Encrypted file not found"}), 404

        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()
    
        # Ensure encrypted data length is a multiple of block size
        if len(encrypted_data) % AES.block_size != 0:
            raise ValueError("Encrypted data length must be a multiple of block size")
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)

        # Retornar o conteúdo descriptografado
        return decrypted_data, 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/document/download', methods=['POST'])
def download_file():
    try:

        data = request.json
        encrypted_data = data['encrypted_payload']
        aes_key = b64decode(data['aes_key'])
        decrypted_data = decrypt_data(encrypted_data, aes_key)
        data_dict = json.loads(decrypted_data)
        file_handle = data_dict['file_handle']


        file_path = os.path.join(SERVER_DIR, f"{file_handle}.encrypted")


        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404


        return send_file(file_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)