from flask import Flask, request, jsonify, send_file
import json
import os
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode, b64encode
from Crypto.Random import get_random_bytes
import json
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from base64 import b64encode

app = Flask(__name__)

ORG_FILE = '../server/organizations.json'
SERVER_DIR = '../server/files'
CLIENT_DIR = '../client'
PRIVATE_KEY_FILE = '../server/rep_private_key.pem'
def generate_aes_key():
    return os.urandom(32)  # 256-bit chave AES
def load_private_key():
    try:
        with open(PRIVATE_KEY_FILE, 'r') as f:
            private_key = RSA.import_key(f.read())
        return private_key
    except Exception as e:
        raise Exception(f"Erro ao carregar chave privada: {str(e)}")

def encrypt_data(data, aes_key):

    cipher = AES.new(aes_key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return b64encode(cipher.iv + encrypted_data).decode('utf-8')

def encrypt_aes_key_with_rsa(aes_key, public_key_pem):

    
    cipher_rsa = PKCS1_OAEP.new(public_key_pem)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return b64encode(encrypted_aes_key).decode('utf-8')


def secure_server_response(data, public_key_pem):

    aes_key = get_random_bytes(32)  


    encrypted_data = encrypt_data(data, aes_key)


    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key_pem)

    return {
        'encrypted_data': encrypted_data,
        'encrypted_aes_key': encrypted_aes_key
    }

def load_json(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}
    
def save_json(file_path, data):

    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def validate_password(plain_password, private_key_pem, salt):

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=plain_password.encode(),
            backend=default_backend()
        )
        return True
    except Exception as e:
        print(f"Failed to validate password: {str(e)}")
        return False
    

def decrypt_data(encrypted_data, aes_key):
    encrypted_data = b64decode(encrypted_data)  
    iv = encrypted_data[:16]  
    ciphertext = encrypted_data[16:] 
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode('utf-8')

def decrypt_aes_key(encrypted_aes_key, private_key):
    try:
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_aes_key = cipher_rsa.decrypt(b64decode(encrypted_aes_key))
        return decrypted_aes_key
    except Exception as e:
        raise Exception(f"Erro ao descriptografar a chave AES: {str(e)}")

@app.route('/organization/create', methods=['POST'])
def create_organization():
    try:
        rep_private_key = load_private_key()
        data = request.json
        encrypted_data = data['encrypted_data']  
        encrypted_aes_key = data['aes_key']

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        decrypted_data = decrypt_data(encrypted_data, aes_key)

        
        data_dict = json.loads(decrypted_data)


        organization_name = data_dict['organization']
        username = data_dict['username']
        full_name = data_dict['full_name']
        email = data_dict['email']
        public_key = data_dict['public_key']

        organizations = load_org_file()

        if organization_name in organizations:
            return jsonify({'error': 'Organization already exists'}), 400


        subject = {
            'username': username,
            'name': full_name,
            'email': email,
            'public_key': public_key,
            'status': 'active',
            'roles' : ['manager'],
            'permissions': []

        }

        organizations[organization_name] = {
            'name': organization_name,
            'subjects': [subject],
            'roles': {
            'manager': [
                'ROLE_ACL',
                'ROLE_DOWN',
                'ROLE_UP',
                'ROLE_NEW',
                'ROLE_MOD',
                'SUBJECT_NEW',
                'SUBJECT_UP',
                'SUBJECT_DOWN',
                'DOC_NEW',
                'DOC_READ',
                'DOC_DELETE',
                'DOC_ACL'
            ]
            },
            'role_status': {
            'manager': 'active'
            },
            'acl': {
            'manager': [username],  
            },
            'docs': [],
            'doc_acl': []
        }


        save_json(ORG_FILE, organizations)

        return jsonify({'message': 'Organization created successfully', 'organization': organization_name}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500




def manual_base64_decode(data):

    data = data.strip()
    padding = b'=' * ((4 - len(data) % 4) % 4)
    return base64.b64decode(data + padding)


def read_pem_file(file_path):

    try:
        with open(file_path, 'r') as pem_file:
            content = pem_file.read()


        salt_line = [line for line in content.split('\n') if line.strip()][1]
        salt = base64.b64decode(salt_line)

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
        received_data = request.json
        encrypted_data = received_data['encrypted_data'] 
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))
        organization = data['organization']
        username = data['username']
        password = data['password']
        credentials_file = data['credentials_file']
        session_file = data['session_file']

        organizations = load_org_file()
        sessions = load_json(session_file)

        if organization not in organizations:
            return jsonify({'error': 'Organization does not exist'}), 400


        subject_found = False
        for subject in organizations[organization]['subjects']:
            if subject['username'] == username:
                subject_found = True
                break

        if not subject_found:
            return jsonify({'error': 'Subject not found in the organization'}), 400

        salt, private_key_pem, public_key_pem = read_pem_file(credentials_file)
        if not all([salt, private_key_pem, public_key_pem]):
            return jsonify({'error': 'Failed to read credentials file'}), 400


        if not validate_password(password, private_key_pem, salt):
            return jsonify({'error': 'Invalid password'}), 400


        confidentiality_key = os.urandom(32).hex()  
        integrity_key = os.urandom(32).hex()        


        session_id = os.urandom(16).hex()
        login_time = datetime.now().isoformat()

        
        if session_id in sessions:
            return jsonify({'error': 'Session already exists with the same session ID'}), 400


        session = {
            'session_id': session_id,
            'username': username,
            'organization': organization,  
            'login_time': login_time,
            'status': 'active',
            'public_key': public_key_pem.decode('utf-8'),
            'session_keys': {
                'confidentiality_key': confidentiality_key,
                'integrity_key': integrity_key
            },
            'active_role' : [],
            'past_roles' : []
        }


        save_json(session_file, session)
        return (f"Session created successfully."), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

    
@app.route('/subjects/list', methods=['POST'])
def list_subjects():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_data'] 
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data.get('session_file')  
        filter_username = data.get('filter_username')

        if not session_file:
            return jsonify({'error': 'session_file is required'}), 400


        sessions = load_session(session_file)
        organizations = load_org_file()
        organization = sessions['organization']

        if organization not in organizations:
            return jsonify({'error': 'Organization not found'}), 404


        subjects = organizations[organization]['subjects']
        if filter_username:
            subjects = [subject for subject in subjects if subject['username'] == filter_username]
            if not subjects:
                return jsonify({'error': 'Subject not found'}), 404
        final_subjects = []
        for subject in subjects:
            final_subjects.append({
                'username': subject['username'],
                'status': subject['status']
            }) 
        print(final_subjects)
            
        public_key = load_public_key(sessions['public_key'])
        encrypted_subjects = encrypt_with_public_key(final_subjects, public_key)

        return jsonify({'encrypted_subjects': encrypted_subjects}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/subjects/add', methods=['POST'])
def add_subject():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_data'] 
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data.get('session_file')
        username = data.get('username')
        name = data.get('name')
        email = data.get('email')
        public_key = data.get('public_key')
        organizations = load_org_file()
        session = load_session(session_file)
        if session['status'] != 'active':
            return jsonify({'error': 'Session is not active'}), 401
        organization = session['organization']
        if organization not in organizations:
            return jsonify({'error': 'Organization not found'}), 404

        requester_username = session['username']
        org_data = organizations[organization]
        for subject in org_data['subjects']:
            if subject['username'] == username:
                return jsonify({'error': f"Subject with username '{username}' already exists in the organization."}), 409
        for subject in org_data['subjects']:
            if subject['username'] == requester_username:
                user_permissions = subject['permissions']
                break
        if 'SUBJECT_NEW' not in user_permissions:
            return jsonify({'error': 'Permission denied'}), 403
        new_subject = {
            'username': username,
            'name': name,
            'email': email,
            'public_key': public_key,
            'status': 'active',
            'roles': [],
            'permissions': []
        }
        org_data['subjects'].append(new_subject)
        save_json(ORG_FILE, organizations)

        return jsonify({'message': f"Subject '{username}' added successfully."}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/subjects/suspend', methods=['POST'])
def suspend_subject():
    try:
        received_data = request.json
        encrypted_data = received_data['data'] 
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data.get('session_file')
        username = data.get('username')
        if not session_file:
            return jsonify({'error': 'session_file path is required'}), 400

        sessions = load_session(session_file)
        organizations = load_org_file()


        org = organizations[sessions['organization']]
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        
        subjects = org['subjects']
        sub_permissions = []
        for subject in subjects:
            if subject['username'] == sessions['username']:
                sub_permissions = subject['permissions']
                break
        if 'SUBJECT_DOWN' not in sub_permissions:
            return jsonify({'error': 'Permission denied'}), 403

        for subject in org['subjects']:
            if subject['username'] == username:
                if subject['status'] == 'suspended':
                    return jsonify({'message': f"Subject '{username}' is already suspended."}), 400
                subject['status'] = 'suspended'
                save_json(ORG_FILE, organizations)
                return jsonify({'message': f"Subject '{username}' suspended successfully."}), 200

        return jsonify({'error': 'Subject not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/subjects/activate', methods=['POST'])
def activate_subject():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_data'] 
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()
        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data.get('session_file')
        username = data.get('username')
        print(username)
        print(session_file)
        if not session_file:
            return jsonify({'error': 'session_file path is required'}), 400

        sessions = load_session(session_file)
        organizations = load_org_file()

        org = organizations[sessions['organization']]
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        subjects = org['subjects']
        sub_permissions = []
        for subject in subjects:
            if subject['username'] == sessions['username']:
                sub_permissions = subject['permissions']
                break
        if 'SUBJECT_UP' not in sub_permissions:
            return jsonify({'error': 'Permission denied'}), 403


        for subject in subjects:
            if subject['username'] == username:
                if subject['status'] == 'active':
                    return jsonify({'message': f"Subject '{username}' is already active."}), 400
                subject['status'] = 'active'
                save_json(ORG_FILE, organizations)
                return jsonify({'message': f"Subject '{username}' activated successfully."}), 200

        return jsonify({'error': 'Subject not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/organization/list', methods=['GET'])
def list_organizations():
    try:
        organizations = load_json(ORG_FILE)
        org_list = list(organizations.keys()) 
        return jsonify({'organizations': org_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def load_session(session_file):
    try:
        
        sessions = load_json(session_file)
        active_session = None
        if sessions['status'] == 'active':
            active_session = sessions
            return active_session
        
        if not active_session:
            raise ValueError("No active session found")
        
        if 'session_keys' not in active_session:
            raise ValueError("Session data missing 'session_keys'")
        
        return active_session
    except Exception as e:
        raise Exception(f"Failed to load session: {str(e)}")

def check_user_in_org(username, organization):
    organizations = load_org_file()
    if organization not in organizations:
        raise ValueError("Organization does not exist")
    
    for subject in organizations[organization]['subjects']:
        if subject['username'] == username:
            return True
    return False

def encrypt_file(file_path, confidentiality_key):
    with open(file_path, 'rb') as f:
        file_content = f.read()
    
    iv = os.urandom(16)  
    cipher = AES.new(confidentiality_key, AES.MODE_CBC, iv)


    padded_content = pad(file_content, AES.block_size)
    encrypted_content = cipher.encrypt(padded_content)


    hmac = HMAC(confidentiality_key, hashes.SHA256())
    hmac.update(encrypted_content)
    file_hmac = hmac.finalize()

    return encrypted_content, iv, file_hmac

@app.route('/document/create', methods=['POST'])
def rep_add_doc():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_data'] 
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()
        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data_dict = json.loads(decrypt_data(encrypted_data, aes_key))

        session_file = data_dict['session_file']
        document_handle = data_dict['document_handle']
        file_path = data_dict['file_path']



        session_data = load_session(session_file)
        username = session_data['username']
        organization = session_data['organization']
        org = load_org_file()[organization]
        
        if not check_user_in_org(username, organization):
            return jsonify({'error': 'User does not belong to the organization'}), 403
        for user in org['subjects']:
            if user['username'] == username:
                user_permissions = user['permissions']
                break
        if 'DOC_NEW' not in user_permissions:
            return jsonify({'error': 'Permission denied: DOC_NEW permission is required'}), 403
        hex_key = session_data['session_keys']['confidentiality_key']
        confidentiality_key = bytes.fromhex(hex_key)
        for docs in org['docs']:
            if docs == document_handle:
                return jsonify({'error': 'Document already exists'}), 400


        encrypted_content, iv, file_hmac = encrypt_file(file_path, confidentiality_key)

        file_handle = os.urandom(16).hex()
        create_date = datetime.now().isoformat()
        file_name = os.path.basename(file_path)


        encrypted_file_path = os.path.join(SERVER_DIR, f"{file_handle}.encrypted")
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_content)


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

        os.makedirs(CLIENT_DIR, exist_ok=True)
        

        # Salvar metadados públicos + privados
        os.makedirs(SERVER_DIR, exist_ok=True)
        metadata_with_private = {
            'public_metadata': public_metadata,
            'restricted_metadata': restricted_metadata,
            'iv': base64.b64encode(iv).decode('utf-8'),
            'hmac': base64.b64encode(file_hmac).decode('utf-8')
        }

        metadata_path = os.path.join(SERVER_DIR, f"{document_handle}_private_meta.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata_with_private, f, indent=4)

        update_org_file(organization, document_handle)

        return jsonify({
            'message': 'Document added successfully',
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def update_org_file(organization, document_handle):
    try:
        org_data = load_org_file()

        if document_handle not in org_data[organization]['docs']:
            org_data[organization]['docs'].append(document_handle)

        save_json(ORG_FILE, org_data)
    except Exception as e:
        raise Exception(f"Erro ao atualizar ORG_FILE: {str(e)}")
    
def load_org_file():
    try:
        if os.path.exists(ORG_FILE):
            with open(ORG_FILE, 'r') as f:
                content = f.read().strip()
                if not content:
                    return {}
                return json.loads(content)
        return {}
    except Exception as e:
        raise ValueError(f"Failed to load organization file: {str(e)}")


@app.route('/document/metadata', methods=['POST'])
def get_document_metadata():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_data'] 
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()
        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data_dict = json.loads(decrypt_data(encrypted_data, aes_key))

        session_file = data_dict['session_file']
        document_name = data_dict['document_name']

        if not session_file or not document_name:
            return jsonify({'error': 'Missing session_file or document_name'}), 400

        session_data = load_session(session_file)
        username = session_data['username']
        organization = session_data['organization']

        org_data = load_org_file()

        if organization not in org_data:
            return jsonify({'error': f"Organization '{organization}' not found"}), 404
        user_permissions = None
        for subject in org_data[organization]['subjects']:
            if subject['username'] == username:
                user_permissions = subject['permissions']
                break
        if 'DOC_READ' not in user_permissions:
            return jsonify({'error': 'Permission denied: DOC_READ required'}), 403  

        if 'docs' not in org_data[organization]:
            return jsonify({'error': f"No documents found for organization '{organization}'"}), 404

        doc_handle = None
        for handle in org_data[organization]['docs']:
            private_metadata_path = os.path.join(SERVER_DIR, f"{handle}_private_meta.json")
            if not os.path.exists(private_metadata_path):
                continue

            with open(private_metadata_path, 'r') as f:
                metadata = json.load(f)
                
                if metadata['public_metadata']['document_handle'] == document_name:
                    doc_handle = handle
                    break

        if not doc_handle:
            return jsonify({'error': f"Document '{document_name}' not found in organization '{organization}'"}), 404

        private_metadata_path = os.path.join(SERVER_DIR, f"{doc_handle}_private_meta.json")
        if not os.path.exists(private_metadata_path):
            return jsonify({'error': f"Metadata file for document '{document_name}' not found"}), 404

        with open(private_metadata_path, 'r') as f:
            metadata = json.load(f)

        public_metadata = metadata.get('public_metadata', {})

        with open(os.path.join(CLIENT_DIR, f'{doc_handle}public_metadata.json'), 'w') as f:
            json.dump(public_metadata, f)

        return jsonify(public_metadata), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


    
@app.route('/document/list', methods=['POST'])
def list_documents():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_data'] 
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()
        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data_dict = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data_dict['session_file']
        creator = data_dict.get('creator')
        date_filter = data_dict.get('date_filter')
        date_value = data_dict.get('date_value')
        session_data = load_session(session_file)
        organization = session_data['organization']

        org_data = load_org_file()

        if organization not in org_data:
            return jsonify({'error': f"Organization '{organization}' not found"}), 404

        if 'docs' not in org_data[organization]:
            return jsonify({'error': f"No documents found for organization '{organization}'"}), 404

        documents = []
        for doc_handle in org_data[organization]['docs']:
            private_metadata_path = os.path.join(SERVER_DIR, f"{doc_handle}_private_meta.json")
            if not os.path.exists(private_metadata_path):
                continue
            metadata = load_json(private_metadata_path)
            documents.append(metadata['public_metadata'])

        if creator:
            documents = [doc for doc in documents if doc.get('creator') == creator]

        if date_filter and date_value:
            try:
                date_value = datetime.strptime(date_value, "%d-%m-%Y")
            except ValueError:
                return jsonify({'error': 'Invalid date format. Use DD-MM-YYYY'}), 400

            if date_filter == "nt":  
                documents = [doc for doc in documents if datetime.fromisoformat(doc['create_date']) > date_value]
            elif date_filter == "ot":  
                documents = [doc for doc in documents if datetime.fromisoformat(doc['create_date']) < date_value]
            elif date_filter == "et": 
                documents = [doc for doc in documents if datetime.fromisoformat(doc['create_date']).date() == date_value.date()]
            else:
                return jsonify({'error': 'Invalid date filter. Use "nt", "ot", or "et"'}), 400

        document_handles = [doc['document_handle'] for doc in documents]

        public_key = load_public_key(session_data['public_key'])

        response = {organization: document_handles}

        encrypted_document_handles = encrypt_with_public_key(response, public_key)

        return jsonify({
            'document_handles': encrypted_document_handles,
        }), 200

        

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/document/delete', methods=['POST'])
def delete_document():

    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_payload'] 
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()
        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data_dict = json.loads(decrypt_data(encrypted_data, aes_key))

        session_file = data_dict['session_file']
        document_name = data_dict['document_name']
        
        if not session_file or not document_name:
            return jsonify({'error': 'Missing session_file or document_name'}), 400

        session_data = load_session(session_file)
        username = session_data['username']
        organization = session_data['organization']

        org_data = load_org_file()
        org_info = org_data.get(organization)

        if not org_info:
            return jsonify({'error': f"Organization '{organization}' not found"}), 404

        user_permissions = None
        for subject in org_info.get('subjects', []):
            if subject['username'] == username:
                user_permissions = subject.get('permissions', {})
                break

        if not user_permissions or 'DOC_DELETE' not in user_permissions:
            return jsonify({'error': 'Permission denied: DOC_DELETE required'}), 403


        doc_handle = None
        for handle in org_info.get('docs', []):
            metadata_path = os.path.join(SERVER_DIR, f"{handle}_private_meta.json")
            if not os.path.exists(metadata_path):
                continue

            metadata = load_json(metadata_path)
            if metadata['public_metadata']['document_handle'] == document_name:
                    doc_handle = handle
                    break

        if not doc_handle:
            return jsonify({'error': f"Document '{document_name}' not found in organization '{organization}'"}), 404

        metadata_path = os.path.join(SERVER_DIR, f"{doc_handle}_private_meta.json")
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)

        file_handle = metadata['public_metadata']['file_handle']
        if not file_handle:
            return jsonify({'error': 'No file_handle exists for this document'}), 404

        metadata['public_metadata']['file_handle'] = None
        metadata['public_metadata']['deleter'] = username

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

    try:
        
        received_data = request.json
        encrypted_data = received_data['encrypted_data'] 
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()
        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data_dict = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data_dict['session_file']
        document_name = data_dict['document_name']

        if not session_file or not document_name:
            return jsonify({"error": "Missing session_file or document_name"}), 400
        session_data = load_session(session_file)
        username = session_data["username"]
        organization = session_data["organization"]

        org_data = load_org_file()
        if organization not in org_data:
            return jsonify({"error": f"Organization '{organization}' not found"}), 404

        user_permissions = None
        for subject in org_data[organization]["subjects"]:
            if subject["username"] == username:
                user_permissions = subject.get("permissions", {})
                break

        if not user_permissions or 'DOC_READ' not in user_permissions:
            return jsonify({"error": "Permission denied: DOC_READ required"}), 403

        doc_handle = None
        for handle in org_data[organization].get("docs", []):
            metadata_path = os.path.join(SERVER_DIR, f"{handle}_private_meta.json")
            if not os.path.exists(metadata_path):
                continue
            metadata = load_json(metadata_path)
            doc_handle = metadata["public_metadata"]["document_handle"]
            

        if not doc_handle:
            return jsonify({"error": f"Document '{document_name}' not found"}), 404

        file_handle = metadata["public_metadata"].get("file_handle")
        if not file_handle:
            return jsonify({"error": "File handle not found"}), 404

        aes_key = b64decode(metadata["restricted_metadata"]["key"])
       
        iv =  base64.b64decode(metadata["iv"])

        encrypted_file_path = os.path.join(SERVER_DIR, f"{file_handle}.encrypted")
        if not os.path.exists(encrypted_file_path):
            return jsonify({"error": "Encrypted file not found"}), 404

        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()
    
        if len(encrypted_data) % AES.block_size != 0:
            raise ValueError("Encrypted data length must be a multiple of block size")
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)

        return decrypted_data, 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/document/download', methods=['POST'])
def download_file():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_payload'] 
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()
        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data_dict = json.loads(decrypt_data(encrypted_data, aes_key))
        file_handle = data_dict['file_handle']

        file_path = os.path.join(SERVER_DIR, f"{file_handle}_private_meta.json")
        if not os.path.exists(file_path):
            return jsonify({"error": "Private metadata not found"}), 404
        metadata = load_json(file_path)
        file_id = metadata['public_metadata']['file_handle']

        file_path = os.path.join(SERVER_DIR, f"{file_id}.encrypted")
        

        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404


        return send_file(file_path, as_attachment=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# ---------------------------------------------------------------------------------------------------------------------------------------



@app.route('/session/assume_role', methods=['POST'])
def assume_role():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_data']
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data.get('session_file')
        role = data.get('role')

        if not session_file or not role:
            return jsonify({'error': 'Missing session_file or role'}), 400

        sessions_data = load_session(session_file)
        if not sessions_data:
            return jsonify({'error': 'Failed to load session: No active session found'}), 404

        session_org = sessions_data.get('organization')
        session_username = sessions_data.get('username')
        session_active_roles = sessions_data.get('active_role') or []  
        session_past_roles = sessions_data.get('past_roles') or []
        if session_active_roles:
            if session_active_roles[0] == role:
                return jsonify({'error': f'User already is active as a {role}'}), 400
            return jsonify({'error': 'User already has an active role, drop it before you assume a different one'}), 400
        organizations = load_org_file()
        org = organizations.get(session_org)
        
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        org_roles = org.get('roles')
        role_permissions = org_roles.get(role)
        org_subjects = org['subjects']

        for subject in org_subjects:
            if subject['username'] == session_username:
                available_roles = subject['roles']
                if role not in available_roles:
                    return jsonify({'error': f"Role '{role}' not found for user '{session_username}'"}), 404
                role_status = org['role_status']
                if role_status[role] == 'inactive':
                    return jsonify({'error': f"Role '{role}' is inactive"}), 400
                sessions_data['active_role'] = [role]  

                sup_permissions = subject['permissions']
                if role in session_past_roles:
                    session_past_roles.remove(role)
                for p in role_permissions:
                    if p not in sup_permissions:
                        sup_permissions.append(p)
                save_json(session_file, sessions_data)  
                save_json(ORG_FILE, organizations)  
                return jsonify({'message': f"Role '{role}' assumed successfully"}), 200
        return jsonify({'error': 'User not found in organization'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    
@app.route('/session/drop_role', methods=['POST'])
def drop_role():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_data']
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data.get('session_file')
        role = data.get('role')
        if not session_file or not role:
            return jsonify({'error': 'Missing session_file or role'}), 400
        sessions_data = load_session(session_file)
        if not sessions_data:
            return jsonify({'error': 'Failed to load session: No active session found'}), 404
        session_org = sessions_data.get('organization')
        session_username = sessions_data.get('username')
        session_active_roles = sessions_data.get('active_role') or []  
        session_past_roles = sessions_data.get('past_roles') or []
        if not session_active_roles:
            return jsonify({'error': 'No active role found'}), 404
        organizations = load_org_file()
        org = organizations.get(session_org)
        if not org:
                return jsonify({'error': 'Organization not found'}), 404
        org_subjects = org['subjects']

        for subject in org_subjects:
            if subject['username'] == session_username:
                    session_active_roles.remove(role)  
                    session_past_roles.append(role)
                    sessions_data['past_roles'] = session_past_roles
                    subject['permissions'] = []
                    save_json(session_file, sessions_data)  
                    save_json(ORG_FILE, organizations)  
                    return jsonify({'message': f"Role '{role}' dropped successfully"}), 200
        return jsonify({'error': 'User not found in organization'}), 404


    except Exception as e:
        return jsonify({"error": str(e)}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/roles/list', methods=['POST'])
def list_roles():

    received_data = request.json
    encrypted_data = received_data['encrypted_data']
    encrypted_aes_key = received_data['aes_key']
    rep_private_key = load_private_key()

    aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

    data = json.loads(decrypt_data(encrypted_data, aes_key))

    session_file = data.get('session_file')

    try:
       sessions_data = load_session(session_file)
       if not sessions_data:
           return jsonify({'error': 'Failed to load session: No active session found'}), 404
       session_active_roles = sessions_data.get('active_role') or []
       session_past_roles = sessions_data.get('past_roles') or []


       response_data = {'active_roles': session_active_roles, 'past_roles': session_past_roles}

       public_key = load_public_key(sessions_data['public_key'])
       print(public_key)
       encrypted_response = encrypt_with_public_key(response_data, public_key)
        
       return jsonify({'encrypted_data': encrypted_response}), 200


    except Exception as e:
        return jsonify({"error": str(e)}), 500


from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode

def load_public_key(public_key_pem):

    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),  
        backend=default_backend()
    )
    return public_key


@app.route('/roles/subjects', methods=['POST'])
def list_role_subjects():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_data']
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data['session_file']
        role = data['role']

        if not session_file or not role:
            return jsonify({'error': 'Missing session_file or role'}), 400

        sessions_data = load_session(session_file)
        organizations = load_org_file()
        session_org = sessions_data.get('organization')
        for a in organizations:
                if a == session_org:
                    org = organizations[a]
                    break      
        if not org:
            return jsonify({'error': 'Organization not found'}), 404

        org_roles = org['roles']
        if role not in org_roles:
            return jsonify({'error': f"Role '{role}' not found in organization '{session_org}'"}), 404
        
        subjects = []
        acl = org['acl']
        for r in acl:
            if role == r:
                for users in acl[r]:
                    subjects.append(users)

        public_key = load_public_key(sessions_data['public_key'])
        encrypted_subjects = encrypt_with_public_key(subjects, public_key)

        return jsonify({'subjects': encrypted_subjects}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def encrypt_with_public_key(data, public_key):

    data_str = json.dumps(data)

    encrypted_data = public_key.encrypt(
        data_str.encode('utf-8'),  
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return b64encode(encrypted_data).decode('utf-8')  

@app.route('/role/add', methods=['POST'])
def add_role():
    try:
        data = request.json
        encrypted_data = data['data']
        encrypted_aes_key = data['aes_key']
        rep_private_key = load_private_key()
        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)
        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data['session_file']
        role = data['role']


        if not session_file or not role:
            return jsonify({'error': 'Missing session_file or role'}), 400
        sessions_data = load_session(session_file)
        session_org = sessions_data.get('organization')
        session_username = sessions_data.get('username')
        organizations = load_org_file()
        for a in organizations:
                if a == session_org:
                    org = organizations[a]
                    break      
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        org_subjects = org['subjects']
        org_roles = org['roles']
        for subject in org_subjects:
            if subject['username'] == session_username:
                sub_roles = subject['roles']
                permissions = []
                for r in sub_roles:
                    permissions += org_roles[r]
                    
                if 'ROLE_NEW' in permissions :
                    if role not in org['roles']:
                        org['roles'][role] = []
                        org['role status'][role] = 'active'
                        save_json(ORG_FILE, organizations)
                        return jsonify({'message': f"Role '{role}' added to organization '{session_org}'"}), 200
                    else:
                        return jsonify({'error': f"Role '{role}' already exists in organization '{session_org}'"}), 409
                else:
                    return jsonify({'error': 'Permission denied: ROLE_NEW required'}), 403
        return jsonify({'error': 'User not found in organization'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/permission/add', methods=['POST'])
def add_permission():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_data']
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))
        
        session_file = data.get('session_file')
        role = data.get('role')
        permission = data.get('permission')

        if not session_file or not role or not permission:
            return jsonify({'error': 'session_file, role, and permission are required'}), 400

        sessions_data = load_session(session_file)
        organizations = load_org_file()
        
        session_org = sessions_data.get('organization')
        for a in organizations:
                if a == session_org:
                    org = organizations[a]
                    break      
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        subjects = org['subjects']
        sub_permissions = []
        for subject in subjects:
            if subject['username'] == sessions_data['username']:
                sub_permissions = subject['permissions']
                break
        if 'ROLE_MOD' not in sub_permissions:
            return jsonify({'error': 'You do not have permission to add permissions'}), 403
        org_roles = org['roles']
        subjects = org['subjects']
        users = []
        for subject in subjects:
            users.append(subject['username'])
        if permission in users:
            username = permission
            for subject in subjects:
                if subject['username'] == username:
                    subject['roles'].append(role)
                    for r in org_roles:
                        if r == role:
                            for p in org_roles[r]:
                                if p not in subject['permissions']:
                                    subject['permissions'].append(p)
            return jsonify({'message': f'Permission {permission} added to role {role} successfully'}), 200   
        if role not in org_roles:
            return jsonify({'error': f'Role {role} not found in organization {org['name']}'}), 404

        if permission not in org_roles[role]:
            org_roles[role].append(permission)
        else:
            return jsonify({'error': f'Permission {permission} already exists in role {role}'}), 409

        save_json(ORG_FILE, organizations)

        return jsonify({'message': f'Permission {permission} added to role {role} successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/permission/remove', methods=['POST'])
def remove_permission():
    try:

        received_data = request.json
        encrypted_data = received_data['encrypted_data']
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))

        session_file = data.get('session_file')
        role = data.get('role')
        permission = data.get('permission')

        if not session_file or not role or not permission:
            return jsonify({'error': 'session_file, role, and permission are required'}), 400

        sessions_data = load_session(session_file)
        organizations = load_org_file()
        session_org = sessions_data.get('organization')
        for a in organizations:
                if a == session_org:
                    org = organizations[a]
                    break      
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        subjects = org['subjects']
        sub_permissions = []
        for subject in subjects:
            if subject['username'] == sessions_data['username']:
                sub_permissions = subject['permissions']
                break
        if 'ROLE_MOD' not in sub_permissions:
            return jsonify({'error': 'You do not have permission to remove permissions'}), 403
        org_roles = org['roles']

        if role not in org_roles:
            return jsonify({'error': f'Role {role} not found in organization {org['name']}'}), 404


        if permission not in org_roles[role]:
            return jsonify({'error': f'Permission {permission} not found in role {role}'}), 404

        org_roles[role].remove(permission)

        save_json(ORG_FILE, organizations)

        return jsonify({'message': f'Permission {permission} removed from role {role} successfully'}), 200

    except Exception as e:
        print(f"Exception occurred: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/role/suspend', methods=['POST'])
def suspend_role():
    try:
        data = request.json
        encrypted_data = data['data']
        encrypted_aes_key = data['aes_key']
        private_key = load_private_key()
        aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data['session_file']
        role = data['role']


        if not session_file or not role:
            return jsonify({'error': 'session_file and role are required'}), 400

        sessions_data = load_session(session_file)
        organizations = load_org_file()
        session_org = sessions_data.get('organization')
        org = organizations.get(session_org)
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        org_roles = org['roles']
        subjects = org['subjects']
        sub_permissions = []
        for subject in subjects:
            if subject['username'] == sessions_data['username']:
                sub_permissions = subject['permissions']
                break
        if 'ROLE_DOWN' not in sub_permissions:
            return jsonify({'error': 'You do not have permission to suspend roles'}), 403
        if role not in org_roles:
            return jsonify({'error': f'Role {role} not found in organization {org["name"]}'}), 404

        org['role status'][role] = 'suspended'
        save_json(ORG_FILE, organizations)

        return jsonify({'message': f'Role {role} suspended successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/role/reactivate', methods=['POST'])
def reactivate_role():
    try:
        data = request.json
        encrypted_data = data['data']
        encrypted_aes_key = data['aes_key']
        private_key = load_private_key()
        aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data['session_file']
        role = data['role']


        if not session_file or not role:
            return jsonify({'error': 'session_file and role are required'}), 400

        sessions_data = load_session(session_file)
        organizations = load_org_file()
        session_org = sessions_data.get('organization')
        for a in organizations:
                if a == session_org:
                    org = organizations[a]
                    break      
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        org_roles = org['roles']

        if role not in org_roles:
            return jsonify({'error': f'Role {role} not found in organization {org["name"]}'}), 404
        subjects = org['subjects']
        sub_permissions = []
        for subject in subjects:
            if subject['username'] == sessions_data['username']:
                sub_permissions = subject['permissions']
                break
        
        if 'ROLE_UP' not in sub_permissions:
            return jsonify({'error': 'You do not have permission to reactivate roles'}), 403
        # Reativar a role
        org['role status'][role] = 'active'
        save_json(ORG_FILE, organizations)

        return jsonify({'message': f'Role {role} reactivated successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/subject/roles', methods=['POST'])
def list_subject_roles():
    try:

        received_data = request.json
        encrypted_data = received_data['encrypted_data']
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data.get('session_file')
        username = data.get('username')

        if not session_file or not username:
            return jsonify({'error': 'session_file and username are required'}), 400

        sessions_data = load_session(session_file)
        organizations = load_org_file()
        session_org = sessions_data.get('organization')
        org = organizations.get(session_org)
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        
        subject = next((s for s in org['subjects'] if s['username'] == username), None)
        if not subject:
            return jsonify({'error': f'Subject with username {username} not found'}), 404

        public_key = load_public_key(sessions_data['public_key'])
        encrypted_roles = encrypt_with_public_key(subject['roles'], public_key)

        return jsonify({'roles': encrypted_roles}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/role/permissions', methods=['POST'])
def rep_list_role_permissions ():
    try:
        data = request.json
        encrypted_data = data['encrypted_data']
        encrypted_aes_key = data['aes_key']
        rep_private_key = load_private_key()
        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)
        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data.get('session_file')
        role = data.get('role')
        if not session_file or not role:
            return jsonify({'error': 'session_file and role are required'}), 400
        sessions_data = load_session(session_file)
        session_org = sessions_data.get('organization')
        org = load_org_file().get(session_org)
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        org_roles = org['roles']
        if role not in org_roles:
            return jsonify({'error': f'Role {role} not found in organization {org["name"]}'}), 404

        public_key = load_public_key(sessions_data['public_key'])
        encrypted_permissions = encrypt_with_public_key(org_roles[role], public_key)
        return jsonify({'permissions': encrypted_permissions}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/permission/roles', methods=['POST'])
def rep_list_permission_roles ():
    try:
        received_data = request.json
        encrypted_data = received_data['encrypted_data']
        encrypted_aes_key = received_data['aes_key']
        rep_private_key = load_private_key()

        aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

        data = json.loads(decrypt_data(encrypted_data, aes_key))
        session_file = data.get('session_file')
        permission = data.get('permission').upper()
        if not session_file or not permission:
            return jsonify({'error': 'session_file and permission are required'}), 400
        sessions_data = load_session(session_file)
        session_org = sessions_data.get('organization')
        org = load_org_file().get(session_org)
        perm_roles = []
        if not org:
            return jsonify({'error': 'Organization not found'}), 404
        org_roles = org['roles']
        for role in org_roles:
            if permission in org_roles[role]:
                perm_roles.append(role)
        public_key = load_public_key(sessions_data['public_key'])
        encrypted_roles = encrypt_with_public_key(perm_roles, public_key)
        return jsonify({'roles': encrypted_roles}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/add_permission', methods=['POST'])
def add_permission2():
    received_data = request.json
    encrypted_data = received_data['encrypted_data']
    encrypted_aes_key = received_data['aes_key']
    rep_private_key = load_private_key()

    aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

    data = json.loads(decrypt_data(encrypted_data, aes_key))
    session_file = data.get('session_file')
    print(session_file)
    role = data.get('role')
    print(role)
    username = data.get('permission') 
    print(username)

    if not session_file or not role or not username:
        return jsonify({"error": "Missing session_file, role, or username"}), 400

    try:

        sessions_data = load_session(session_file)  
        organizations = load_org_file()  
        
        session_org = sessions_data.get('organization')
        org = organizations.get(session_org)

        if not org:
            return jsonify({"error": "Organization not found in session"}), 400
        subjects = org['subjects']
        sub_permissions = []
        for subject in subjects:
            if subject['username'] == sessions_data['username']:
                sub_permissions = subject['permissions']
                break
        if 'ROLE_MOD' not in sub_permissions:
            return jsonify({'error': 'You do not have permission to add permissions'}), 403

        user = None
        for subject in org.get('subjects', []):
            if subject.get('username') == username:
                user = subject
                break

        if not user:
            return jsonify({"error": f"User '{username}' not found in organization"}), 400
        role_permissions = org.get('roles', {}).get(role)

        if not role_permissions:
            return jsonify({"error": f"Role '{role}' not found in organization"}), 400
        
        if role not in user.get('roles', []):
            user.setdefault('roles', []).append(role)

        acl = org.get('acl', {})
        print("acl: ",acl)
        if username not in acl.get(role, []):
            acl.setdefault(role, []).append(username)

        save_json(ORG_FILE, organizations)

        return jsonify({"success": f"Permissions for '{role}' added to '{username}'"}), 200

    except Exception as e:
        return jsonify({"error": f"Error processing request: {str(e)}"}), 500

@app.route('/remove_permission', methods=['POST'])
def remove_permission2():

    received_data = request.json
    encrypted_data = received_data['encrypted_data']
    encrypted_aes_key = received_data['aes_key']
    rep_private_key = load_private_key()

    aes_key = decrypt_aes_key(encrypted_aes_key, rep_private_key)

    data = json.loads(decrypt_data(encrypted_data, aes_key))
    session_file = data.get('session_file')
    role = data.get('role')
    username = data.get('permission')  

    if not session_file or not role or not username:
        return jsonify({"error": "Missing session_file, role, or username"}), 400

    try:

        sessions_data = load_session(session_file) 
        organizations = load_org_file()  
        
        session_org = sessions_data.get('organization')
        org = organizations.get(session_org)

        if not org:
            return jsonify({"error": "Organization not found in session"}), 400
        subjects = org['subjects']
        sub_permissions = []
        for subject in subjects:
            if subject['username'] == sessions_data['username']:
                sub_permissions = subject['permissions']
                break
        if 'ROLE_MOD' not in sub_permissions:
            return jsonify({'error': 'You do not have permission to remove permissions'}), 403

        user = None
        for subject in org.get('subjects', []):
            if subject.get('username') == username:
                user = subject
                break

        if not user:
            return jsonify({"error": f"User '{username}' not found in organization"}), 400

        if role in user.get('roles', []):
            user['roles'].remove(role)
        else:
            return jsonify({"error": f"Role '{role}' not found in user '{username}'"}), 400

        acl = org.get('acl', {})
        if username in acl.get(role, []):
            acl[role].remove(username)
        else:
            return jsonify({"error": f"User '{username}' not found in ACL for role '{role}'"}), 400

        save_json(ORG_FILE, organizations)

        return jsonify({"success": f"Permission '{role}' removed from '{username}'"}), 200

    except Exception as e:
        return jsonify({"error": f"Error processing request: {str(e)}"}), 500

@app.route('/acl_doc', methods=['POST'])
def acl_doc():

    data = request.json
    encrypted_data = data.get('encrypted_data')
    encrypted_aes_key = data.get('aes_key')
    private_key = load_private_key()
    decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
    decrypted_data = decrypt_data(encrypted_data, decrypted_aes_key)
    data = json.loads(decrypted_data)
    session_file = data.get('session_file')
    doc_name = data.get('doc_name')
    sign = data.get('sign')
    role = data.get('role')
    permission = data.get('permission')

    if not session_file or not doc_name or not sign or not role or not permission:
        return jsonify({"error": "Missing session_file, doc_name, sign, role, or permission"}), 400

    try:
        session_data = load_session(session_file)
        session_org = session_data.get('organization')

        if not session_org:
            return jsonify({"error": "No organization associated with the session"}), 400

        organizations = load_org_file()
        org = organizations.get(session_org)
        
        if not org:
            return jsonify({"error": "Organization not found"}), 404
        subjects = org['subjects']
        sub_permissions = []
        for subject in subjects:
            if subject['username'] == session_data['username']:
                sub_permissions = subject['permissions']
                break
        if 'DOC_ACL' not in sub_permissions:
            return jsonify({'error': 'Permission denied'}), 403
        if doc_name not in org.get('docs', []):
            return jsonify({"error": f"Document '{doc_name}' not found in the organization"}), 404

        org_roles = org.get('roles', {})
        if role not in org_roles:
            return jsonify({"error": f"Role '{role}' not found in the organization"}), 404

        if permission not in org_roles[role]:
            return jsonify({"error": f"Permission '{permission}' not found for role '{role}'"}), 404

        if doc_name not in org:
            org[doc_name] = {}

        if sign == "+":
            if role not in org[doc_name]:
                org[doc_name][role] = [permission]
            elif permission not in org[doc_name][role]:
                org[doc_name][role].append(permission)
            else:
                print(f"Permission '{permission}' already exists for role '{role}' in document '{doc_name}'")
        elif sign == "-":
            if role in org[doc_name] and permission in org[doc_name][role]:
                org[doc_name][role].remove(permission)
                if not org[doc_name][role]:
                    del org[doc_name][role] 
            else:
                print(f"Permission '{permission}' not found for role '{role}' in document '{doc_name}' for removal")
        else:
            return jsonify({"error": "Invalid sign provided. Must be '+' or '-'"})

        organizations[session_org] = org

        with open(ORG_FILE, 'w') as f:
            json.dump(organizations, f, indent=4)

        return jsonify({"message": f"ACL updated successfully for document '{doc_name}'"}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500




if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)