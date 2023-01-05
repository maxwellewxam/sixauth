import hashlib
import jsonpath_ng
import os
import json
import base64
import bcrypt
import socket
import time
import threading
import logging

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_restful import fields, marshal
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

from . import logs

class LocationError(BaseException): ...
class AuthenticationError(BaseException): ...
class UsernameError(AuthenticationError): ...
class PasswordError(AuthenticationError): ...
class DataError(BaseException): ...

cache = {}

server_console = logging.getLogger('server_console')
server_file = logging.getLogger('server_file')
client_console = logging.getLogger('client_console')
client_file = logging.getLogger('client_file')

server_console.setLevel(logging.INFO)
server_file.setLevel(logging.INFO)
client_console.setLevel(logging.INFO)
client_file.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def log_paths(client_file_location = os.path.dirname(logs.__file__), server_file_location = os.getcwd()): 
    global server_file_handler
    global client_file_handler
    server_file_handler = logging.FileHandler(server_file_location+'/server.log')
    client_file_handler = logging.FileHandler(client_file_location+'/client.log')
    server_file_handler.setFormatter(formatter)
    client_file_handler.setFormatter(formatter)
    server_console.addHandler(server_file_handler)
    server_console.addHandler(console_handler)
    server_file.addHandler(server_file_handler)
    client_console.addHandler(client_file_handler)
    client_file.addHandler(client_file_handler)

log_paths()

def check_and_remove(d, threshold, stop_flag):
    while not stop_flag.is_set():
        for key in list(d):  # make a copy of the keys to avoid modifying the dict while iterating
            if time.time() - d[key]['time'] > threshold:
                del d[key]
        time.sleep(1)  # check every 1 second

def encrypt_data(data, password, username):
    json_data = json.dumps(data)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(username.encode()),
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
    fernet = Fernet(key)
    return fernet.encrypt(json_data.encode()).decode()

def decrypt_data(data, password, username):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(username.encode()),
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
    fernet = Fernet(key)
    return json.loads(fernet.decrypt(data.encode()).decode())

def encrypt_data_fast(message, key):
    return Fernet(bytes.fromhex(key)).encrypt(json.dumps(message).encode())

def decrypt_data_fast(message, key):
    return json.loads(Fernet(bytes.fromhex(key)).decrypt(message).decode())

def create_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).hex()

def verify_password_hash(hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(hash))

def convert_numbers_to_words(text):
        return text.replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')

def is_json_serialized(obj):
    try:
        json.loads(obj)
        return True
    except json.decoder.JSONDecodeError:
        return False

def is_valid_key(data, id):
    try:
        decrypt_data_fast(data, id)
        return True
    except InvalidToken:
        return False

def establish_connection(address):
    client_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
    client_public_key = client_private_key.public_key()

    #Serialize the client's public key
    client_public_key_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    #reate a socket
    client_socket = socket.socket()
    
    #get adress and port
    connection_info = address.split(':')

    #Connect to the server
    client_socket.connect((connection_info[0], int(connection_info[1])))

    #Send the client's public key to the server
    client_socket.send(client_public_key_bytes)

    #Wait for the server's public key
    server_public_key_bytes = client_socket.recv(1024)

    #Deserialize the server's public key
    server_public_key = serialization.load_pem_public_key(
    server_public_key_bytes, default_backend()
    )

    #Calculate the shared secret key using ECDH
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)

    #Use HKDF to derive a symmetric key from the shared secret
    kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"session key",
    backend=default_backend()
    )
    key = kdf.derive(shared_secret)

    #Use the symmetric key to encrypt and decrypt messages
    f = Fernet(base64.urlsafe_b64encode(key))
    
    return f, client_socket

def add_user(id):
    hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
    cache[hash] = {'main':encrypt_data_fast([None,(None,None)],id), 'time':time.time()}
    return hash
    
def find_user(hash, id):
    if is_valid_key(cache[hash]['main'], id):
        cache[hash]['time'] = time.time()
        return decrypt_data_fast(cache[hash]['main'],id)
    
    return [False,(False,False)]
    
def update_user(hash, id, dbdat):
    if is_valid_key(cache[hash]['main'], id):
        cache[hash]['main'] = encrypt_data_fast(dbdat,id)
        cache[hash]['time'] = time.time()
        return [None]

    return [False,(False,False)]

def delete_user(hash, id):
    if is_valid_key(cache[hash]['main'], id):
        del cache[hash]
        return [None]

    return [False,(False,False)]

def sign_up(app, db, User, **data):
    if data['username'] == '':
        return {'code':406}
    
    if data['username'].isalnum() == False:
        return {'code':406}
    
    with app.app_context():
        user_from_database = User.query.filter_by(username=data['username']).first()
    
    if user_from_database:
        return {'code':409}
        
    with app.app_context():
        db.session.add(User(username=data['username'], password=create_password_hash(data['password']), data=encrypt_data({}, data['username'], data['password'])))
        db.session.commit()
    
    return {'code':200}

def save_data(**data):
    user_from_cache = find_user(data['hash'], data['id'])[0]
    userinfo_from_cache = find_user(data['hash'], data['id'])[1]
    
    if user_from_cache == None or user_from_cache == False:
        return {'code':423}
    
    if not is_json_serialized(data['data']):
        return {'code':420, 'data':data['data'], 'error':'Object is not json serialized'}
    
    data_from_request = json.loads(data['data'])
    
    if data['location'] == '':
        update_user(data['hash'], data['id'], [data_from_request, userinfo_from_cache])
        return {'code':200, 'data':data_from_request}
    
    jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).update_or_create(user_from_cache, data_from_request)
    update_user(data['hash'], data['id'], [user_from_cache, userinfo_from_cache])

    return {'code':200, 'data':user_from_cache}

def delete_data(**data):
    user_from_cache = find_user(data['hash'], data['id'])[0]
    userinfo_from_cache = find_user(data['hash'], data['id'])[1]
    
    if user_from_cache == None or user_from_cache == False:
        return {'code':423}
    
    if data['location'] == '':
        update_user(data['hash'], data['id'], [{}, userinfo_from_cache])
        return {'code':200}
    
    parsed_location = jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).find(user_from_cache)
    
    if parsed_location == []:
        return {'code':416}
    
    del [match.context for match in parsed_location][0].value[str([match.path for match in parsed_location][0])]
    update_user(data['hash'], data['id'], [user_from_cache, userinfo_from_cache])
    
    return {'code':200}

def log_out(app, db, passfields, User, **data):
    user_from_cache = find_user(data['hash'], data['id'])[0]
    username, password = find_user(data['hash'], data['id'])[1]

    if user_from_cache == None or user_from_cache == False:
        return {'code':200}
    
    with app.app_context():
        user_from_database = User.query.filter_by(username=username).first()
    
    if not user_from_database:
        return {'code':420, 'data':user_from_cache, 'error':'could not find user to logout'}
    
    datPass = marshal(user_from_database, passfields)['password']
    
    if not verify_password_hash(datPass, password):
        return {'code': 423}

    with app.app_context():
        db.session.delete(user_from_database)
        db.session.add(User(username=username, password=create_password_hash(password), data=encrypt_data(user_from_cache, username, password)))
        db.session.commit()
    
    update_user(data['hash'], data['id'], [None,(None,None)])
    
    return {'code':200}

def remove_account(app, db, passfields, User, **data):
    username, password = find_user(data['hash'], data['id'])[1]
            
    with app.app_context():
        user_from_database = User.query.filter_by(username=username).first()
    
    if not user_from_database or username == False:
        return {'code':423}
    
    datPass = marshal(user_from_database, passfields)['password']
    
    if not verify_password_hash(datPass, password):
        return {'code':423}
    
    with app.app_context():
        db.session.delete(user_from_database)
        db.session.commit()
        
    update_user(data['hash'], data['id'], [None,(None,None)])
    
    return {'code':200}

def log_in(app, datfields, passfields, User, **data):
    if data['username'] == '':
        return {'code':406}
    
    if data['username'].isalnum() == False:
        return {'code':406}
    
    with app.app_context():
        user_from_database = User.query.filter_by(username=data['username']).first()

    if not user_from_database:
        return {'code':404}
    
    datPass = marshal(user_from_database, passfields)['password']
    
    if not verify_password_hash(datPass, data['password']):
        return {'code':401}
        
    if update_user(data['hash'], data['id'], [decrypt_data(marshal(user_from_database, datfields)['data'], data['username'], data['password']), (data['password'], data['username'])])[0] == False:
        return {'code':423}
    
    return {'code':200}

def load_data(**data):
    user_from_cache = find_user(data['hash'], data['id'])[0]
    
    if user_from_cache == None or user_from_cache == False:
        return {'code':423}
    
    if data['location'] == '':
        return {'code':202, 'data':user_from_cache}
    
    parsed_location = jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).find(user_from_cache)
    
    if parsed_location == []:
        return {'code':416}
    
    return {'code':202, 'data':[match.value for match in parsed_location][0]}

def create_session(**data):
    user_hash = add_user(data['id'])
    
    return {'code':101, 'hash':user_hash}

def end_session(**data):
    if delete_user(data['hash'], data['id'])[0] == False:
        return {'code':423}

    return {'code':200}

def backend_session(address):
    f, client_socket = establish_connection(address)
    def send(**data):
        client_socket.send(f.encrypt(json.dumps(data).encode('utf-8')))
        return json.loads(f.decrypt(client_socket.recv(1024)).decode())
    return send

def frontend_session(path = os.getcwd()):
    
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{path}/database.db'
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy(app)            

    class User(db.Model):
        username = db.Column(db.String, nullable=False, primary_key = True)
        password = db.Column(db.String, nullable=False)
        data = db.Column(db.String)

        def __init__(self, username, password, data):
            self.username = username
            self.password = password
            self.data = data

    if not os.path.isfile(f'{path}/database.db'):
        with app.app_context():
            db.create_all()
        
    datfields = {'data': fields.Raw}
    passfields = {'password': fields.String}
    
    def action(**data):
        if data['func'] == 'create_session':
            return create_session(**data)
        
        elif data['func'] == 'sign_up':
            return sign_up(app, db, User, **data)
        
        elif data['func'] == 'save_data':
            return save_data(**data)

        elif data['func'] == 'delete_data':
            return delete_data(**data)
            
        elif data['func'] == 'log_out':
            return log_out(app, db, passfields, User, **data)
            
        elif data['func'] == 'remove_account':
            return remove_account(app, db, passfields, User, **data)
    
        elif data['func'] == 'log_in':
            return log_in(app, datfields, passfields, User, **data)
            
        elif data['func'] == 'load_data':
            return load_data(**data)
        
        elif data['func'] == 'end_session':
            return end_session(**data)
    
    return action

def start_server(host, port, cache_threshold = 300, debug = False):
    
    if debug:
        server_file.addHandler(console_handler)
        client_file.addHandler(console_handler)
    client_file.addHandler(server_file_handler)
    
    # Run the server
    # Create a frontend session for the server
    session = frontend_session()
    stop_flag = threading.Event()
    
    t = threading.Thread(target=check_and_remove, args=(cache, cache_threshold, stop_flag))
    t.start()
    
    #Generate an ECDH key pair for the server
    server_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
    server_public_key = server_private_key.public_key()

    #Serialize the server's public key
    server_public_key_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

    clients = []
    def exit():
        stop_flag.set()
        t.join()
        for client_s, client_t in clients:
            client_s.close()
            client_t.exit()
            
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #HMM
    server_socket.setblocking(0)
    
    # Bind the socket to the port
    server_socket.bind((host, port))

    # Listen for incoming connections
    server_socket.listen()

    server_console.info('Press Ctrl+C to exit')
    server_console.info(f"Listening for incoming connections on {host}:{port}...")

    def handle_client(client_socket, f, client_address, session):
    # Pass requests from the client to the servers database session
        while True:
            # Get client request
            try:
                recv = client_socket.recv(1024)
                if debug:
                    server_console.info(f"Received data from client: {client_address}")
                if recv != None:
                    # Decrpyt request 
                    data = json.loads(f.decrypt(recv).decode())
                    # This is a special case for when the client requests to end the session
                    try:
                        if data['func'] == 'end_session':
                            # Send request to server session and then check the return status
                            end = session(**data)
                            client_socket.send(f.encrypt(json.dumps(end).encode('utf-8')))
                            # If good then close connection
                            if end['code'] == 200:
                                break
                        # Normal handling of client requests
                        else:
                            # Just pass the request to the session and return to the client
                            client_socket.send(f.encrypt(json.dumps(session(**data)).encode('utf-8')))
                    except Exception as err:
                        client_socket.send(f.encrypt(str(err).encode('utf-8')))
                        break
                else:
                    break
            except BlockingIOError:
                pass
        # End the connection when loop breaks
        if debug:
            server_console.info(f"Closed connection from {client_address}")
        client_socket.close()
    #Accept an incoming connection
    while True:
        try:
            try:
                client_socket, client_address = server_socket.accept()

                #Wait for the client's public key
                client_public_key_bytes = client_socket.recv(1024)
                
                #Deserialize the client's public key
                client_public_key = serialization.load_pem_public_key(
                client_public_key_bytes, default_backend())

                #Send the server's public key to the client
                client_socket.send(server_public_key_bytes)

                #Calculate the shared secret key using ECDH
                shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

                #Use HKDF to derive a symmetric key from the shared secret
                kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"session key",
                backend=default_backend()
                )
                key = kdf.derive(shared_secret)

                #Use the symmetric key to encrypt and decrypt messages
                f = Fernet(base64.urlsafe_b64encode(key))
                if debug:
                    server_console.info(f"Received incoming connection from {client_address}")
                
                #Create a new thread to handle the incoming connection
                client_thread = threading.Thread(target=handle_client, args=(client_socket, f, client_address, session))
                client_thread.start()
                clients.append((client_socket, client_thread))
            except BlockingIOError:
                pass
        except KeyboardInterrupt:
            break
        except BaseException as err:
            exit()
            raise err()
    exit()
    server_console.info('Exited')
