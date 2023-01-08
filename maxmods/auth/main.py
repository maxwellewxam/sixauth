# so you wanna know whats going on in this file eh
# basically these are all functions the auth module uses to manage ya things
# because this is my file and im not regulated by sum community
# im gonna make the comments for this my way bozo
# you should still beable to understand it but youll def have fun reading it lmao
# ion finna be rude or out rageous or nun, you can lowk read this to your grandma no problem
# also if anyone sees this, please lemme know of any improvements i can make to the code, not the comments
# also also i made this whole file without classes because i felt like it
# object oriented programming is cool and all, and by the gods i love classes
# but i challenged myself to make this without them and i also remember sum vid i watch about
# O.O.P. being bas so i decided to not use it
# only ecxeption to this rule is that the code used for the database connection uses a class
# i lowk dont know a different way without rewriting the whole database connection with a different module or sum 

# ok so these are all the imports i use
# my fav lowk being josnpath_ng or cryptography
# the two modules that really pull their weight arround here
# like flask was lowk only used in earlier versions for the online server connections
# it came preloaded with a fye ass database api and so it became heavily ingraned into the base of alot of the functions
# but now i use sockets and cryptography, and i just havent felt the need to rewrite alot of the database code
# i mean it shouldnt be hard but im here now an nun else we gonna do
import hashlib
import jsonpath_ng
import os
import sys
import json
import base64
import bcrypt
import socket
import time
import threading
import logging
import traceback

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

# this lil john here is just used to get a file path to a folder where the module is stored
from . import logs

# these are all the exceptions that this module will raise
# i could use like built in ones but ion feel like it so...
class LocationError(BaseException): ...
class AuthenticationError(BaseException): ...
class UsernameError(AuthenticationError): ...
class PasswordError(AuthenticationError): ...
class DataError(BaseException): ...

# alr alr so first real thing here is this cache dict
# so this john will hold all the active users data for way quicker access
# the database holds the users data with a really strong encryption thats tough to compute
# and so we to pull the johns data from the db and and decrypt it once
# then store it in the cache with a weaker but way faster encryption
# this also means that if the john doesnt properly exit, any change made to the data before its saved will be lost
# a sacrifice im willing to make, also with i could put emoji's in here lol
# i lowk dont like just creating this thing like this but ion know a better way with out classes and whatnot
cache = {}

server_console = logging.getLogger('server_console')
server_logger = logging.getLogger('server_logger')
client_console = logging.getLogger('client_console')
client_logger = logging.getLogger('client_logger')

server_console.setLevel(logging.INFO)
server_logger.setLevel(logging.INFO)
client_console.setLevel(logging.INFO)
client_logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def log_paths(client_logger_location = os.path.dirname(logs.__file__), server_logger_location = os.getcwd()): 
    global server_logger_handler
    global client_logger_handler
    server_logger_handler = logging.FileHandler(server_logger_location+'/server.log')
    client_logger_handler = logging.FileHandler(client_logger_location+'/client.log')
    server_console.addHandler(server_logger_handler)
    server_console.addHandler(console_handler)
    server_logger.addHandler(server_logger_handler)
    client_console.addHandler(client_logger_handler)
    client_logger.addHandler(client_logger_handler)
    server_logger.info('VVV---------BEGIN-NEW-LOG----------VVV')
    client_logger.info('VVV---------BEGIN-NEW-LOG----------VVV')
    server_logger_handler.setFormatter(formatter)
    client_logger_handler.setFormatter(formatter)

log_paths()

def check_and_remove(threshold, stop_flag):
    while not stop_flag.is_set():
        for key in list(cache):  # make a copy of the keys to avoid modifying the dict while iterating
            if time.time() - cache[key]['time'] > threshold:
                del cache[key]
                server_logger.info('A user timed out')
                server_logger.info(f'Current cache: {cache}')
        time.sleep(1)  # check every 1 second

def keep_alive(cache_threshold, stop_flag):
    while not stop_flag.is_set():
        t = threading.Thread(target=check_and_remove, args=(cache_threshold, stop_flag))
        t.start()
        t.join()

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
        client_logger.info(f'Key invalid, {id}')
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
    client_logger.info(f'Current cache: {cache}')
    return hash
    
def find_user(hash, id):
    if is_valid_key(cache[hash]['main'], id):
        cache[hash]['time'] = time.time()
        client_logger.info(f'Current cache: {cache}')
        return decrypt_data_fast(cache[hash]['main'],id)

    return [False,(False,False)]
    
def update_user(hash, id, dbdat):
    if is_valid_key(cache[hash]['main'], id):
        cache[hash]['main'] = encrypt_data_fast(dbdat,id)
        cache[hash]['time'] = time.time()
        client_logger.info(f'Current cache: {cache}')
        return [None]

    return [False,(False,False)]

def delete_user(hash, id):
    if is_valid_key(cache[hash]['main'], id):
        del cache[hash]
        client_logger.info(f'Current cache: {cache}')
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
    #client_logger.info(f'Username from cache: {username}') 
    with app.app_context():
        user_from_database = User.query.filter_by(username=username).first()
        #client_logger.info(f'Username from database: {user_from_database}')
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
        
    if update_user(data['hash'], data['id'], [decrypt_data(marshal(user_from_database, datfields)['data'], data['username'], data['password']), (data['username'], data['password'])])[0] == False:
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
    client_logger.info(f'Connected to: {address}')
    def send(**data):
        client_socket.send(f.encrypt(json.dumps(data).encode('utf-8')))
        return json.loads(f.decrypt(client_socket.recv(1024)).decode())
    return send

def frontend_session(path = os.getcwd()):
    
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{path}/database.db'
    client_logger.info(f'Database located at: sqlite:///{path}/database.db')
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

def server(host, port, cache_threshold = 300, debug = False, log_senseitive_info = False):
    
    if debug:
        server_logger.addHandler(console_handler)
        client_logger.addHandler(console_handler)
        server_console.info('Debug mode active')
        
    if log_senseitive_info:
        server_console.info('WARNING: SENSEITIVE INFORMATION BEING LOGGED')
        
    client_logger.addHandler(server_logger_handler)
    
    # Run the server
    # Create a frontend session for the server
    session = frontend_session()
    stop_flag1 = threading.Event()
    
    t = threading.Thread(target=keep_alive, args=(cache_threshold, stop_flag1))
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
        stop_flag1.set()
        t.join()
        server_logger.info('Cache thread exited')
        for client_s, client_t in clients:
            client_s.close()
            client_t.join()
        server_logger.info('All client threads exited')
            
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #HMM
    server_socket.setblocking(0)
    
    # Bind the socket to the port
    server_socket.bind((host, port))

    # Listen for incoming connections
    server_socket.listen()
    server_console.info('Server started')
    server_console.info('Press Ctrl+C to exit')
    server_console.info(f"Listening for incoming connections on {host}:{port}")

    def handle_client(client_socket, f, client_address, session, stop_flag):
    # Pass requests from the client to the servers database session
        try:
            while not stop_flag.is_set():

                try:
                    recv = client_socket.recv(1024)
                    server_logger.info(f"Received data from client: {client_address}: {recv}")
                    
                    if recv != b'':
                        try:
                            data = json.loads(f.decrypt(recv).decode())
                            
                            if log_senseitive_info:
                                server_logger.info(f"Received: {data}")
                            elif data['func'] != 'sign_up' and data['func'] != 'create_session':
                                server_logger.info(f"Received: {data['func']}, {data['hash']}")
                            
                            response = session(**data)
                            
                            server_logger.info(f'Response: {response["code"]}')
                            
                            client_socket.send(f.encrypt(json.dumps(response).encode('utf-8')))
                            
                            if data['func'] == 'end_session' and response['code'] == 200:
                                break
                        
                        except BaseException as err:
                            if type(err) == KeyError:
                                client_socket.send(f.encrypt(json.dumps({'code':420, 'data':None, 'error':f'Couldnt find user in cache, contact owner to recover any data, \nuse this key: {str(err)}\nuse this id: \'{str(data["id"])}\''}).encode('utf-8')))
                            else:
                                client_socket.send(f.encrypt(json.dumps({'code':420, 'data':None, 'error':str(err)}).encode('utf-8')))
                            
                            tb = traceback.extract_tb(sys.exc_info()[2])
                            line_number = tb[-1][1]
                            server_logger.info(f'Request prossesing for {client_address} failed, Error on line {line_number}: {str(type(err))}:{str(err)}\n{str(tb)}')
                            break
                    else:
                        break
                    
                except BlockingIOError:
                    pass
                
        except BaseException as err:
            server_console.info(f'Client thread did not exit successfully, Error: {err}')
        # End the connection when loop breaks
        server_logger.info(f"Closed connection from {client_address}")
        client_socket.close()
        for sock, thread in clients:
            if sock == client_socket:
                clients.remove((client_socket, thread))
    #Accept an incoming connection
    try:
        while not stop_flag1.is_set():
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
                server_logger.info(f"Received incoming connection from {client_address}")
                
                #Create a new thread to handle the incoming connection
                client_thread = threading.Thread(target=handle_client, args=(client_socket, f, client_address, session, stop_flag1))
                client_thread.start()
                server_logger.info('Client thread started')
                clients.append((client_socket, client_thread))
            except BlockingIOError:
                pass
    except KeyboardInterrupt:
        exit()
        server_console.info('Exited')
    except BaseException as err:
        exit()
        server_console.info(f'Program did not exit successfully, Error: {err}')
