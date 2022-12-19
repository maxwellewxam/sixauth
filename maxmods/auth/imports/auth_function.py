import hashlib
import jsonpath_ng
import os
import json
import base64
import bcrypt
import socket

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

class LocationError(BaseException): ...
class AuthenticationError(BaseException): ...
class UsernameError(AuthenticationError): ...
class PasswordError(AuthenticationError): ...
class DataError(BaseException): ...

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
    return Fernet(base64.urlsafe_b64encode(key)), client_socket

cache = {}

def add_user(id):
    hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
    cache[hash] = encrypt_data_fast([None,(None,None)],id)
    
    return hash
    
def find_user(hash, id):
    if is_valid_key(cache[hash], id):
        return decrypt_data_fast(cache[hash],id)
    
    return [False,(False,False)]
    
def update_user(hash, id, dbdat):
    if is_valid_key(cache[hash], id):
        cache[hash] = encrypt_data_fast(dbdat,id)
        return [None]

    return [False,(False,False)]

def delete_user(hash, id):
    if is_valid_key(cache[hash], id):
        del cache[hash]
        return [None]

    return [False,(False,False)]

def sign_up(context, **data):
    if data['username'] == '':
        return {'code':406}
    
    if data['username'].isalnum() == False:
        return {'code':406}
    
    with context.app.app_context():
        user_from_database = context.User.query.filter_by(username=data['username']).first()
    
    if user_from_database:
        return {'code':409}
        
    with context.app.app_context():
        context.db.session.add(context.User(username=data['username'], password=create_password_hash(data['password']), data=encrypt_data({}, data['username'], data['password'])))
        context.db.session.commit()
    
    return {'code':200}

def save_data(context, **data):
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

def delete_data(context, **data):
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

def log_out(context, **data):
    user_from_cache = find_user(data['hash'], data['id'])[0]
    username, password = find_user(data['hash'], data['id'])[1]

    if user_from_cache == None or user_from_cache == False:
        return {'code':200}
    
    with context.app.app_context():
        user_from_database = context.User.query.filter_by(username=username).first()
    
    if not user_from_database:
        return {'code':420, 'data':user_from_cache, 'error':'could not find user to logout'}
    
    datPass = marshal(user_from_database, context.passfields)['password']
    
    if not verify_password_hash(datPass, password):
        return {'code': 423}

    with context.app.app_context():
        context.db.session.delete(user_from_database)
        context.db.session.add(context.User(username=username, password=create_password_hash(password), data=encrypt_data(user_from_cache, username, password)))
        context.db.session.commit()
    
    update_user(data['hash'], data['id'], [None,(None,None)])
    
    return {'code':200}

def remove_account(context, **data):
    username, password = find_user(data['hash'], data['id'])[1]
            
    with context.app.app_context():
        user_from_database = context.User.query.filter_by(username=username).first()
    
    if not user_from_database or username == False:
        return {'code':423}
    
    datPass = marshal(user_from_database, context.passfields)['password']
    
    if not verify_password_hash(datPass, password):
        return {'code':423}
    
    with context.app.app_context():
        context.db.session.delete(user_from_database)
        context.db.session.commit()
        
    update_user(data['hash'], data['id'], [None,(None,None)])
    
    return {'code':200}

def log_in(context, **data):
    if data['username'] == '':
        return {'code':406}
    
    if data['username'].isalnum() == False:
        return {'code':406}
    
    with context.app.app_context():
        user_from_database = context.User.query.filter_by(username=data['username']).first()

    if not user_from_database:
        return {'code':404}
    
    datPass = marshal(user_from_database, context.passfields)['password']
    
    if not verify_password_hash(datPass, data['password']):
        return {'code':401}
        
    if update_user(data['hash'], data['id'], [decrypt_data(marshal(user_from_database, context.datfields)['data'], data['username'], data['password']), (data['password'], data['username'])])[0] == False:
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

def frontend_session(path = None):
    self = {'app', 'db', 'datfields', 'passfields', 'User'}
    app = Flask(__name__)
    if path == None:
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.getcwd()}/database.db'
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{path}/database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy(app)            

    class User(db.Model):
        username = db.Column(db.String, nullable=False, primary_key = True)
        password = db.Column(db.String, nullable=False)
        data = db.Column(db.String)

        def __init__(self, username, password, data):
            username = username
            password = password
            data = data

    if path == None:        
        if os.path.isfile(f'{os.getcwd()}/database.db') is False:
            with app.app_context():
                db.create_all()

    else:
        if os.path.isfile(f'{path}/database.db') is False:
            with app.app_context():
                db.create_all()
        
    datfields = {'data': fields.Raw}
    passfields = {'password': fields.String}
    
    def action(**data):
        if data['func'] == 'create_session':
            return create_session(app, db, datfields, passfields, User, **data)
        
        elif data['func'] == 'sign_up':
            return sign_up(app, db, datfields, passfields, User, **data)
        
        elif data['func'] == 'save_data':
            return save_data(app, db, datfields, passfields, User, **data)

        elif data['func'] == 'delete_data':
            return delete_data(app, db, datfields, passfields, User, **data)
            
        elif data['func'] == 'log_out':
            return log_out(app, db, datfields, passfields, User, **data)
            
        elif data['func'] == 'remove_account':
            return remove_account(app, db, datfields, passfields, User, **data)
    
        elif data['func'] == 'log_in':
            return log_in(app, db, datfields, passfields, User, **data)
            
        elif data['func'] == 'load_data':
            return load_data(app, db, datfields, passfields, User, **data)
        
        elif data['func'] == 'end_session':
            return end_session(app, db, datfields, passfields, User, **data)
    
    return action
