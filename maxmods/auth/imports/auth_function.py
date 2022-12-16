import hashlib
import jsonpath_ng
import os
import json
import base64
import bcrypt
import requests
import warnings

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_restful import fields, marshal
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

class UserCache:
    def __init__(self):
        self.users = {}
        
    def add_user(self, id):
        hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
        self.users[hash] = encrypt_data_fast([None,(None,None)],id)
        
        return hash
        
    def find_user(self, hash, id):
        if is_valid_key(self.users[hash], id):
            return decrypt_data_fast(self.users[hash],id)
        
        return [False,(False,False)]
        
    def update_user(self, hash, id, dbdat):
        if is_valid_key(self.users[hash], id):
            self.users[hash] = encrypt_data_fast(dbdat,id)
            return [None]

        return [False,(False,False)]

    def delete_user(self, hash, id):
        if is_valid_key(self.users[hash], id):
            del self.users[hash]
            return [None]

        return [False,(False,False)]

class JsonResponse:
    def __init__(self, Code):
        self.Code = Code
        
    def json(self):
        return self.Code
    
def json_response(func):
    def wrapper(*args, **kwargs):
            return JsonResponse(func(*args, **kwargs))
    return wrapper

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
    user_from_cache = context.cache.find_user(data['hash'], data['id'])[0]
    userinfo_from_cache = context.cache.find_user(data['hash'], data['id'])[1]
    
    if user_from_cache == None or user_from_cache == False:
        return {'code':423}
    
    if not is_json_serialized(data['data']):
        return {'code':420, 'data':data['data'], 'error':'Object is not json serialized'}
    
    data_from_request = json.loads(data['data'])
    
    if data['location'] == '':
        context.cache.update_user(data['hash'], data['id'], [data_from_request, userinfo_from_cache])
        return {'code':200, 'data':data_from_request}
    
    jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).update_or_create(user_from_cache, data_from_request)
    context.cache.update_user(data['hash'], data['id'], [user_from_cache, userinfo_from_cache])

    return {'code':200, 'data':user_from_cache}

def delete_data(context, **data):
    user_from_cache = context.cache.find_user(data['hash'], data['id'])[0]
    userinfo_from_cache = context.cache.find_user(data['hash'], data['id'])[1]
    
    if user_from_cache == None or user_from_cache == False:
        return {'code':423}
    
    if data['location'] == '':
        context.cache.update_user(data['hash'], data['id'], [{}, userinfo_from_cache])
        return {'code':200}
    
    parsed_location = jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).find(user_from_cache)
    
    if parsed_location == []:
        return {'code':416}
    
    del [match.context for match in parsed_location][0].value[str([match.path for match in parsed_location][0])]
    context.cache.update_user(data['hash'], data['id'], [user_from_cache, userinfo_from_cache])
    
    return {'code':200}

def log_out(context, **data):
    user_from_cache = context.cache.find_user(data['hash'], data['id'])[0]
    username, password = context.cache.find_user(data['hash'], data['id'])[1]

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
    
    context.cache.update_user(data['hash'], data['id'], [None,(None,None)])
    
    return {'code':200}

def remove_account(context, **data):
    username, password = context.cache.find_user(data['hash'], data['id'])[1]
            
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
        
    context.cache.update_user(data['hash'], data['id'], [None,(None,None)])
    
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
        
    if context.cache.update_user(data['hash'], data['id'], [decrypt_data(marshal(user_from_database, context.datfields)['data'], data['username'], data['password']), (data['password'], data['username'])])[0] == False:
        return {'code':423}
    
    return {'code':200}

def load_data(context, **data):
    user_from_cache = context.cache.find_user(data['hash'], data['id'])[0]
    
    if user_from_cache == None or user_from_cache == False:
        return {'code':423}
    
    if data['location'] == '':
        return {'code':202, 'data':user_from_cache}
    
    parsed_location = jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).find(user_from_cache)
    
    if parsed_location == []:
        return {'code':416}
    
    return {'code':202, 'data':[match.value for match in parsed_location][0]}

def create_session(context, **data):
    user_hash = context.cache.add_user(data['id'])
    
    return {'code':101, 'hash':user_hash}

def end_session(context, **data):
    if context.cache.delete_user(data['hash'], data['id'])[0] == False:
        return {'code':423}

    return {'code':200}

class Session():
    def __init__(self, path=None):
        self.app = Flask(__name__)
        if path == None:
            self.app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.getcwd()}/database.db'
        else:
            self.app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{path}/database.db'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.db = SQLAlchemy(self.app)            

        class User(self.db.Model):
            username = self.db.Column(self.db.String, nullable=False, primary_key = True)
            password = self.db.Column(self.db.String, nullable=False)
            data = self.db.Column(self.db.String)

            def __init__(self, username, password, data):
                self.username = username
                self.password = password
                self.data = data

        if path == None:        
            if os.path.isfile(f'{os.getcwd()}/database.db') is False:
                with self.app.app_context():
                    self.db.create_all()

        else:
            if os.path.isfile(f'{path}/database.db') is False:
                with self.app.app_context():
                    self.db.create_all()
            
        self.datfields = {'data': fields.Raw}
        self.passfields = {'password': fields.String}
        self.User = User
        self.cache = UserCache()
            
    @json_response
    def post(self, location, a ,data, **_):
        if location == 'sign_up':
            return sign_up(self, **data)
            
        elif location == 'save_data':
            return save_data(self, **data)

        elif location == 'delete_data':
            return delete_data(self, **data)
            
        elif location == 'log_out':
            return log_out(self, **data)
            
        elif location == 'remove_account':
            return remove_account(self, **data)
    
        elif location == 'log_in':
            return log_in(self, **data)
            
        elif location == 'load_data':
            return load_data(self, **data)
                
        elif location == 'create_session':
            return create_session(self, **data)
        
        elif location == 'Cert':
            return {'code':200}
    
        elif location == 'end_session':
            return end_session(self, **data)
