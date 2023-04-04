import hashlib
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
import asyncio

from datetime import datetime
from sqlalchemy import create_engine, Column, String, Table, MetaData, LargeBinary
from sqlalchemy.pool import StaticPool
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

from .logger import *

VER = '1.0.3_DEV.1'

class AuthError(Exception): ...
class LocationError(AuthError): ...
class AuthenticationError(AuthError): ...
class UsernameError(AuthError): ...
class PasswordError(AuthError): ...
class DataError(AuthError): ...

old_hook = sys.excepthook

def exception_hook(exc_type, value, tb):
    tb = traceback.format_exception(exc_type, value=value, tb=tb)
    if exc_type.__bases__[0] == AuthError:
        bottom = tb[-1:]
        tb = tb[:-3]
        tb.append(bottom[0].strip('sixauth.main.'))
        tb = ''.join(tb)
        print(tb)
    else:
        old_hook(exc_type, value, tb)
    
sys.excepthook = exception_hook


@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def server_encrypt_data(data:dict, key:str, salt:bytes):
    for k, v in data.items():
        data[k] = base64.b64encode(v).decode()
    json_data = json.dumps(data)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(bytes(key.encode())))
    fernet = Fernet(key)
    return fernet.encrypt(json_data.encode())

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def server_decrypt_data(data:bytes, key:str, salt:bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(bytes(key.encode())))
    fernet = Fernet(key)
    iv_dict = json.loads(fernet.decrypt(data))
    for k, v in iv_dict.items():
        iv_dict[k] = base64.b64decode(v.encode())
    return iv_dict
        
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def encrypt_data(data:dict, password:str, salt:str):
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=backend)
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(iv, json.dumps(data).encode(), salt.encode()), iv

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def decrypt_data(data:bytes, password:str, salt:bytes, iv:bytes):
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=backend)
    key = kdf.derive(password.encode())
    aesgcm = AESGCM(key)
    return json.loads(aesgcm.decrypt(iv, data, salt.encode()).decode())

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def encrypt_data_fast(message:dict, key:str):
    return Fernet(bytes.fromhex(key)).encrypt(json.dumps(message).encode())

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def decrypt_data_fast(message:bytes, key:str):
    return json.loads(Fernet(bytes.fromhex(key)).decrypt(message).decode())

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def create_password_hash(password:str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).hex()

@logger(is_log_more=True, in_sensitive=True)
def verify_password_hash(hash:str, password:str):
    return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(hash))

@logger(is_log_more=True, in_sensitive=True)
def is_json_serialized(obj:dict):
    try:
        json.loads(obj)
        return True
    except json.decoder.JSONDecodeError:
        return False

@logger(is_log_more=True, in_sensitive=True)
def is_valid_key(data:bytes, id:str):
    try:
        decrypt_data_fast(data, id)
        return True
    except InvalidToken:
        return False

class Data:
    @logger(is_log_more=True, in_sensitive=True)
    def __init__(self, data):
        self.data = data
    
    @logger(is_log_more=True, out_sensitive=True)
    def store(self):
        return self.data
    
    @logger(is_log_more=True, in_sensitive=True)
    def make(self, path:str, data):
        path = path.split('/')
        temp = self.data
        for pos, name in enumerate(path):
            if not len([match for match in temp.keys() if match == name]) > 0:
                temp[name] = {'data': None, 'folder':{}}
            if len(path)==pos+1:
                temp[name]['data'] = data
                return {'code':200}
            temp = temp[name]['folder']

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def find(self, path:str):
        path = path.split('/')
        temp = self.data
        try:
            for pos, name in enumerate(path):
                if len(path)==pos+1:
                    return {'code':200, 'data':temp[name]['data']}
                temp = temp[name]['folder']
        except KeyError:
            return {'code': 500}

    @logger(is_log_more=True, in_sensitive=True)
    def delete(self, path:str):
        path = path.split('/')
        temp = self.data
        for pos, name in enumerate(path):
            if len(path)==pos+1:
                del temp[name]
                return {'code':200}
            temp = temp[name]['folder']

class User:
    data: Data
    @logger(is_log_more=True, in_sensitive=True)
    def __init__(self, data = None, username = None, password = None, done_callback = None):
        self.data = Data(data)
        self.username = username
        self.password = password
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def store(self, id):
        self.data = self.data.store()
        return encrypt_data_fast(self.__dict__, id)
    
    @logger(is_log_more=True, in_sensitive=True)
    def from_dict(self, dict, id):
        self.__dict__ = decrypt_data_fast(dict, id)
        self.data = Data(self.data)
        return self

class Cache:
    @logger(is_log_more=True)
    def __init__(self, threshold = 300, is_server=False):
        self.cache = {}
        self.threshold = threshold
        self.stop_flag = threading.Event()
        if is_server:    
            self.t = threading.Thread(target=self.cache_timeout_thread)
            self.t.start()

    @logger(is_log_more=True)
    def cache_timeout_thread(self):
        while not self.stop_flag.is_set():
            try:
                for key in list(self.cache):
                    if time.time() - self.cache[key]['time'] > self.threshold:
                        self.remove_key(self.cache[key])
                time.sleep(1)
            except Exception as err:
                server_console.info(err)

    @logger(is_log_more=True, in_sensitive=True)
    def remove_key(self, key):
        key['done']()
        server_console.info('removed user')
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def add_user(self, id):
        hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
        self.cache[hash] = {'main':User().store(id), 'time':time.time()}
        return {'code':200, 'hash':hash}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def find_user(self, hash, id):
        if not is_valid_key(self.cache[hash]['main'], id):
            return {'code':500}
        self.cache[hash]['time'] = time.time()
        data = User().from_dict(self.cache[hash]['main'], id)
        if data.username == None:
            return {'code':500}
        return {'code':200, 'data':data}
    
    @logger(is_log_more=True, in_sensitive=True)
    def update_user(self, hash, id, user, done_callback):
        if not is_valid_key(self.cache[hash]['main'], id):
            return {'code':500}
        self.cache[hash]['main'] = user.store(id)
        self.cache[hash]['time'] = time.time()
        self.cache[hash]['done'] = done_callback
        return {'code':200}
        
    @logger(is_log_more=True, in_sensitive=True)
    def delete_user(self, hash, id):
        if not is_valid_key(self.cache[hash]['main'], id):
            return {'code':500}
        del self.cache[hash]
        return {'code':200}

class Database:
    @logger(is_log_more=True)
    def __init__(self, path):
        db_path = f'sqlite:///{path}/database.db'
        client_logger.info(f'Database located at: {db_path}')
        engine = create_engine(db_path, connect_args={'check_same_thread':False}, poolclass=StaticPool)
        metadata = MetaData()
        self.users = Table('users', metadata,
            Column('username', String, unique=True, primary_key=True),
            Column('password', String),
            Column('data', LargeBinary))
        self.ivs = Table('ivs', metadata,
            Column('server', String, unique=True, primary_key=True),
            Column('iv', LargeBinary), 
            Column('bytes', LargeBinary))
        metadata.create_all(engine)
        self.conn = engine.connect()
        self.iv = 'server_iv'
        from_database = self.conn.execute(self.ivs.select().where(self.ivs.c.server == self.iv)).fetchone()
        if from_database:
            _,ivs_bytes,bites = from_database
            self.key, self.salt = json.loads(bites.decode())
            self.iv_dict = server_decrypt_data(ivs_bytes, self.key, self.salt)
        else:
            self.iv_dict = {}
            self.key = b'CHANGE'
            self.salt = b'THIS'
            bites = json.dumps((self.key, self.salt)).encode()
            self.conn.execute(self.ivs.insert().values(server=self.iv, iv=server_encrypt_data(self.iv_dict, self.key, self.salt), bytes=bites))
    
    def change_keys(self, key, salt):
        self.key = key
        self.salt = salt
    
    @logger(is_log_more=True)
    def close(self):
        self.conn.execute(self.ivs.update().where(self.ivs.c.server == self.iv).values(iv=server_encrypt_data(self.iv_dict, self.key, self.salt)))
        self.conn.commit()
        self.conn.close()
        
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def create(self, username, password, data):
        self.conn.execute(self.users.insert().values(username=username, password=password, data=data))
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def find(self, username):
        return self.conn.execute(self.users.select().where(self.users.c.username == username)).fetchone()
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def update(self, username, data):
        return self.conn.execute(self.users.update().where(self.users.c.username == username).values(data=data))
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def delete(self, username):
        return self.conn.execute(self.users.delete().where(self.users.c.username == username))

class Session:
    @logger()
    def __init__(self, path = os.getcwd(), cache_threshold = 300, is_server=False):
        self.cache = Cache(cache_threshold, is_server=is_server)
        self.db = Database(path)
        self.function_map = {
            301: self.create_session,
            302: self.sign_up,
            303: self.log_in,
            304: self.log_out,
            305: self.remove_account,
            306: self.save_data,
            307: self.load_data,
            308: self.delete_data,
            309: self.end_session,
            310: self.close_session}
        
    @logger(is_log_more=True, in_sensitive=True)
    def close_session(self,_):
        self.cache.stop_flag.set()
        self.cache.t.join()
        self.server()
        self.db.close()
        return {'code':200}
    
    def server(self):
        pass
    
    @logger(in_sensitive=True, out_sensitive=True)
    def __call__(self, **data:dict):
        code = data.get('code')
        if code in self.function_map:
            return self.function_map[code](data)
        else:
            return {'code': 420, 'data':None, 'error': f"Invalid code: {code}"}
    
    def create_done_callback(self, hash, id):
        def done_callback():
            self(code=305, hash=hash, id=id)
        return done_callback
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def sign_up(self, data):
        if data['username'] == '':
            return {'code':406}
        if data['username'].isalnum() == False:
            return {'code':406}
        user_from_database = self.db.find(data['username'])
        if user_from_database:
            return {'code':409}
        encrypted_data, iv = encrypt_data({}, data['password'], data['username'])
        self.db.iv_dict[data['username']] = iv
        self.db.create(data['username'], create_password_hash(data['password']), encrypted_data)
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def save_data(self, data):
        user_from_cache = self.cache.find_user(data['hash'], data['id'])
        if user_from_cache['code'] == 500:
            return {'code':423}
        if not is_json_serialized(data['data']):
            return {'code':420, 'data':data['data'], 'error':'Object is not json serialized'}
        data_from_request = json.loads(data['data'])
        if data['location'] == '':
            return {'code':417}
        user_from_cache['data'].data.make(data['location'], data_from_request)
        self.cache.update_user(data['hash'], data['id'], user_from_cache['data'])
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def delete_data(self, data):
        user_from_cache = self.cache.find_user(data['hash'], data['id'])
        if user_from_cache['code'] == 500:
            return {'code':423}
        if data['location'] == '':
            user_from_cache['data'].data.data = {}
        else:
            user_from_cache['data'].data.delete(data['location'])
        self.cache.update_user(data['hash'], data['id'], user_from_cache['data'])
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def log_out(self, data):
        user_from_cache = self.cache.find_user(data['hash'], data['id'])
        if user_from_cache['code'] == 500:
            return {'code':200}
        user_from_database = self.db.find(user_from_cache['data'].username)
        if not user_from_database:
            return {'code':420, 'data':user_from_cache['data'], 'error':'could not find user to logout'}
        if not verify_password_hash(user_from_database[1], password=user_from_cache['data'].password):
            return {'code': 423}
        encrypted_data, iv = encrypt_data(user_from_cache['data'].data.data, user_from_cache['data'].password, user_from_cache['data'].username)
        self.db.iv_dict[user_from_cache['data'].username] = iv
        self.db.update(user_from_cache['data'].username, encrypted_data)
        self.cache.update_user(data['hash'], data['id'], User())
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def remove_account(self, data):
        user_from_cache = self.cache.find_user(data['hash'], data['id'])
        if user_from_cache['code'] == 500:
            return{'code':423}
        user_from_database = self.db.find(user_from_cache['data'].username)
        if not user_from_database:
            return {'code':423}
        if not verify_password_hash(user_from_database[1], password=user_from_cache['data'].password):
            return {'code':423}
        self.db.delete(user_from_cache['data'].username)
        self.cache.update_user(data['hash'], data['id'], User())
        del self.db.iv_dict[user_from_cache['data'].username]
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def log_in(self, data):
        if data['username'] == '':
            return {'code':406}
        if data['username'].isalnum() == False:
            return {'code':406}
        user_from_database = self.db.find(data['username'])
        if not user_from_database:
            return {'code':404}
        if not verify_password_hash(user_from_database[1], password=data['password']):
            return {'code':401}   
        cache_data = User(decrypt_data(user_from_database[2], data['password'], data['username'], self.db.iv_dict[data['username']]), data['username'], data['password'])
        done_call = self.create_done_callback(data['hash'], data['id'])
        if self.cache.update_user(data['hash'], data['id'], cache_data, done_call)['code'] == 500:
            return {'code':423}
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def load_data(self, data):
        user_from_cache = self.cache.find_user(data['hash'], data['id'])
        if user_from_cache['code'] == 500:
            return {'code':423}
        if data['location'] == '':
            return {'code':202, 'data':user_from_cache['data'].data.data}
        val = user_from_cache['data'].data.find(data['location'])
        if val['code'] == 500:
            return {'code':416}
        return {'code':202, 'data':val['data']}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def create_session(self, data):
        user_hash = self.cache.add_user(data['id'])['hash']
        return {'code':201, 'hash':user_hash}

    @logger(is_log_more=True, in_sensitive=True)
    def end_session(self, data):
        if self.cache.delete_user(data['hash'], data['id'])['code'] == 500:
            return {'code':423}
        return {'code':200}

@logger()
def frontend_session(path = os.getcwd(), cache_threshold = 300):
    session = Session(path, cache_threshold, is_server=True)
    @logger(in_sensitive=True, out_sensitive=True)
    def send_data_to_session(**data:dict):
        code = data.get('code')
        if code in session.function_map:
            return session.function_map[code](data)
        else:
            return {'code': 420, 'data':None, 'error': f"Invalid code: {code}"}
    return send_data_to_session, session