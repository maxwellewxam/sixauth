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

from . import logs

class AuthError(Exception): ...
class LocationError(AuthError): ...
class AuthenticationError(AuthError): ...
class UsernameError(AuthError): ...
class PasswordError(AuthError): ...
class DataError(AuthError): ...

ver = '1.0.3_DEV.1'

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

class Logger:
    def __init__(self, server_console: logging.Logger, client_console: logging.Logger, server_logger: logging.Logger, client_logger: logging.Logger, console_handler, formatter):
        self.server_console = server_console
        self.client_console = client_console
        self.client_logger = client_logger
        self.server_logger = server_logger
        self.console_handler = console_handler
        self.formatter = formatter
        self.times = []
    
    def set_logger(self, loghandle:logging.Logger):
        def log_func(text):
            loghandle.info(text)
        return log_func
    
    def setup_logger(self,
                        client_logger_location = os.path.dirname(logs.__file__), 
                        server_logger_location = os.getcwd(), 
                        debug = False,
                        log_sensitive = False,
                        log_more = False):
        self.client_logger_location = client_logger_location
        self.server_logger_location = server_logger_location
        self.debug = debug
        self.log_sensitive = log_sensitive
        self.log_more = log_more
        self.client_console.handlers = []
        self.client_logger.handlers = []
        self.server_console.handlers = []
        self.server_logger.handlers = []
        if server_logger_location != None:
            server_logger_handler = logging.FileHandler(server_logger_location+'/server.log')
            self.server_console.addHandler(server_logger_handler)
            self.server_logger.addHandler(server_logger_handler)
            self.server_logger.info('VVV---------BEGIN-NEW-LOG----------VVV')
            if self.log_sensitive:
                self.server_logger.info('WARNING: LOGGING SENSITIVE INFO')
            server_logger_handler.setFormatter(self.formatter)
        if client_logger_location != None:
            client_logger_handler = logging.FileHandler(client_logger_location+'/client.log')
            self.client_console.addHandler(client_logger_handler)
            self.client_logger.addHandler(client_logger_handler)
            self.client_logger.info('VVV---------BEGIN-NEW-LOG----------VVV')
            if self.log_sensitive:
                self.client_logger.info('WARNING: LOGGING SENSITIVE INFO')
            client_logger_handler.setFormatter(self.formatter)
        self.server_console.addHandler(self.console_handler)
        self.client_console.addHandler(self.console_handler)
        return self
    
    def __call__(self, is_server = False, is_log_more=False, in_sensitive=False, out_sensitive=False):
        if is_server and self.debug:
            log = self.set_logger(self.server_console)
        elif is_server and not self.debug:
            log = self.set_logger(self.server_logger)
        elif not is_server and self.debug:
            log = self.set_logger(self.client_console)
        elif not is_server and not self.debug:
            log = self.set_logger(self.client_logger)
        def decorator(func):
            def wrapper(*args, **kwargs):
                if is_log_more == False or self.log_more == True:
                    if not in_sensitive or self.log_sensitive:
                        log(f'{func.__name__} called with arguments {args} and {kwargs}')
                    else:
                        log(f'{func.__name__} called')
                start = time.time()               
                returned = func(*args, **kwargs)
                end = time.time()
                self.times.append((func.__name__, end-start, str(args), str(kwargs)))
                if is_log_more == False or self.log_more == True:
                    if not out_sensitive or self.log_sensitive:
                        log(f'{func.__name__} returned {returned}')
                    else:
                        log(f'{func.__name__} returned')
                if self.log_more:
                    log(f"{func.__name__} took {end-start} seconds to execute")
                return returned
            return wrapper
        return decorator

if __name__ != '__main__':
    server_console = logging.getLogger('server_console')
    client_console = logging.getLogger('client_console')
    server_logger = logging.getLogger('server_logger')
    client_logger = logging.getLogger('client_logger')
    
    server_console.setLevel(logging.INFO)
    client_console.setLevel(logging.INFO)
    server_logger.setLevel(logging.INFO)
    client_logger.setLevel(logging.INFO)
    
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = Logger(server_console, client_console, server_logger, client_logger, console_handler, formatter).setup_logger(server_logger_location=None)

else:
    def logger(**_):
        def decorator(func):
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper
        return decorator

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def server_encrypt_data(data:dict, key:bytes, salt:bytes):
    for k, v in data.items():
        data[k] = base64.b64encode(v).decode()
    json_data = json.dumps(data)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(key))
    fernet = Fernet(key)
    return fernet.encrypt(json_data.encode())

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def server_decrypt_data(data:bytes, key:bytes, salt:bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(key))
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
    def __init__(self, data = None, username = None, password = None):
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
        del key
    
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
    def update_user(self, hash, id, user):
        if not is_valid_key(self.cache[hash]['main'], id):
            return {'code':500}
        self.cache[hash]['main'] = user.store(id)
        self.cache[hash]['time'] = time.time()
        return {'code':200}
        
    @logger(is_log_more=True, in_sensitive=True)
    def delete_user(self, hash, id):
        if not is_valid_key(self.cache[hash]['main'], id):
            return {'code':500}
        del self.cache[hash]
        return {'code':200}

class Session:
    @logger(is_log_more=True)
    def __init__(self, path:str = os.getcwd(), threshold = 600, is_server = False):
        self.db = Database(path)
        self.cache = Cache(threshold, is_server)
        
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def signup(self, username, password):
        if username == '':
            return {'code':406}
        if username.isalnum() == False:
            return {'code':406}
        user_from_database = self.db.find(username)
        if user_from_database:
            return {'code':409}
        encrypted_data, iv = encrypt_data({}, password, username)
        self.db.iv_dict[username] = iv
        self.db.create(username, password, encrypted_data)
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def log_in(self, hash, id, username, password):
        if username == '':
            return {'code':406}
        if username.isalnum() == False:
            return {'code':406}
        user_from_database = self.db.find(username)
        if not user_from_database:
            return {'code':404}
        if not verify_password_hash(user_from_database[1], password):
            return {'code':401}
        user_data = decrypt_data(user_from_database[2], password, username, self.db.iv_dict[username])
        cache_data = User(user_data, username, password)
        if self.cache.update_user(hash, id, cache_data)['code'] == 500:
            return {'code':423}
        return {'code':200}