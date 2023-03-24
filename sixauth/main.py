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

from typing import Any, Callable
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
                        server_console.info(self.cache)
                time.sleep(1)
            except Exception as err:
                server_console.info(err)

    @logger(is_log_more=True, in_sensitive=True)
    def remove_key(self, key):
        self.server(key)
        del key
        
    def server(self, _):
        pass
    
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
    @logger()
    def __init__(self, path = os.getcwd(), cache_threshold = 300):
        self.cache = Cache(cache_threshold)
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
            Column('iv', LargeBinary))
        metadata.create_all(engine)
        self.conn = engine.connect()
        self.key = 'random ass key'
        self.salt = b'BOOBIES'
        from_database = self.conn.execute(self.ivs.select().where(self.ivs.c.server == self.key)).fetchone()
        if from_database:
            _,ivs_bytes = from_database
            self.iv_dict = server_decrypt_data(ivs_bytes, self.key, self.salt)
        else:
            self.iv_dict = {}
            self.conn.execute(self.ivs.insert().values(server = self.key, iv=server_encrypt_data(self.iv_dict, self.key, self.salt)))
        self.function_map = {
            301: self.create_session,
            302: self.sign_up,
            303: self.save_data,
            304: self.delete_data,
            305: self.log_out,
            306: self.remove_account,
            307: self.log_in,
            308: self.load_data,
            309: self.end_session,
            310: self.close_session}
        
    @logger(is_log_more=True, in_sensitive=True)
    def close_session(self,_):
        self.cache.stop_flag.set()
        self.cache.t.join()
        self.server()
        self.conn.execute(self.ivs.update().where(self.ivs.c.server == self.key).values(iv=server_encrypt_data(self.iv_dict, self.key, self.salt)))
        self.conn.commit()
        self.conn.close()
        return {'code':200}
    
    def server(self):
        pass
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def sign_up(self, data):
        if data['username'] == '':
            return {'code':406}
        if data['username'].isalnum() == False:
            return {'code':406}
        user_from_database = self.conn.execute(self.users.select().where(self.users.c.username == data['username'])).fetchone()
        if user_from_database:
            return {'code':409}
        encrypted_data, iv = encrypt_data({}, data['password'], data['username'])
        self.iv_dict[data['username']] = iv
        self.conn.execute(self.users.insert().values(username=data['username'], password=create_password_hash(data['password']), data=encrypted_data))
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
        user_from_database = self.conn.execute(self.users.select().where(self.users.c.username == user_from_cache['data'].username)).fetchone()
        if not user_from_database:
            return {'code':420, 'data':user_from_cache['data'], 'error':'could not find user to logout'}
        if not verify_password_hash(user_from_database[1], password=user_from_cache['data'].password):
            return {'code': 423}
        encrypted_data, iv = encrypt_data(user_from_cache['data'].data.data, user_from_cache['data'].password, user_from_cache['data'].username)
        self.iv_dict[user_from_cache['data'].username] = iv
        self.conn.execute(self.users.update().where(self.users.c.username == user_from_cache['data'].username).values(data=encrypted_data))
        self.cache.update_user(data['hash'], data['id'], User())
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def remove_account(self, data):
        user_from_cache = self.cache.find_user(data['hash'], data['id'])
        if user_from_cache['code'] == 500:
            return{'code':423}
        user_from_database = self.conn.execute(self.users.select().where(self.users.c.username == user_from_cache['data'].username)).fetchone()
        if not user_from_database:
            return {'code':423}
        if not verify_password_hash(user_from_database[1], password=user_from_cache['data'].password):
            return {'code':423}
        self.conn.execute(self.users.delete().where(self.users.c.username == user_from_cache['data'].username))
        self.cache.update_user(data['hash'], data['id'], User())
        del self.iv_dict[user_from_cache['data'].username]
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def log_in(self, data):
        if data['username'] == '':
            return {'code':406}
        if data['username'].isalnum() == False:
            return {'code':406}
        user_from_database = self.conn.execute(self.users.select().where(self.users.c.username == data['username'])).fetchone()
        if not user_from_database:
            return {'code':404}
        if not verify_password_hash(user_from_database[1], password=data['password']):
            return {'code':401}   
        cache_data = User(decrypt_data(user_from_database[2], data['password'], data['username'], self.iv_dict[data['username']]), data['username'], data['password'])
        if self.cache.update_user(data['hash'], data['id'], cache_data)['code'] == 500:
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

@logger(is_log_more=True)
def establish_client_connection(address:str):
    client_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
    client_public_key = client_private_key.public_key()
    client_public_key_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    client_socket = socket.socket()
    connection_info = address.split(':')
    client_socket.connect((connection_info[0], int(connection_info[1])))
    client_socket.send(client_public_key_bytes)
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(
    server_public_key_bytes, default_backend())
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"session key",
    backend=default_backend())
    key = kdf.derive(shared_secret)
    f = Fernet(base64.urlsafe_b64encode(key))
    return f, client_socket

class Connection:
    @logger(is_log_more=True, in_sensitive=True)
    def __init__(self, socket:socket.socket, address, f:Fernet, log:logging.Logger):
        self.log = log.info
        self.socket = socket
        self.address = address
        self.f = f
        self.dead = False

    def is_dead(self):
        return self.dead
    
    @logger(is_log_more=True, in_sensitive=True)
    def send(self, data:dict):
        encrypted_data = self.f.encrypt(json.dumps(data).encode('utf-8'))
        first = self.f.encrypt(json.dumps({'code':320, 'len':len(encrypted_data)}).encode('utf-8'))
        self.socket.send(first)
        self.socket.send(encrypted_data)
        self.log(f'Sent data to {self.address}')
        
    @logger(is_log_more=True, out_sensitive=True)
    def recv(self):
        try:
            first = self.socket.recv(1024)
            if first == b'':
                self.log(f'{self.address} made empty request')
                #self.socket.send(self.f.encrypt(json.dumps({'code':400}).encode('utf-8')))
                return {'code':502}
            first = json.loads(self.f.decrypt(first))
            code = first.get('code')
            if not code:
                self.log(f'{self.address} failed protocol')
                self.socket.send(self.f.encrypt(json.dumps({'code':400}).encode('utf-8')))
                return {'code':500}
            if code == 420:
                self.log(f'{self.address} sent 420')
                self.log(f'{self.address} error: {first["error"]}')
                self.socket.send(self.f.encrypt(json.dumps({'code':400}).encode('utf-8')))
                return {'code':500}
            if code == 400:
                self.log(f'{self.address} sent protocol error')
                return {'code':501}
            if code != 320:
                self.log(f'{self.address} failed protocol')
                self.socket.send(self.f.encrypt(json.dumps({'code':400}).encode('utf-8')))
                return {'code':500}
            second = self.socket.recv(first['len'])
            if second == b'':
                self.log(f'{self.address} made empty request')
                #self.socket.send(self.f.encrypt(json.dumps({'code':400}).encode('utf-8')))
                return {'code':502}
            data = json.loads(self.f.decrypt(second))
            return {'code':200, 'recv':data}
        except Exception as err:
            return {'code':200, 'recv':err}

@logger()
def frontend_session(path = os.getcwd(), cache_threshold = 300):
    session = Session(path, cache_threshold)
    @logger(in_sensitive=True, out_sensitive=True)
    def send_data_to_session(**data:dict):
        code = data.get('code')
        if code in session.function_map:
            return session.function_map[code](data)
        else:
            return {'code': 420, 'data':None, 'error': f"Invalid code: {code}"}
    return send_data_to_session, session

class Server:
    @logger(is_server=True)
    def __init__(self, host, port, cache_threshold = 300, use_default_logger = True):
        if use_default_logger:
            logger.setup_logger(client_logger_location=os.getcwd())
        if logger.log_sensitive:
            server_console.info('WARNING: Logging sensitive information')
        self.session, self.back_session = frontend_session(cache_threshold=cache_threshold)
        self.stop_flag1 = self.back_session.cache.stop_flag
        self.back_session.server = self.waiter
        self.back_session.cache.server = self.remover
        self.server_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
        server_public_key = self.server_private_key.public_key()
        self.server_public_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.server_socket.setblocking(0)
        self.server_socket.bind((host, port))
        self.server_socket.listen()
        server_console.info(f'Server {ver} started')
        server_console.info('Press Ctrl+C to exit')
        server_console.info(f"Listening for incoming connections on {host}:{port}")
        try:
            asyncio.run(self.server_main_loop())
        except KeyboardInterrupt:
            server_console.info('Server Closed')
        except BaseException as err:
            server_console.info(f'Server did not exit successfully, Error: {err}')
        finally:
            self.server_socket.close()
            self.session(code=310)

    @logger(is_log_more=True, is_server=True, in_sensitive=True)
    async def main_client_loop1(self, client_socket, client_address, f):
        uhash, uid, ex = None, None, None
        while not self.stop_flag1.is_set():
            try:
                ldata = await self.server_recv_data(client_socket, client_address, f)
                if ldata['code'] == 500:
                    server_logger.info(f'{client_address} failed to follow protocol')
                    break
                data = ldata['data']
                uhash, uid = data.get('hash'), data.get('id')
                server_logger.info(f'{client_address} made request: {data["code"]}')
                if data['code'] == 310:
                    response = {'code':423}
                else:
                    response = self.session(**data)
                server_logger.info(f'response to {client_address}: {response["code"]}')
                status = await self.server_send_data(client_socket, client_address, f, response)
                if status['code'] == 500:
                    server_logger.info(f'{client_address} failed to follow protocol')
                    break
                if data['code'] == 309 and response['code'] == 200:
                    recv = await self.server_recv_data(client_socket, client_address, f)
                    await self.server_send_data(client_socket, client_address, f, {'code':200})
                    ex=True
                    break
            except BaseException as err:
                await self.server_send_data(client_socket, client_address, f, {'code':420, 'data':None, 'error':str(err)})
                tb = traceback.extract_tb(sys.exc_info()[2])
                line_number = tb[-1][1]
                server_logger.info(f'Request {data["code"]} processing for {client_address} failed, Error on line {line_number}: {str(type(err))}:{str(err)}\n{str(tb)}')
                break
        if not ex:
            self.session(code=305, hash=uhash, id=uid)

    @logger(is_log_more=True, is_server=True, in_sensitive=True)
    async def main_client_loop(self, client_socket, client_address, f):
        client = Connection(client_socket, client_address, f, server_logger)
        while not self.stop_flag1.is_set() and not client.is_dead():
            recv = client.recv()
            if recv.get('code') == 200:
                client.send({'code':200, 'your data': recv.get('recv')})
                if recv['recv']['code'] == 100:
                    client.dead = True
            if recv.get('code') == 502:
                client.dead = True

    @logger(is_server=True, in_sensitive=True)
    async def setup_client(self, client_socket, client_address):
        client_public_key_bytes = await self.loop.sock_recv(client_socket, 1024)
        client_public_key = serialization.load_pem_public_key(
        client_public_key_bytes, default_backend())
        await self.loop.sock_sendall(client_socket, self.server_public_key_bytes)
        shared_secret = self.server_private_key.exchange(ec.ECDH(), client_public_key)
        kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session key",
        backend=default_backend())
        key = kdf.derive(shared_secret)
        f = Fernet(base64.urlsafe_b64encode(key))
        await self.main_client_loop(client_socket, client_address, f)
        client_socket.close()

    def waiter(self):
        while len(self.clients) > 0:
            time.sleep(0.1)
    
    def remover(self, user_hash):
        
    
    @logger(is_server=True, in_sensitive=True)
    async def server_main_loop(self):
        self.loop = asyncio.get_event_loop()
        self.clients = set()
        while  not self.stop_flag1.is_set():
            client_socket, client_address = await self.loop.sock_accept(self.server_socket)
            task = asyncio.create_task(self.setup_client(client_socket, client_address))
            self.clients.add(task)
            task.add_done_callback(self.clients.discard)

@logger()
def backend_session(address:str):
    f, client_socket = establish_client_connection(address)
    client_logger.info(f'Connected to: {address}')
    
    @logger(in_sensitive=True, out_sensitive=True)
    def session(**data:dict):
        encrypted_data = f.encrypt(json.dumps(data).encode('utf-8'))
        request_length = len(encrypted_data)
        client_socket.send(f.encrypt(json.dumps({'code':320, 'len':request_length}).encode('utf-8')))
        response = json.loads(f.decrypt(client_socket.recv(1024)).decode())
        if response['code'] == 420:
            return response
        elif response['code'] != 200:
            return {'code':420, 'data':None, 'error':'Server failed to follow protocol'}
        client_socket.send(encrypted_data)
        request = json.loads(f.decrypt(client_socket.recv(1024)).decode())
        if request['code'] == 420:
            return request
        if request['code'] != 320:
            return {'code':420, 'data':None, 'error':'Server failed to follow protocol'}
        client_socket.send(f.encrypt(json.dumps({'code':200}).encode('utf-8')))
        return json.loads(f.decrypt(client_socket.recv(request['len'])).decode())
    return session
