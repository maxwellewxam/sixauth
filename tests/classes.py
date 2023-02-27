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

class Logger:
    def __init__(self, server_console: logging.Logger, client_console: logging.Logger, server_logger: logging.Logger, client_logger: logging.Logger, console_handler, formatter):
        self.server_console = server_console
        self.client_console = client_console
        self.client_logger = client_logger
        self.server_logger = server_logger
        self.console_handler = console_handler
        self.formatter = formatter
        self.times = []
    
    def set_logger(self, loghandle):
        def log_func(text):
            loghandle.info(text)
        return log_func
    
    def setup_logger(self,
                        client_logger_location = os.getcwd(), 
                        server_logger_location = os.getcwd(), 
                        debug = False,
                        log_sensitive = False,
                        log_more = False):
        self.client_logger_location = client_logger_location
        self.server_logger_location = server_logger_location
        self.debug = debug
        self.log_sensitive = log_sensitive
        self.log_more = log_more
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

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def server_encrypt_data(data, key, salt):
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
def server_decrypt_data(data, key, salt):
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
def encrypt_data(data, password, salt):
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
def decrypt_data(data, password, salt, iv):
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
def encrypt_data_fast(message, key):
    return Fernet(bytes.fromhex(key)).encrypt(json.dumps(message).encode())

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def decrypt_data_fast(message, key):
    return json.loads(Fernet(bytes.fromhex(key)).decrypt(message).decode())

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def create_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).hex()

@logger(is_log_more=True, in_sensitive=True)
def verify_password_hash(hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(hash))

@logger(is_log_more=True, in_sensitive=True)
def is_json_serialized(obj):
    try:
        json.loads(obj)
        return True
    except json.decoder.JSONDecodeError:
        return False

@logger(is_log_more=True, in_sensitive=True)
def is_valid_key(data, id):
    try:
        decrypt_data_fast(data, id)
        return True
    except InvalidToken:
        return False

class Data:
    def __init__(self, data):
        self.data = data
    
    def store(self, id):
        self.data = encrypt_data_fast(self.data, id)
        return self
        
    def retrive(self, id):
        self.data = decrypt_data_fast(self.data, id)
        return self
    
    def make(self, path, data):
        path = path.split('/')
        temp = self.data
        for pos, name in enumerate(path):
            if not len([match for match in temp.keys() if match == name]) > 0:
                temp[name] = {'data': None, 'folder':{}}
            if len(path)==pos+1:
                temp[name]['data'] = data
                return {'code':200}
            temp = temp[name]['folder']

    def find(self, path):
        path = path.split('/')
        temp = self.data
        try:
            for pos, name in enumerate(path):
                if len(path)==pos+1:
                    return {'code':200, 'data':temp[name]['data']}
                temp = temp[name]['folder']
        except KeyError:
            return {'code': 500}

    def delete(self, path):
        path = path.split('/')
        temp = self.data
        for pos, name in enumerate(path):
            if len(path)==pos+1:
                del temp[name]
                return {'code':200}
            temp = temp[name]['folder']

class User:
    def __init__(self, data = None, username = None, password = None):
        self.data = Data(data)
        self.username = username
        self.password = password
    
    def store(self, id):
        self.data.store(id)
        self.username = encrypt_data_fast(self.username, id)
        self.password = encrypt_data_fast(self.password, id)
        return self
    
    def retrive(self, id):
        self.data.retrive(id)
        self.username = decrypt_data_fast(self.username, id)
        self.password = decrypt_data_fast(self.password, id)
        return self

class Cache:
    @logger(is_log_more=True)
    def __init__(self, threshold):
        self.cache = {}
        self.threshold = threshold
        self.stop_flag = threading.Event()
        self.t = threading.Thread(target=self.cache_timeout_thread)
        self.t.start()

    @logger(is_log_more=True)
    def cache_timeout_thread(self):
        while not self.stop_flag.is_set():
            try:
                for key in list(self.cache):
                    if time.time() - self.cache[key]['time'] > self.threshold:
                        del self.cache[key]
                time.sleep(1)
            except Exception as err:
                server_console.log(err)

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def add_user(self, id):
        hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
        self.cache[hash] = {'main':User().store(id), 'time':time.time()}
        return {'code':200, 'hash':hash}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def find_user(self, hash, id):
        if not is_valid_key(self.cache[hash]['main'].username, id):
            return {'code':500}
        self.cache[hash]['time'] = time.time()
        data = self.cache[hash]['main']
        if data.username == None:
            return {'code':500}
        return {'code':200, 'data':data}
    
    @logger(is_log_more=True, in_sensitive=True)
    def update_user(self, hash, id, data, username, password):
        if not is_valid_key(self.cache[hash]['main'].username, id):
            return {'code':500}
        self.cache[hash]['main'] = User(data, username, password).store(id)
        self.cache[hash]['time'] = time.time()
        return {'code':200}
        
    @logger(is_log_more=True, in_sensitive=True)
    def delete_user(self, hash, id):
        if not is_valid_key(self.cache[hash]['main'].username, id):
            return {'code':500}
        del self.cache[hash]
        return {'code':200}

