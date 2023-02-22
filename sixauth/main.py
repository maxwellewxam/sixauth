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
import struct

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

from .logs.log_class import Logger

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

cache = {}

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

@logger(is_log_more=True)
def cache_timeout_thread(threshold, stop_flag):
    while not stop_flag.is_set():
        try:
            for key in list(cache):
                if time.time() - cache[key]['time'] > threshold:
                    del cache[key]
            time.sleep(1)
        except Exception as err:
            server_console.log(err)

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

@logger(is_log_more=True)
def establish_client_connection(address):
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

def make_location(dict, path, data):
    path = path.split('/')
    for pos, name in enumerate(path):
        if not len([match for match in dict.keys() if match == name]) > 0:
            dict[name] = {'data': None, 'folder':{}}
        if len(path)==pos+1:
            dict[name]['data'] = data
            return {'code':200}
        dict = dict[name]['folder']

def find_data(dict, path):
    path = path.split('/')
    try:
        for pos, name in enumerate(path):
            if len(path)==pos+1:
                return {'code':200, 'data':dict[name]['data']}
            dict = dict[name]['folder']
    except KeyError:
        return {'code': 500}

def delete_location(dict, path):
    path = path.split('/')
    for pos, name in enumerate(path):
        if len(path)==pos+1:
            del dict[name]
            return {'code':200}
        dict = dict[name]['folder']

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def add_user(id):
    hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
    cache[hash] = {'main':encrypt_data_fast([None,(None,None)],id), 'time':time.time()}
    return {'code':200, 'hash':hash}

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def find_user(hash, id):
    if not is_valid_key(cache[hash]['main'], id):
        return {'code':500}
    cache[hash]['time'] = time.time()
    data = decrypt_data_fast(cache[hash]['main'],id)
    if data[0] == None:
        return {'code':500}
    return {'code':200, 'data':data}

@logger(is_log_more=True, in_sensitive=True)
def update_user(hash, id, dbdat):
    if is_valid_key(cache[hash]['main'], id):
        cache[hash]['main'] = encrypt_data_fast(dbdat,id)
        cache[hash]['time'] = time.time()
        return {'code':200}
    return {'code':500}

@logger(is_log_more=True, in_sensitive=True)
def delete_user(hash, id):
    if is_valid_key(cache[hash]['main'], id):
        del cache[hash]
        return {'code':200}
    return {'code':500}

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def sign_up(database, data):
    if data['username'] == '':
        return {'code':406}
    if data['username'].isalnum() == False:
        return {'code':406}
    user_from_database = database['conn'].execute(database['users'].select().where(database['users'].c.username == data['username'])).fetchone()
    if user_from_database:
        return {'code':409}
    encrypted_data, iv = encrypt_data({}, data['username'], data['password'])
    database['iv_dict'][data['username']] = iv
    database['conn'].execute(database['users'].insert().values(username=data['username'], password=create_password_hash(data['password']), data=encrypted_data))
    return {'code':200}

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def save_data(data):
    user_from_cache = find_user(data['hash'], data['id'])
    if user_from_cache['code'] == 500:
        return {'code':423}
    if not is_json_serialized(data['data']):
        return {'code':420, 'data':data['data'], 'error':'Object is not json serialized'}
    data_from_request = json.loads(data['data'])
    if data['location'] == '':
        return {'code':417}
    make_location(user_from_cache['data'][0], data['location'], data_from_request)
    update_user(data['hash'], data['id'], [user_from_cache['data'][0], user_from_cache['data'][1]])
    return {'code':200, 'data':user_from_cache['data'][0]}

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def delete_data(data):
    user_from_cache = find_user(data['hash'], data['id'])
    if user_from_cache['code'] == 500:
        return {'code':423}
    if data['location'] == '':
        update_user(data['hash'], data['id'], [{}, user_from_cache['data'][1]])
        return {'code':200}
    delete_location(user_from_cache['data'][0], data['location'])
    update_user(data['hash'], data['id'], [user_from_cache['data'][0], user_from_cache['data'][1]])
    return {'code':200}

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def log_out(database, data):
    user_from_cache = find_user(data['hash'], data['id'])
    if user_from_cache['code'] == 500:
        return {'code':200}
    user_from_database = database['conn'].execute(database['users'].select().where(database['users'].c.username == user_from_cache['data'][1][0])).fetchone()
    if not user_from_database:
        return {'code':420, 'data':user_from_cache['data'], 'error':'could not find user to logout'}
    if not verify_password_hash(user_from_database[1], password=user_from_cache['data'][1][1]):
        return {'code': 423}
    encrypted_data, iv = encrypt_data(user_from_cache['data'][0], user_from_cache['data'][1][0], user_from_cache['data'][1][1])
    database['iv_dict'][user_from_cache['data'][1][0]] = iv
    database['conn'].execute(database['users'].update().where(database['users'].c.username == user_from_cache['data'][1][0]).values(data=encrypted_data))
    update_user(data['hash'], data['id'], [None,(None,None)])
    return {'code':200}

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def remove_account(database, data):
    user_from_cache = find_user(data['hash'], data['id'])
    if user_from_cache['code'] == 500:
        return{'code':423}
    user_from_database = database['conn'].execute(database['users'].select().where(database['users'].c.username == user_from_cache['data'][1][0])).fetchone()
    if not user_from_database:
        return {'code':423}
    if not verify_password_hash(user_from_database[1], password=user_from_cache['data'][1][1]):
        return {'code':423}
    database['conn'].execute(database['users'].delete().where(database['users'].c.username == user_from_cache['data'][1][0]))
    update_user(data['hash'], data['id'], [None,(None,None)])
    del database['iv_dict'][user_from_cache['data'][1][0]]
    return {'code':200}

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def log_in(database, data):
    if data['username'] == '':
        return {'code':406}
    if data['username'].isalnum() == False:
        return {'code':406}
    user_from_database = database['conn'].execute(database['users'].select().where(database['users'].c.username == data['username'])).fetchone()
    if not user_from_database:
        return {'code':404}
    if not verify_password_hash(user_from_database[1], password=data['password']):
        return {'code':401}   
    cache_data = [decrypt_data(user_from_database[2], data['username'], data['password'], database['iv_dict'][data['username']]), (data['username'], data['password'])]
    if update_user(data['hash'], data['id'], cache_data)['code'] == 500:
        return {'code':423}
    return {'code':200}

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def load_data(data):
    user_from_cache = find_user(data['hash'], data['id'])
    if user_from_cache['code'] == 500:
        return {'code':423}
    if data['location'] == '':
        return {'code':202, 'data':user_from_cache['data'][0]}
    val = find_data(user_from_cache['data'][0], data['location'])
    if val['code'] == 500:
        return {'code':416}
    return {'code':202, 'data':val['data']}

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def create_session(data):
    user_hash = add_user(data['id'])['hash']
    return {'code':201, 'hash':user_hash}

@logger(is_log_more=True, in_sensitive=True)
def end_session(data):
    if delete_user(data['hash'], data['id'])['code'] == 500:
        return {'code':423}
    return {'code':200}

@logger()
def backend_session(address):
    f, client_socket = establish_client_connection(address)
    client_logger.info(f'Connected to: {address}')
    
    @logger(in_sensitive=True, out_sensitive=True)
    def session(**data):
        encrypted_data = f.encrypt(json.dumps(data).encode('utf-8'))
        request_length = len(encrypted_data)
        client_socket.send(f.encrypt(json.dumps({'code':320, 'len':request_length}).encode('utf-8')))
        response = json.loads(f.decrypt(client_socket.recv(1024)).decode())
        if response['code'] == 420:
            return response
        elif response['code'] != 200:
            return {'code':420, 'data':None, 'error':'Server failed to follow protocall'}
        client_socket.send(encrypted_data)
        request = json.loads(f.decrypt(client_socket.recv(1024)).decode())
        if request['code'] == 420:
            return request
        if request['code'] != 320:
            return {'code':420, 'data':None, 'error':'Server failed to follow protocall'}
        client_socket.send(f.encrypt(json.dumps({'code':200}).encode('utf-8')))
        return json.loads(f.decrypt(client_socket.recv(request['len'])).decode())
    return session

@logger()
def frontend_session(path = os.getcwd(), test_mode = False):
    db_path = f'sqlite:///{path}/database.db'
    client_logger.info(f'Database located at: {db_path}')
    engine = create_engine(db_path, connect_args={'check_same_thread':False}, poolclass=StaticPool)
    metadata = MetaData()
    users = Table('users', metadata,
        Column('username', String, unique=True, primary_key=True),
        Column('password', String),
        Column('data', LargeBinary))
    ivs = Table('ivs', metadata,
        Column('server', String, unique=True, primary_key=True),
        Column('iv', LargeBinary))
    metadata.create_all(engine)
    conn = engine.connect()
    key = 'random ass key'
    salt = b'BOOBIES'
    from_database = conn.execute(ivs.select().where(ivs.c.server == key)).fetchone()
    if from_database:
        _,ivs_bytes = from_database
        ivs_dict = server_decrypt_data(ivs_bytes, key, salt)
    else:
        ivs_dict = {}
        conn.execute(ivs.insert().values(server = key, iv=server_encrypt_data(ivs_dict, key, salt)))
    database = {'conn':conn, 'users':users, 'iv_dict':ivs_dict}
    
    @logger(in_sensitive=True, out_sensitive=True)
    def session(**data):
        if data['code'] == 301:
            return create_session(data)
        elif data['code'] == 302:
            return sign_up(database, data)
        elif data['code'] == 303:
            return save_data(data)
        elif data['code'] == 304:
            return delete_data(data)
        elif data['code'] == 305:
            return log_out(database, data)
        elif data['code'] == 306:
            return remove_account(database, data)
        elif data['code'] == 307:
            return log_in(database, data)
        elif data['code'] == 308:
            return load_data(data)
        elif data['code'] == 309:
            return end_session(data)
        elif data['code'] == 310:
            conn.execute(ivs.update().where(ivs.c.server == key).values(iv=server_encrypt_data(ivs_dict, key, salt)))
            return {'code':200} 
    return session

@logger(is_log_more=True, is_server=True, in_sensitive=True)
async def server_send_data(loop, client_socket, client_address, f, data):
    encrypted_data = f.encrypt(json.dumps(data).encode('utf-8'))
    request_length = len(encrypted_data)
    await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':320, 'len':request_length}).encode('utf-8')))
    recv = await loop.sock_recv(client_socket, 1024)
    if recv == b'':
        server_logger.info(f'{client_address} made empty request')
        await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':200}).encode('utf-8')))
        return {'code':500}
    try:
        response = json.loads(f.decrypt(recv).decode())
    except InvalidToken:
        server_logger.info(f'{client_address} sent invalid token')
        await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':'Sent invalid token'}).encode('utf-8')))
        return {'code':500}
    except BaseException as err:
        await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':str(err)}).encode('utf-8')))
        tb = traceback.extract_tb(sys.exc_info()[2])
        line_number = tb[-1][1]
        server_logger.info(f'Request {data["code"]} prossesing for {client_address} failed, Error on line {line_number}: {str(type(err))}:{str(err)}')#\n{str(tb)}')
        return {'code':500}
    if response['code'] != 200:
        return {'code':500}
    client_socket.send(encrypted_data)
    return {'code':200}

@logger(is_log_more=True, is_server=True, in_sensitive=True)
async def server_recv_data(loop, client_socket, client_address, f):
    request = await loop.sock_recv(client_socket, 1024)
    if request == b'':
        server_logger.info(f'{client_address} made empty request')
        await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':200}).encode('utf-8')))
        return {'code':500}
    try:
        data = json.loads(f.decrypt(request).decode())
        if data['code'] != 320:
            server_logger.info(f'{client_address} failed to follow protocall')
            await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':'Client failed to follow protocall'}).encode('utf-8')))
            return {'code':500}
        await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':200}).encode('utf-8')))
        recv = await loop.sock_recv(client_socket, data['len'])
        if recv == b'':
            server_logger.info(f'{client_address} made empty request')
            await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':200}).encode('utf-8')))
            return {'code':500}
        data = json.loads(f.decrypt(recv).decode())
    except InvalidToken:
        server_logger.info(f'{client_address} sent invalid token')
        await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':'Sent invalid token'}).encode('utf-8')))
        return {'code':500}
    except BaseException as err:
        if type(err) == KeyError:
            await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':f'Couldnt find user in cache, contact owner to recover any data, \nuse this key: {str(err)}\nuse this id: \'{str(data["id"])}\''}).encode('utf-8')))
        else:
            await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':str(err)}).encode('utf-8')))
        tb = traceback.extract_tb(sys.exc_info()[2])
        line_number = tb[-1][1]
        server_logger.info(f'Request {data["code"]} prossesing for {client_address} failed, Error on line {line_number}: {str(type(err))}:{str(err)}')#\n{str(tb)}')
        return {'code':500}
    return {'code':200, 'data':data}

@logger(is_log_more=True, is_server=True, in_sensitive=True)
async def main_client_loop(client_socket, client_address, f, loop, session, stop_flag1):
    while not stop_flag1.is_set():
        try:
            data = await server_recv_data(loop, client_socket, client_address, f)
            if data['code'] == 500:
                server_logger.info(f'{client_address} failed to follow protocall')
                await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':'Failed to follow protocall'}).encode('utf-8')))
                break
            data = data["data"]
            server_logger.info(f'{client_address} made request: {data["code"]}')
            if data['code'] == 310:
                response = {'code':423}
            else:
                response = session(**data)
            server_logger.info(f'response to {client_address}: {response["code"]}')
            status = await server_send_data(loop, client_socket, client_address, f, response)
            if status['code'] == 500:
                server_logger.info(f'{client_address} failed to follow protocall')
                await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':'Failed to follow protocall'}).encode('utf-8')))
                break
            if data['code'] == 309 and response['code'] == 200:
                recv = await server_recv_data(loop, client_socket, client_address, f)
                await server_send_data(loop, client_socket, client_address, f, {'code':200})
                break
        except BaseException as err:
            if type(err) == KeyError:
                await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':f'Couldnt find user in cache, contact owner to recover any data, \nuse this key: {str(err)}\nuse this id: \'{str(data["id"])}\''}).encode('utf-8')))
            else:
                await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':str(err)}).encode('utf-8')))
            tb = traceback.extract_tb(sys.exc_info()[2])
            line_number = tb[-1][1]
            server_logger.info(f'Request {data["code"]} prossesing for {client_address} failed, Error on line {line_number}: {str(type(err))}:{str(err)}')#\n{str(tb)}')

@logger(is_server=True, in_sensitive=True)
async def setup_client(client_socket, client_address, server_public_key_bytes, stop_flag1, loop, session, server_private_key=None):
    client_public_key_bytes = await loop.sock_recv(client_socket, 1024)
    client_public_key = serialization.load_pem_public_key(
    client_public_key_bytes, default_backend())
    await loop.sock_sendall(client_socket, server_public_key_bytes)
    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
    kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"session key",
    backend=default_backend())
    key = kdf.derive(shared_secret)
    f = Fernet(base64.urlsafe_b64encode(key))
    await main_client_loop(client_socket, client_address, f, loop, session, stop_flag1)
    client_socket.close()

@logger(is_server=True, in_sensitive=True)
async def server_main_loop(server_socket, server_public_key_bytes, stop_flag1, session, server_private_key=None):
    loop = asyncio.get_event_loop()
    clients = set()
    while True:
        client_socket, client_address = await loop.sock_accept(server_socket)
        task = asyncio.create_task(setup_client(client_socket, client_address, server_public_key_bytes, stop_flag1, loop, session, server_private_key=server_private_key))
        clients.add(task)
        task.add_done_callback(clients.discard)

@logger(is_server=True)
def server(host, port, cache_threshold = 300, test_mode = False, use_default_logger = True):
    if use_default_logger:
        logger.setup_logger(client_logger_location=os.getcwd())
    session = frontend_session(test_mode=test_mode)
    stop_flag1 = threading.Event()
    t = threading.Thread(target=cache_timeout_thread, args=(cache_threshold, stop_flag1))
    t.start()
    server_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
    server_public_key = server_private_key.public_key()
    server_public_key_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setblocking(0)
    server_socket.bind((host, port))
    server_socket.listen()
    server_console.info('Server started')
    server_console.info('Press Ctrl+C to exit')
    server_console.info(f"Listening for incoming connections on {host}:{port}")
    try:
        asyncio.run(server_main_loop(server_socket, server_public_key_bytes, stop_flag1, session, server_private_key=server_private_key))
    except KeyboardInterrupt:
        server_console.info('Server Closed')
    except BaseException as err:
        server_console.info(f'Server did not exit successfully, Error: {err}')
    finally:
        stop_flag1.set()
        t.join()
        session(code=310)
